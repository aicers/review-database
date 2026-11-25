use anyhow::Result;
use bincode::Options;
use serde::{Deserialize, Serialize};
use strum_macros::{Display, EnumString};

use crate::ClusteringModelTypeRef;

#[derive(Deserialize)]
pub struct Digest {
    pub id: i32,
    pub name: String,
    pub version: i32,
    pub raw_event_kind: String,
    pub classification_id: Option<i64>,
}

/// A clustering model as the Unsupervised Engine uploads it, decoded from
/// and encoded to model format 3.
#[derive(Clone, Debug, PartialEq)]
pub struct Model {
    pub id: i32,
    pub name: String,
    pub version: i32,
    pub kind: String,
    pub serialized_classifier: Vec<u8>,
    pub max_event_id_num: i32,
    /// The giganto-client `RawEventKind` name of the raw events the model
    /// reads, in snake case, `log` included.
    pub raw_event_kind: String,
    /// The log kind the model reads, which the uploader sets exactly when
    /// `raw_event_kind` is `log`. The codec does not check the pairing.
    pub log_kind: Option<String>,
    pub classification_id: i64,
    pub batch_info: Vec<crate::types::ModelBatchInfo>,
    pub scores: crate::types::ModelScores,
    /// The clustering model type the model was trained as.
    pub clustering_model_type: ClusteringModelTypeRef,
    /// What the training of the model actually read.
    pub training_read: TrainingRead,
    /// The state of each detection model that keeps one for the model.
    pub detection_model_states: Vec<DetectionModelState>,
    /// The number of clusters the model had right after its training, which
    /// the engine sets for a time-series model. This crate does not check it
    /// against the method.
    pub cluster_count_at_training: Option<u32>,
}

/// A summary of the raw events the training of a model read.
///
/// Times are raw event times in nanoseconds since the Unix epoch.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct TrainingRead {
    /// The time of the first raw event read.
    pub first: i64,
    /// The time of the last raw event read.
    pub last: i64,
    /// The number of raw events read on each day.
    pub days: Vec<TrainingReadDay>,
}

/// The number of raw events the training of a model read on one day.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct TrainingReadDay {
    /// The start of the day, as a raw event time in nanoseconds since the
    /// Unix epoch.
    pub start: i64,
    /// The number of raw events read on the day.
    pub count: u64,
}

/// The state a detection model keeps for a clustering model.
///
/// This crate stores the state as opaque bytes and does not interpret it.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct DetectionModelState {
    /// The number of the detection model.
    pub model: u32,
    /// The version of the state's encoding.
    pub state_version: u32,
    /// The state, opaque to this crate.
    pub state: Vec<u8>,
}

impl Model {
    /// Returns the clustering method `kind` names.
    pub(crate) fn method(&self) -> Result<ClusteringMethod> {
        use std::str::FromStr;
        Ok(ClusteringMethod::from_str(&self.kind)?)
    }

    fn header(&self) -> Result<MagicHeader> {
        Ok(MagicHeader {
            tag: MagicHeader::MAGIC_STRING.to_vec(),
            format: MagicHeader::FORMAT_VERSION,
            kind: self.method()?,
            version: self.version,
        })
    }

    /// Decodes a model serialized in format 3.
    ///
    /// # Errors
    ///
    /// Returns an error if the input is shorter than the 16-byte header, if
    /// its format is not 3 (no other format is read), if deserialization
    /// fails, or if bytes are left after the body.
    pub fn from_serialized(serialized: &[u8]) -> Result<Self> {
        use anyhow::anyhow;

        let header_bytes = serialized
            .get(..MagicHeader::MAGIC_SIZE)
            .ok_or_else(|| anyhow!("length should be {} bytes or more", MagicHeader::MAGIC_SIZE))?;
        let header = MagicHeader::try_from(header_bytes)?;
        if header.format != MagicHeader::FORMAT_VERSION {
            return Err(anyhow!(
                "Model format mismatch: {:?} (Expecting: {:?})",
                header.format,
                MagicHeader::FORMAT_VERSION
            ));
        }
        let version = header.version;
        let kind = header.kind.to_string();
        let model: Body =
            bincode::DefaultOptions::new().deserialize(&serialized[MagicHeader::MAGIC_SIZE..])?;
        Ok(Self {
            id: model.id,
            name: model.name,
            version,
            kind,
            serialized_classifier: model.serialized_classifier,
            max_event_id_num: model.max_event_id_num,
            raw_event_kind: model.raw_event_kind,
            log_kind: model.log_kind,
            classification_id: model.classification_id,
            batch_info: model.batch_info,
            scores: model.scores,
            clustering_model_type: model.clustering_model_type,
            training_read: model.training_read,
            detection_model_states: model.detection_model_states,
            cluster_count_at_training: model.cluster_count_at_training,
        })
    }

    /// Encodes the model in format 3.
    ///
    /// # Errors
    ///
    /// Returns an error if `kind` is not a known clustering method or if
    /// serialization fails.
    pub fn into_serialized(self) -> Result<Vec<u8>> {
        let mut buf = <Vec<u8>>::from(self.header()?);
        let model = Body {
            id: self.id,
            name: self.name,
            serialized_classifier: self.serialized_classifier,
            max_event_id_num: self.max_event_id_num,
            raw_event_kind: self.raw_event_kind,
            log_kind: self.log_kind,
            classification_id: self.classification_id,
            batch_info: self.batch_info,
            scores: self.scores,
            clustering_model_type: self.clustering_model_type,
            training_read: self.training_read,
            detection_model_states: self.detection_model_states,
            cluster_count_at_training: self.cluster_count_at_training,
        };
        buf.extend(bincode::DefaultOptions::new().serialize(&model)?);
        Ok(buf)
    }
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize, EnumString, Display)]
pub(crate) enum ClusteringMethod {
    Distribution = 0,
    Multifield = 1, // This corresponds to ClusteringMethod::Multidimention in REconverge
    Prefix = 2,
    Timeseries = 3,
}

impl From<crate::ModelMethod> for ClusteringMethod {
    fn from(method: crate::ModelMethod) -> Self {
        match method {
            crate::ModelMethod::Multidimension => Self::Multifield,
            crate::ModelMethod::Prefix => Self::Prefix,
            crate::ModelMethod::Timeseries => Self::Timeseries,
        }
    }
}

impl TryFrom<ClusteringMethod> for crate::ModelMethod {
    type Error = anyhow::Error;

    fn try_from(method: ClusteringMethod) -> Result<Self> {
        match method {
            ClusteringMethod::Multifield => Ok(Self::Multidimension),
            ClusteringMethod::Prefix => Ok(Self::Prefix),
            ClusteringMethod::Timeseries => Ok(Self::Timeseries),
            ClusteringMethod::Distribution => Err(anyhow::anyhow!(
                "the Distribution method is not trained by runs"
            )),
        }
    }
}

impl TryFrom<u32> for ClusteringMethod {
    type Error = anyhow::Error;

    fn try_from(input: u32) -> Result<Self> {
        use anyhow::anyhow;

        match input {
            0 => Ok(Self::Distribution),
            1 => Ok(Self::Multifield),
            2 => Ok(Self::Prefix),
            3 => Ok(Self::Timeseries),
            _ => Err(anyhow!("Unexpected clustering method {input}")),
        }
    }
}

#[derive(Debug, PartialEq)]
struct MagicHeader {
    tag: Vec<u8>,
    format: u32,
    kind: ClusteringMethod,
    version: i32,
}

impl MagicHeader {
    const FORMAT_VERSION: u32 = 3;
    const MAGIC_STRING: &'static [u8] = b"RCM\0";
    const MAGIC_SIZE: usize = 16;
}

impl From<MagicHeader> for Vec<u8> {
    fn from(val: MagicHeader) -> Self {
        let mut buf = val.tag.clone();
        buf.extend(val.format.to_le_bytes().iter());
        buf.extend((val.kind as u32).to_le_bytes().iter());
        buf.extend(val.version.to_le_bytes().iter());
        buf
    }
}

impl TryFrom<&[u8]> for MagicHeader {
    type Error = anyhow::Error;

    fn try_from(v: &[u8]) -> Result<Self, Self::Error> {
        use anyhow::anyhow;

        if v.len() < MagicHeader::MAGIC_SIZE {
            return Err(anyhow!(
                "length should be {} bytes or more",
                MagicHeader::MAGIC_SIZE
            ));
        }

        let tag = (v[..4]).to_vec();
        if tag.as_slice() != MagicHeader::MAGIC_STRING {
            return Err(anyhow!("wrong magic string"));
        }
        let format = u32::from_le_bytes(v[4..8].try_into()?);
        let kind = u32::from_le_bytes(v[8..12].try_into()?).try_into()?;
        let version = i32::from_le_bytes(v[12..].try_into()?);

        Ok(MagicHeader {
            tag,
            format,
            kind,
            version,
        })
    }
}

/// The body of format 3, in field order.
#[derive(Deserialize, Serialize)]
struct Body {
    id: i32,
    name: String,
    serialized_classifier: Vec<u8>,
    max_event_id_num: i32,
    raw_event_kind: String,
    log_kind: Option<String>,
    classification_id: i64,
    batch_info: Vec<crate::types::ModelBatchInfo>,
    scores: crate::types::ModelScores,
    clustering_model_type: ClusteringModelTypeRef,
    training_read: TrainingRead,
    detection_model_states: Vec<DetectionModelState>,
    cluster_count_at_training: Option<u32>,
}

#[cfg(test)]
mod tests {
    use bincode::Options;

    use super::{
        ClusteringMethod, DetectionModelState, MagicHeader, Model, TrainingRead, TrainingReadDay,
    };
    use crate::ClusteringModelTypeRef;

    /// The fixture of test model 1, which the engine's codec writes too.
    const TEST_MODEL_1: &[u8] = include_bytes!("../tests/fixtures/model_format_3/test_model_1.bin");
    /// The fixture of test model 2, which the engine's codec writes too.
    const TEST_MODEL_2: &[u8] = include_bytes!("../tests/fixtures/model_format_3/test_model_2.bin");
    /// The fixture of test model 3, which the engine's codec writes too.
    const TEST_MODEL_3: &[u8] = include_bytes!("../tests/fixtures/model_format_3/test_model_3.bin");
    /// The engine's fixture of test model 1, from petabi/reconverge commit
    /// bcfcb8609b312f3ec1fdc2cffc6ab7edcd35e67a.
    const ENGINE_TEST_MODEL_1: &[u8] =
        include_bytes!("../tests/fixtures/model_format_3/engine/test_model_1.bin");
    /// The engine's fixture of test model 2, from the same commit.
    const ENGINE_TEST_MODEL_2: &[u8] =
        include_bytes!("../tests/fixtures/model_format_3/engine/test_model_2.bin");
    /// The engine's fixture of test model 3, from the same commit.
    const ENGINE_TEST_MODEL_3: &[u8] =
        include_bytes!("../tests/fixtures/model_format_3/engine/test_model_3.bin");
    /// The bytes of test model 3, as the format spells them out.
    const TEST_MODEL_3_BYTES: &str = concat!(
        "52434d00030000000300000001000000",
        "0e016d0301020332",
        "03746c73",
        "00",
        "54",
        "00",
        "00",
        "00",
        "10",
        "7365727665725f6461696c795f746c73",
        "01",
        "0204",
        "01",
        "0203",
        "00",
        "0104",
    );

    /// Test model 1 of the fixture shared with the engine.
    fn test_model_1() -> Model {
        Model {
            id: 7,
            name: "m".to_owned(),
            version: 1,
            kind: "Multifield".to_owned(),
            serialized_classifier: vec![1, 2, 3],
            max_event_id_num: 25,
            raw_event_kind: "http".to_owned(),
            log_kind: None,
            classification_id: 42,
            batch_info: vec![],
            scores: crate::types::ModelScores::default(),
            clustering_model_type: ClusteringModelTypeRef::Catalog {
                id: "http_url".to_owned(),
                version: 1,
            },
            training_read: TrainingRead {
                first: 1,
                last: 2,
                days: vec![TrainingReadDay { start: 1, count: 3 }],
            },
            detection_model_states: vec![DetectionModelState {
                model: 19,
                state_version: 1,
                state: vec![9],
            }],
            cluster_count_at_training: None,
        }
    }

    /// Test model 2: test model 1 reading `syslog` logs as a custom type.
    fn test_model_2() -> Model {
        Model {
            raw_event_kind: "log".to_owned(),
            log_kind: Some("syslog".to_owned()),
            clustering_model_type: ClusteringModelTypeRef::Custom,
            ..test_model_1()
        }
    }

    /// Test model 3: test model 1 as a time-series model of the
    /// `server_daily_tls` type, with a cluster count at training.
    fn test_model_3() -> Model {
        Model {
            kind: "Timeseries".to_owned(),
            raw_event_kind: "tls".to_owned(),
            clustering_model_type: ClusteringModelTypeRef::Catalog {
                id: "server_daily_tls".to_owned(),
                version: 1,
            },
            detection_model_states: vec![],
            cluster_count_at_training: Some(4),
            ..test_model_1()
        }
    }

    /// A model with every field set, the new ones included.
    fn full_model() -> Model {
        let mut scores = crate::types::ModelScores::default();
        scores.insert(3, 0.5);
        Model {
            id: 1,
            name: "example".to_owned(),
            version: 2,
            kind: "Prefix".to_owned(),
            serialized_classifier: b"test".to_vec(),
            max_event_id_num: 123,
            raw_event_kind: "log".to_owned(),
            log_kind: Some("auth".to_owned()),
            classification_id: -5,
            batch_info: vec![crate::types::ModelBatchInfo {
                id: 4,
                earliest: 10,
                latest: 20,
                size: 30,
                sensors: vec!["piglet".to_owned()],
            }],
            scores,
            clustering_model_type: ClusteringModelTypeRef::Catalog {
                id: "http_url".to_owned(),
                version: 2,
            },
            training_read: TrainingRead {
                first: -1,
                last: i64::MAX,
                days: vec![
                    TrainingReadDay {
                        start: 0,
                        count: u64::MAX,
                    },
                    TrainingReadDay {
                        start: 86_400_000_000_000,
                        count: 1,
                    },
                ],
            },
            detection_model_states: vec![
                DetectionModelState {
                    model: 19,
                    state_version: 1,
                    state: vec![9, 8, 7],
                },
                DetectionModelState {
                    model: 3,
                    state_version: 2,
                    state: vec![],
                },
            ],
            cluster_count_at_training: Some(17),
        }
    }

    /// Returns `serialized` with its header's format set to `format`.
    fn with_format(serialized: &[u8], format: u32) -> Vec<u8> {
        let mut serialized = serialized.to_vec();
        serialized[4..8].copy_from_slice(&format.to_le_bytes());
        serialized
    }

    #[test]
    fn short_serialized_model() {
        for length in [0, 15] {
            let input = vec![0; length];
            let error = Model::from_serialized(&input).err().unwrap();
            assert_eq!(error.to_string(), "length should be 16 bytes or more");
            let error = MagicHeader::try_from(input.as_slice()).unwrap_err();
            assert_eq!(error.to_string(), "length should be 16 bytes or more");
        }
    }

    #[test]
    fn header() {
        let model = full_model();
        let header = model.header().unwrap();
        assert_eq!(header.kind, ClusteringMethod::Prefix);
        assert_eq!(header.version, 2);
        assert_eq!(header.format, 3);

        let serialized: Vec<u8> = header.into();
        assert_eq!(serialized.len(), MagicHeader::MAGIC_SIZE);
        assert_eq!(&serialized[..4], b"RCM\0");
        assert_eq!(&serialized[4..8], 3_u32.to_le_bytes());
        assert_eq!(
            &serialized[8..12],
            (ClusteringMethod::Prefix as u32).to_le_bytes()
        );
        assert_eq!(&serialized[12..], 2_i32.to_le_bytes());

        let deserialized = MagicHeader::try_from(serialized.as_slice()).unwrap();
        assert_eq!(deserialized, model.header().unwrap());
    }

    /// The body is the bincode encoding, with `DefaultOptions`, of the
    /// fields in the order of the format, each of its type.
    #[test]
    fn body_fields_in_order() {
        let model = full_model();
        #[allow(clippy::type_complexity)] // The tuple spells out the format.
        let fields: (
            i32,
            String,
            Vec<u8>,
            i32,
            String,
            Option<String>,
            i64,
            Vec<crate::types::ModelBatchInfo>,
            crate::types::ModelScores,
            ClusteringModelTypeRef,
            TrainingRead,
            Vec<DetectionModelState>,
            Option<u32>,
        ) = (
            model.id,
            model.name.clone(),
            model.serialized_classifier.clone(),
            model.max_event_id_num,
            model.raw_event_kind.clone(),
            model.log_kind.clone(),
            model.classification_id,
            model.batch_info.clone(),
            model.scores.clone(),
            model.clustering_model_type.clone(),
            model.training_read.clone(),
            model.detection_model_states.clone(),
            model.cluster_count_at_training,
        );
        let header: Vec<u8> = model.header().unwrap().into();
        let body = bincode::DefaultOptions::new().serialize(&fields).unwrap();

        let serialized = model.into_serialized().unwrap();
        assert_eq!(&serialized[..MagicHeader::MAGIC_SIZE], header.as_slice());
        assert_eq!(&serialized[MagicHeader::MAGIC_SIZE..], body.as_slice());
    }

    #[test]
    fn round_trip_of_every_field() {
        let serialized = full_model().into_serialized().unwrap();
        assert_eq!(Model::from_serialized(&serialized).unwrap(), full_model());
    }

    /// Both values of the cluster count at training round-trip, and the
    /// field is the last of the body: `None` is one zero byte, `Some(n)` a
    /// one byte followed by `n` as a varint.
    #[test]
    fn the_cluster_count_at_training_round_trips_as_the_last_field() {
        let without = Model {
            cluster_count_at_training: None,
            ..full_model()
        };
        let without_bytes = without.clone().into_serialized().unwrap();
        assert_eq!(without_bytes.last(), Some(&0));
        assert_eq!(Model::from_serialized(&without_bytes).unwrap(), without);

        for (count, encoded) in [
            (0, vec![1, 0]),
            (4, vec![1, 4]),
            (300, vec![1, 0xfb, 0x2c, 0x01]),
            (u32::MAX, vec![1, 0xfc, 0xff, 0xff, 0xff, 0xff]),
        ] {
            let with = Model {
                cluster_count_at_training: Some(count),
                ..full_model()
            };
            let with_bytes = with.clone().into_serialized().unwrap();
            let (rest, last) = with_bytes.split_at(with_bytes.len() - encoded.len());
            assert_eq!(last, encoded.as_slice());
            assert_eq!(rest, &without_bytes[..without_bytes.len() - 1]);
            assert_eq!(Model::from_serialized(&with_bytes).unwrap(), with);
        }
    }

    #[test]
    fn test_models_match_the_fixture() {
        for (model, fixture) in [
            (test_model_1(), TEST_MODEL_1),
            (test_model_2(), TEST_MODEL_2),
            (test_model_3(), TEST_MODEL_3),
        ] {
            assert_eq!(model.clone().into_serialized().unwrap(), fixture);
            assert_eq!(Model::from_serialized(fixture).unwrap(), model);
        }
        assert_eq!(TEST_MODEL_1.len(), 55);
        assert_eq!(
            TEST_MODEL_1[TEST_MODEL_1.len() - 6..],
            [1, 0x13, 1, 1, 9, 0]
        );
        assert_eq!(TEST_MODEL_2.len(), 51);
        assert_eq!(TEST_MODEL_3.len(), 59);
        assert_eq!(
            TEST_MODEL_3,
            data_encoding::HEXLOWER
                .decode(TEST_MODEL_3_BYTES.as_bytes())
                .unwrap()
        );
    }

    /// The engine's fixture is byte-identical to this crate's, and this
    /// codec encodes the test models to it and decodes it to them.
    #[test]
    fn test_models_match_the_engine_fixture() {
        assert_eq!(ENGINE_TEST_MODEL_1, TEST_MODEL_1);
        assert_eq!(ENGINE_TEST_MODEL_2, TEST_MODEL_2);
        assert_eq!(ENGINE_TEST_MODEL_3, TEST_MODEL_3);
        for (model, fixture) in [
            (test_model_1(), ENGINE_TEST_MODEL_1),
            (test_model_2(), ENGINE_TEST_MODEL_2),
            (test_model_3(), ENGINE_TEST_MODEL_3),
        ] {
            assert_eq!(model.clone().into_serialized().unwrap(), fixture);
            assert_eq!(Model::from_serialized(fixture).unwrap(), model);
        }
    }

    #[test]
    fn other_formats_are_refused() {
        let serialized = full_model().into_serialized().unwrap();
        for format in [0, 1, 2, 4, u32::MAX] {
            let error = Model::from_serialized(&with_format(&serialized, format)).unwrap_err();
            assert_eq!(
                error.to_string(),
                format!("Model format mismatch: {format} (Expecting: 3)")
            );
        }
    }

    /// The format 2 golden bytes, which petabi/reconverge#1959 and earlier
    /// versions of this crate wrote, are refused.
    #[test]
    fn format_2_golden_fixture_is_refused() {
        const GOLDEN: &str = "52434d0002000000010000000100000002016d03010203320468747470000000";

        let serialized = data_encoding::HEXLOWER.decode(GOLDEN.as_bytes()).unwrap();
        assert_eq!(serialized.len(), 32);
        let error = Model::from_serialized(&serialized).unwrap_err();
        assert_eq!(error.to_string(), "Model format mismatch: 2 (Expecting: 3)");
    }

    #[test]
    fn a_byte_after_the_body_is_refused() {
        for fixture in [TEST_MODEL_1, TEST_MODEL_2, TEST_MODEL_3] {
            let mut serialized = fixture.to_vec();
            serialized.push(0);
            assert!(Model::from_serialized(&serialized).is_err());
        }
    }

    #[test]
    fn a_truncated_body_is_refused() {
        for fixture in [TEST_MODEL_1, TEST_MODEL_2, TEST_MODEL_3] {
            assert!(Model::from_serialized(&fixture[..fixture.len() - 1]).is_err());
        }
    }
}
