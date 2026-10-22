use anyhow::Result;
use bincode::Options;
use serde::{Deserialize, Serialize};
use strum_macros::{Display, EnumString};

#[derive(Deserialize)]
pub struct Digest {
    pub id: i32,
    pub name: String,
    pub version: i32,
    pub event_kind: String,
    pub classification_id: Option<i64>,
}

#[derive(Debug)]
pub struct Model {
    pub id: i32,
    pub name: String,
    pub version: i32,
    pub kind: String,
    pub serialized_classifier: Vec<u8>,
    pub max_event_id_num: i32,
    pub event_kind: String,
    pub classification_id: i64,
    pub batch_info: Vec<crate::types::ModelBatchInfo>,
    pub scores: crate::types::ModelScores,
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

    /// Decodes a model serialized in format 2.
    ///
    /// # Errors
    ///
    /// Returns an error if the input is shorter than the 16-byte header, if
    /// its format is not `MagicHeader::FORMAT_VERSION` (no earlier format is
    /// read), or if deserialization fails.
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
            event_kind: model.event_kind,
            classification_id: model.classification_id,
            batch_info: model.batch_info,
            scores: model.scores,
        })
    }

    /// # Errors
    ///
    /// Returns an error if serialization process failed.
    pub fn into_serialized(self) -> Result<Vec<u8>> {
        let mut buf = <Vec<u8>>::from(self.header()?);
        let model = Body {
            id: self.id,
            name: self.name,
            serialized_classifier: self.serialized_classifier,
            max_event_id_num: self.max_event_id_num,
            event_kind: self.event_kind,
            classification_id: self.classification_id,
            batch_info: self.batch_info,
            scores: self.scores,
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
    const FORMAT_VERSION: u32 = 2;
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

#[derive(Deserialize, Serialize)]
struct Body {
    id: i32,
    name: String,
    serialized_classifier: Vec<u8>,
    max_event_id_num: i32,
    event_kind: String,
    classification_id: i64,
    batch_info: Vec<crate::types::ModelBatchInfo>,
    scores: crate::types::ModelScores,
}

#[cfg(test)]
mod tests {

    fn example() -> (super::Model, super::Body) {
        (
            super::Model {
                id: 1,
                name: "example".to_owned(),
                version: 2,
                kind: "Multifield".to_owned(),
                serialized_classifier: b"test".to_vec(),
                max_event_id_num: 123,
                event_kind: "http".to_owned(),
                classification_id: 0,
                batch_info: vec![],
                scores: crate::types::ModelScores::default(),
            },
            super::Body {
                id: 1,
                name: "example".to_owned(),
                serialized_classifier: b"test".to_vec(),
                max_event_id_num: 123,
                event_kind: "http".to_owned(),
                classification_id: 0,
                batch_info: vec![],
                scores: crate::types::ModelScores::default(),
            },
        )
    }

    #[test]
    fn short_serialized_model() {
        for length in [0, 15] {
            let input = vec![0; length];
            let error = super::Model::from_serialized(&input).err().unwrap();
            assert_eq!(error.to_string(), "length should be 16 bytes or more");
            let error = super::MagicHeader::try_from(input.as_slice()).unwrap_err();
            assert_eq!(error.to_string(), "length should be 16 bytes or more");
        }
    }

    #[test]
    fn header() {
        let (model, _) = example();
        let header = model.header().unwrap();
        assert_eq!(header.kind, super::ClusteringMethod::Multifield);
        assert_eq!(header.version, 2);
        assert_eq!(header.format, super::MagicHeader::FORMAT_VERSION);

        let serialized: Vec<u8> = header.into();
        assert_eq!(&serialized[..4], super::MagicHeader::MAGIC_STRING);
        assert_eq!(
            &serialized[4..8],
            super::MagicHeader::FORMAT_VERSION.to_le_bytes()
        );
        assert_eq!(
            &serialized[8..12],
            (super::ClusteringMethod::Multifield as u32).to_le_bytes()
        );
        assert_eq!(&serialized[12..], 2_u32.to_le_bytes());

        let deserialized = super::MagicHeader::try_from(serialized.as_slice()).unwrap();
        assert_eq!(deserialized, model.header().unwrap());
    }

    #[test]
    fn serialized_model() {
        use bincode::Options;

        let (model, body) = example();
        let header = model.header().unwrap();
        let s_header: Vec<u8> = header.into();
        let s_body = bincode::DefaultOptions::new().serialize(&body).unwrap();

        let serialized = model.into_serialized().unwrap();
        assert_eq!(&serialized[..super::MagicHeader::MAGIC_SIZE], &s_header);
        assert_eq!(&serialized[super::MagicHeader::MAGIC_SIZE..], &s_body);

        let d_model = super::Model::from_serialized(&serialized).unwrap();
        let (model, _body) = example();
        assert_eq!(d_model.id, model.id);
        assert_eq!(d_model.name, model.name);
        assert_eq!(d_model.version, model.version);
        assert_eq!(d_model.kind, model.kind);
        assert_eq!(d_model.serialized_classifier, model.serialized_classifier);
        assert_eq!(d_model.max_event_id_num, model.max_event_id_num);
        assert_eq!(d_model.event_kind, "http");
        assert_eq!(d_model.classification_id, model.classification_id);
    }

    /// The same fixture as petabi/reconverge#1959: header format 2, method 1
    /// (`Multifield`), version 1, and a body whose `event_kind` sits where
    /// format 1 had `data_source_id`.
    #[test]
    fn format_2_golden_fixture() {
        const GOLDEN: &str = "52434d0002000000010000000100000002016d03010203320468747470000000";

        let model = super::Model {
            id: 1,
            name: "m".to_owned(),
            version: 1,
            kind: "Multifield".to_owned(),
            serialized_classifier: vec![1, 2, 3],
            max_event_id_num: 25,
            event_kind: "http".to_owned(),
            classification_id: 0,
            batch_info: vec![],
            scores: crate::types::ModelScores::default(),
        };
        let serialized = model.into_serialized().unwrap();
        assert_eq!(serialized.len(), 32);
        assert_eq!(data_encoding::HEXLOWER.encode(&serialized), GOLDEN);

        let decoded = super::Model::from_serialized(&serialized).unwrap();
        assert_eq!(decoded.event_kind, "http");
        assert_eq!(decoded.kind, "Multifield");
        assert_eq!(decoded.max_event_id_num, 25);
    }

    #[test]
    fn format_1_is_refused() {
        let (model, _) = example();
        let mut serialized = model.into_serialized().unwrap();
        serialized[4..8].copy_from_slice(&1_u32.to_le_bytes());

        let error = super::Model::from_serialized(&serialized).unwrap_err();
        assert_eq!(error.to_string(), "Model format mismatch: 1 (Expecting: 2)");
    }
}
