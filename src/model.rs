use anyhow::Result;
use bincode::Options;
use serde::{Deserialize, Serialize};
use strum_macros::{Display, EnumString};

#[derive(Deserialize)]
pub struct Digest {
    pub id: i32,
    pub name: String,
    pub version: i32,
    pub data_source_id: i32,
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
    pub data_source_id: i32,
    pub classification_id: i64,
    pub batch_info: Vec<crate::types::ModelBatchInfo>,
    pub scores: crate::types::ModelScores,
}

impl Model {
    fn header(&self) -> Result<MagicHeader> {
        use std::str::FromStr;
        Ok(MagicHeader {
            tag: MagicHeader::MAGIC_STRING.to_vec(),
            format: MagicHeader::FORMAT_VERSION,
            kind: ClusteringMethod::from_str(&self.kind)?,
            version: self.version,
        })
    }

    /// # Errors
    ///
    /// Returns an error if format version doesn't match `MagicHeader::FORMAT_VERSION` or
    /// if deserialization process failed.
    pub fn from_serialized(serialized: &[u8]) -> Result<Self> {
        use anyhow::anyhow;

        let header_bytes = serialized
            .get(..MagicHeader::MAGIC_SIZE)
            .ok_or_else(|| anyhow!("model data is shorter than the magic header"))?;
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
            data_source_id: model.data_source_id,
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
            data_source_id: self.data_source_id,
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
enum ClusteringMethod {
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
    const FORMAT_VERSION: u32 = 1;
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
            return Err(anyhow!("length should be > {}", MagicHeader::MAGIC_SIZE));
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
    data_source_id: i32,
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
                data_source_id: 1,
                classification_id: 0,
                batch_info: vec![],
                scores: crate::types::ModelScores::default(),
            },
            super::Body {
                id: 1,
                name: "example".to_owned(),
                serialized_classifier: b"test".to_vec(),
                max_event_id_num: 123,
                data_source_id: 1,
                classification_id: 0,
                batch_info: vec![],
                scores: crate::types::ModelScores::default(),
            },
        )
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
    }

    #[test]
    fn short_serialized_model_returns_error() {
        let result = super::Model::from_serialized(&[0; super::MagicHeader::MAGIC_SIZE - 1]);

        assert!(result.is_err());
    }
}
