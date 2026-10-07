mod time_series;

use serde::{Deserialize, Serialize};

#[allow(deprecated)]
pub use self::time_series::{ClusterTrend, LineSegment, Regression, TopTrendsByColumn};

impl TryFrom<(i32, i32)> for StructuredColumnType {
    type Error = anyhow::Error;

    fn try_from((column_index, type_id): (i32, i32)) -> Result<Self, Self::Error> {
        let data_type = match type_id {
            1 => "int64",
            2 => "enum",
            3 => "float64",
            4 => "utf8",
            5 => "ipaddr",
            6 => "datetime",
            7 => "binary",
            _ => {
                return Err(anyhow::anyhow!(
                    "unknown structured column type ID: {type_id}"
                ));
            }
        };
        Ok(Self {
            column_index,
            data_type: data_type.to_string(),
        })
    }
}

#[derive(Clone, Deserialize)]
pub struct ElementCount {
    pub value: String,
    pub count: i64,
}

#[derive(Deserialize, Serialize)]
pub struct StructuredColumnType {
    pub column_index: i32,
    pub data_type: String,
}

#[derive(Clone, Deserialize)]
pub struct TopElementCountsByColumn {
    pub column_index: usize,
    pub counts: Vec<ElementCount>,
}

#[cfg(test)]
mod tests {
    use super::StructuredColumnType;

    #[test]
    fn structured_column_type_conversion() {
        for type_id in [0, 8] {
            assert!(StructuredColumnType::try_from((42, type_id)).is_err());
        }
        for (type_id, expected) in [
            (1, "int64"),
            (2, "enum"),
            (3, "float64"),
            (4, "utf8"),
            (5, "ipaddr"),
            (6, "datetime"),
            (7, "binary"),
        ] {
            let column = StructuredColumnType::try_from((42, type_id)).unwrap();
            assert_eq!(column.column_index, 42);
            assert_eq!(column.data_type, expected);
        }
    }
}
