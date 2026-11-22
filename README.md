# review-database

This crate provides a permanent storage solution for data collected and
maintained by REview, a cybersecurity analysis system. It offers a robust and
flexible database interface for efficient data management.

[![Coverage Status](https://codecov.io/gh/aicers/review-database/branch/main/graphs/badge.svg)](https://codecov.io/gh/aicers/review-database)

## Features

- High-performance persistent storage
- Comprehensive data models for cybersecurity events, network information, and
  system configurations
- Advanced querying capabilities including time series data and statistical
  analysis
- Support for various cybersecurity-related entities such as agents, data
  sources, and traffic filters
- Database format version checks that refuse data directories and backups
  of an unsupported format
- Backup and restore functionalities for data integrity
- Efficient data structures for handling large-scale datasets

## Key Components

- Event Management: Store and retrieve the detection events detection engines
  report, filter and count them, and score them against triage policies
- Network Configuration: Handle trusted domains and Tor exit nodes
- Model Management: Store and update machine learning models with versioning
  support
- Data Analysis: Support for outlier detection, time series analysis, and
  statistical computations

## Country Codes At Ingestion

Open an IP2Location database in the caller application and pass it to
`Store::new` as `Some(Arc<ip2location::DB>)` to share it with event writers.
`EventDb::put` then resolves the country code of each endpoint address of a
detection event and stores it with the record, outside the event itself.
Producers do not provide country codes. See the public rustdoc for
[`COUNTRY_CODE_UNKNOWN`](https://docs.rs/review-database/latest/review_database/constant.COUNTRY_CODE_UNKNOWN.html)
and
[`COUNTRY_CODE_UNRESOLVED`](https://docs.rs/review-database/latest/review_database/constant.COUNTRY_CODE_UNRESOLVED.html)
for placeholder semantics. `StoredDetectionEvent::country_codes` returns each
endpoint address with its stored code.

## License

Copyright 2018-2025 Petabi, Inc.
Copyright 2025-2026 ClumL Inc.

Licensed under [Apache License, Version 2.0][apache-license] (the "License");
you may not use this crate except in compliance with the License.

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See [LICENSE](LICENSE) for
the specific language governing permissions and limitations under the License.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the [Apache-2.0
license][apache-license], shall be licensed as above, without any additional
terms or conditions.

[apache-license]: http://www.apache.org/licenses/LICENSE-2.0
