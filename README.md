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
- Support for various cybersecurity-related entities such as agents, customers,
  data sources, and traffic filters
- Flexible schema migration tools for seamless updates
- Backup and restore functionalities for data integrity
- Efficient data structures for handling large-scale datasets

## Key Components

- Event Management: Store and retrieve various types of security events (e.g.,
  HTTP threats, network threats, Windows threats)
- User and Account Management: Manage user accounts, access tokens, and
  permissions
- Network Configuration: Handle allow/block networks, trusted domains, and Tor
  exit nodes
- Model Management: Store and update machine learning models with versioning
  support
- Data Analysis: Support for outlier detection, time series analysis, and
  statistical computations

## License

Copyright 2018-2025 Petabi, Inc.

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
