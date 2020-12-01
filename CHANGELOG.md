# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.5] - 2020-12-01
### Fixed
- Incoming serno may be a string as well.

## [0.1.4] - 2020-11-27
### Fixed
- Correct parsing of auth serno in case of length is less than 10 bytes.

### Changed
- Some cleanup.

## [0.1.3] - 2020-07-08
### Changed
- Generated auth serno is fitted to 10 bytes.

## [0.1.2] - 2020-07-07
### Changed
- Fixed ``method not found in std::result::Result<extfg_sigma::SigmaRequest, std::io::ErrorKind>``.

## [0.1.1] - 2020-07-07
### Added
- Dummy ``SigmaResponse`` serialization/deserialization.

## [0.1.0] - 2020-07-06
### Added
- Message serialization.
