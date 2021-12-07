# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.2] - 2021-12-07
### Fixed
- Functionality added with `codec` module and feature made public.

## [0.3.1] - 2021-12-07
### Added
- Automatic memory preallocation in `Decoder` implementation of `SigmaClientProtocol`.

## [0.3.0] - 2021-12-06
### Fixed
- Several clippy-related code style errors.
### Added
- Implementations of `Decoder` and `Encoder` traits from `tokio_util::codec` under the `codec` feature.

## [0.2.2] - 2021-08-27
### Changed
- Used v0.8 of `rand` crate.

## [0.2.1] - 2021-02-11
### Added
- `SigmaRequest::decode` method for decoding request from `Bytes`;
- `SigmaResponse::encode` method for encoding response into `Bytes`.

## [0.2.0] - 2021-02-05
### Added
- `Error` type.
- New methods for `SigmaRequest`/`SigmaResponse` for constructing this types and accessing their fields;
- Ability to store raw byte fields in `iso_fields` and `iso_subfields` of `SigmaRequest`.
### Changed
- Most of the functions/methods now return `Error` instead of logging and returning `0`/`-1`.
- Renamed some methods of `SigmaRequest`/`SigmaResponse`.

## [0.1.8] - 2020-12-07
### Added
- Tag 0048 "Additional data" support.

## [0.1.7] - 2020-12-03
### Fixed
- Data tags larger than 0x99 BCD.

## [0.1.6] - 2020-12-03
### Added
- Response fee data support.

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
