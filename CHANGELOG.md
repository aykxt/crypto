# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.11.0] - 2025-02-14

### Added
-  (*block-modes*): Add IGE block mode ([d39bd50](https://github.com/aykxt/crypto/commit/d39bd504b5d6bcb396de759cf639665eb120f9cb))
-  (*benchmarks*): Add AES-128-CBC WebCrypto benchmark ([6643132](https://github.com/aykxt/crypto/commit/66431325efc6a1a057230099389c3ef841678be3))


### Changed
-  (*deps*): Migrate to deno.json ([1f0bd45](https://github.com/aykxt/crypto/commit/1f0bd457e27efd3c317ff0d3ed74e79ab3be56f1))


### Fixed
-  (*block-ciphers*): Cbc: use array offsets (#5) ([7486524](https://github.com/aykxt/crypto/commit/7486524fa8a42a75693db7826082e66050d48067))


### Removed
-  (*ci*): Remove codeql-analysis.yml ([b2ecd50](https://github.com/aykxt/crypto/commit/b2ecd50517e5e25766e21aea9a924788c596bab6))
-  (*benchmarks*): Remove GodCrypto AES benchmarks ([6eab45f](https://github.com/aykxt/crypto/commit/6eab45fc2f1f927fa836283f08282f6cd891debf))
-  (*ci*): Remove canary version from Deno matrix ([193e77f](https://github.com/aykxt/crypto/commit/193e77fde76e4a30591c4477c712e759c24f45db))

## [0.10.1] - 2023-07-14

### Changed
-  (*benchmark*): Migrate to Deno.bench ([ea25f83](https://github.com/aykxt/crypto/commit/ea25f831f0d3ec380dbcdb82f608e8bb7f1c8bf9))


### Fixed
-  (*AES*): Use DataView instead of TypedArray ([935e7f0](https://github.com/aykxt/crypto/commit/935e7f09cc5bd89e045ef1e7e0139ffe1a7f040b))
-  (*AES*): Fix bug causing wrong output sometimes ([315d4f6](https://github.com/aykxt/crypto/commit/315d4f675f412f56c21950eaade0fb1a12a45632))


### Removed
-  Remove unnecessary parentheses ([2584522](https://github.com/aykxt/crypto/commit/25845221f8bbca2fd8c74fafec1cf622ea8f670f))

## [0.10.0] - 2021-04-05

### Added
-  (*block-ciphers*): Add DES algorithm ([15d408e](https://github.com/aykxt/crypto/commit/15d408eb7b2c753fecaab48926499af6717af530))
-  (*block-ciphers*): Add 3DES algorithm ([c0877ae](https://github.com/aykxt/crypto/commit/c0877aebe586b3d4047ea69c3d434ea414bcd2c5))

## [0.9.1] - 2021-04-04

### Fixed
-  (*pbkdf2*): Fix offset out of bounds ([1377a73](https://github.com/aykxt/crypto/commit/1377a739fa80b2b26907616684e65c2bc124d220))

## [0.9.0] - 2021-04-02

### Added
-  (*block-ciphers*): Add CAST5 algorithm ([840c419](https://github.com/aykxt/crypto/commit/840c41963dbae0c59aa51f1529dae7720804d49c))

## [0.8.0] - 2021-03-26

### Added
-  (*KDFs*): Add HKDF algorithm ([d6260ca](https://github.com/aykxt/crypto/commit/d6260ca8e5aa3d987c05bd8ec36d7611e740128c))
-  (*KDFs*): Add PBKDF2 algorithm ([d3a0d78](https://github.com/aykxt/crypto/commit/d3a0d7873cd031d523f0a7798d249c9c59c4944f))

## [0.7.0] - 2021-03-23

### Added
-  (*block-modes*): Add CTR block mode ([f91253c](https://github.com/aykxt/crypto/commit/f91253cd39b9add21600f1038514732fc1fd2e17))

## [0.6.0] - 2021-03-16

### Changed
-  **BREAKING CHANGE**: Generic block cipher modes ([e0329bf](https://github.com/aykxt/crypto/commit/e0329bfa03ffa179d75b8769e6acadcda6c47d8e))


### Fixed
-  (*AES*): Use DataView for better performance ([0c20792](https://github.com/aykxt/crypto/commit/0c207923948049e2e8942ada7e31f93aef382803))

## [0.5.0] - 2021-03-14

### Added
-  (*AES*): Add CFB block mode ([39bb513](https://github.com/aykxt/crypto/commit/39bb513b7c46ae297f77b9aa0a67542e03c1be0a))
-  (*AES*): Add OFB block mode ([3e54974](https://github.com/aykxt/crypto/commit/3e54974fca3c35704d92bf9655d1c21040bc472b))
-  Add HMAC algorithm ([bd08fa8](https://github.com/aykxt/crypto/commit/bd08fa8706f283314bc1da7bd0c1ee139599afc6))
-  (*Blowfish*): Add CFB and OFB block modes ([1f61da9](https://github.com/aykxt/crypto/commit/1f61da999c691f6d9ff878f8e2bef19e32825e1b))


### Changed
-  (*benchmark*): Parse benchmark args ([ff97e20](https://github.com/aykxt/crypto/commit/ff97e20ff01ed4120a35642e7e28526425202757))
-  (*AES*): Compute constants ([cf46ca7](https://github.com/aykxt/crypto/commit/cf46ca721fefa55a16ff382813d7f2ea54ac7c64))


### Removed
-  **BREAKING CHANGE**: Remove root mod.ts ([d74ae74](https://github.com/aykxt/crypto/commit/d74ae7434533dd50c96515e6606c7e04512fa722))

## [0.4.1] - 2021-03-12

### Fixed
-  (*AES*): Reduce amount of array copies ([5db6174](https://github.com/aykxt/crypto/commit/5db61740f9ff3b69a877193d83f70971844d8674))

## [0.4.0] - 2021-03-11

### Changed
-  **BREAKING CHANGE**: Rewrite AES and Blowfish logic ([5288fa3](https://github.com/aykxt/crypto/commit/5288fa30fdc799c58e4c2c4de81b3eca9cc83e6b)):
Block modes are now separated from encryption
logic and can be instantiated directly, e.g. AesEcb


[0.11.0]: https://github.com/aykxt/crypto/compare/v0.10.1..v0.11.0
[0.10.1]: https://github.com/aykxt/crypto/compare/v0.10.0..v0.10.1
[0.10.0]: https://github.com/aykxt/crypto/compare/v0.9.1..v0.10.0
[0.9.1]: https://github.com/aykxt/crypto/compare/v0.9.0..v0.9.1
[0.9.0]: https://github.com/aykxt/crypto/compare/v0.8.0..v0.9.0
[0.8.0]: https://github.com/aykxt/crypto/compare/v0.7.0..v0.8.0
[0.7.0]: https://github.com/aykxt/crypto/compare/v0.6.0..v0.7.0
[0.6.0]: https://github.com/aykxt/crypto/compare/v0.5.0..v0.6.0
[0.5.0]: https://github.com/aykxt/crypto/compare/v0.4.1..v0.5.0
[0.4.1]: https://github.com/aykxt/crypto/compare/v0.4.0..v0.4.1
[0.4.0]: https://github.com/aykxt/crypto/compare/v0.3.5..v0.4.0

<!-- generated by git-cliff -->
