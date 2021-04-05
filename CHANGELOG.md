# [0.10.0](https://github.com/aykxt/crypto/compare/v0.9.1...v0.10.0) (2021-04-05)

### Features

- **block-ciphers:** add 3DES algorithm
  ([c0877ae](https://github.com/aykxt/crypto/commit/c0877aebe586b3d4047ea69c3d434ea414bcd2c5))
- **block-ciphers:** add DES algorithm
  ([15d408e](https://github.com/aykxt/crypto/commit/15d408eb7b2c753fecaab48926499af6717af530))

# [0.9.1](https://github.com/aykxt/crypto/compare/v0.9.0...v0.9.1) (2021-04-04)

### Bug Fixes

- **pbkdf2:** fix offset out of bounds
  ([1377a73](https://github.com/aykxt/crypto/commit/1377a739fa80b2b26907616684e65c2bc124d220))

# [0.9.0](https://github.com/aykxt/crypto/compare/v0.8.0...v0.9.0) (2021-04-02)

### Features

- **Block ciphers:** add CAST5 algorithm
  ([840c419](https://github.com/aykxt/crypto/commit/840c41963dbae0c59aa51f1529dae7720804d49c))

# [0.8.0](https://github.com/aykxt/crypto/compare/v0.7.0...v0.8.0) (2021-03-26)

### Features

- **KDFs:** add HKDF algorithm
  ([d6260ca](https://github.com/aykxt/crypto/commit/d6260ca8e5aa3d987c05bd8ec36d7611e740128c))
- **KDFs:** add PBKDF2 algorithm
  ([d3a0d78](https://github.com/aykxt/crypto/commit/d3a0d7873cd031d523f0a7798d249c9c59c4944f))

# [0.7.0](https://github.com/aykxt/crypto/compare/v0.6.0...v0.7.0) (2021-03-23)

### Features

- **block-modes:** add CTR block mode
  ([f91253c](https://github.com/aykxt/crypto/commit/f91253cd39b9add21600f1038514732fc1fd2e17))

# [0.6.0](https://github.com/aykxt/crypto/compare/v0.5.0...v0.6.0) (2021-03-16)

- refactor!: generic block cipher modes
  ([e0329bf](https://github.com/aykxt/crypto/commit/e0329bfa03ffa179d75b8769e6acadcda6c47d8e))

### Performance Improvements

- **AES:** use DataView for better performance
  ([0c20792](https://github.com/aykxt/crypto/commit/0c207923948049e2e8942ada7e31f93aef382803))

# [0.5.0](https://github.com/aykxt/crypto/compare/v0.4.1...v0.5.0) (2021-03-14)

- refactor!: remove root mod.ts
  ([d74ae74](https://github.com/aykxt/crypto/commit/d74ae7434533dd50c96515e6606c7e04512fa722))

### Features

- **Blowfish:** add CFB and OFB block modes
  ([1f61da9](https://github.com/aykxt/crypto/commit/1f61da999c691f6d9ff878f8e2bef19e32825e1b))
- add HMAC algorithm
  ([bd08fa8](https://github.com/aykxt/crypto/commit/bd08fa8706f283314bc1da7bd0c1ee139599afc6))
- **AES:** add CFB block mode
  ([39bb513](https://github.com/aykxt/crypto/commit/39bb513b7c46ae297f77b9aa0a67542e03c1be0a))
- **AES:** add OFB block mode
  ([3e54974](https://github.com/aykxt/crypto/commit/3e54974fca3c35704d92bf9655d1c21040bc472b))

## [0.4.1](https://github.com/aykxt/crypto/compare/v0.4.0...v0.4.1) (2021-03-12)

### Performance Improvements

- **AES:** reduce amount of array copies
  ([5db6174](https://github.com/aykxt/crypto/commit/5db61740f9ff3b69a877193d83f70971844d8674))

# [0.4.0](https://github.com/aykxt/crypto/compare/v0.3.5...v0.4.0) (2021-03-11)

- refactor!: rewrite AES and Blowfish logic
  ([5288fa3](https://github.com/aykxt/crypto/commit/5288fa30fdc799c58e4c2c4de81b3eca9cc83e6b))

### BREAKING CHANGES

- Block modes are now separated from encryption logic and can be instantiated
  directly, e.g. AesEcb
