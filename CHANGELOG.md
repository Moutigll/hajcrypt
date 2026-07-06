# Changelog

## [v0.2.0] - 24 Feb 2026

- Build: Add Makefile and sources.mk for ft_ssl - Create a cli and a lib - Compile hajlib and project sources. - Build ft_ssl executable with proper linking. - Add clean, fclean, and re targets. (37cdfc0)
- Build/Feat: Update Makefile, submodule, and streaming padding (19dca05)
- Build: Integrate const header generation and improve Makefile (a3841c8)
- Feat: Add generic padding and endian utilities for hash functions (a24e802)
- Feat: Add hajlib submodule and basic hash/bit utilities (7532bea)
- Feat: Add robust CLI argument parsing for ft_ssl (7f50975)
- Feat(benchmark: Add benchmark script for ft_ssl vs OpenSSL (20ebca5)
- Feat(benchmark): Add Whirlpool benchmark with rhash (29e45c5)
- Feat(cli,hash,consts): Integrate Whirlpool and generalize padding (b78543e)
- Feat(cli): Refactor cli execution flow + Added sha256 header (02d818c)
- Feat(consts): Add header generation system for MD5 constants (b10b73b)
- Feat(consts): Add SHA-256 header generator and unify constant utilities (32e6c7c)
- Feat(consts): Add Whirlpool constant generator (856cfb3)
- Feat(md5): Implement streaming API with optimized transform (4d7b6b7)
- Feat(sha256): Add high-level SHA-256 API + conditional ARMv8 transform (b625bbe)
- Feat(sha256/arm64): Add ARMv8 SHA-256 compression with crypto extensions (0f8a12c)
- Feat(sha256): Implement full SHA-256 compression function (4492f53)
- Feat(whirlpool): Implement Whirlpool compression and hash API (c91edd7)
- Fix(typos): Fix whirlpool cont file name + Fix lengthFieldSize spelling (93a3ceb)
- Perf(md5): Optimize md5Update and inline md5Transform (4774b66)
- Perf(whirlpool): Add optimized transform using T-tables (7e65b4b)
- Perf(whirlpool): Generate T-tables for optimized round processing (f5efcf8)
- Refactor(hash): Align SHA-256 context, update padding, and finalize hash headers (f1a8474)
- Refactor: Introduce CLI dispatch, client structs, and unify MD5 padding (85944de)

## [v0.3.0] - 05 Mar 2026

- Build(consts): Add Base64 constant tables generator (b4f3b99)
- Build(consts): Add DES constants generator (e03a548)
- Build(crypto): Add HMAC support for MD5, SHA-256, and Whirlpool (337ce9d)
- Build(crypto): add secure random byte generator (364ec1c)
- Build(test): Add comprehensive ft_ssl CLI tester script (4e5a664)
- Docs: Add proper README and update leak flags (6f5009e)
- Docs(README): Update README clone instructions and bump hajlib submodule (51e46f3)
- Feat(cipher): Add DES interface and context structures for ECB/CBC modes (d49149a)
- Feat(cli): Add generic encoding interface and integrate Base64 command (ba1edb4)
- Feat(cli): Integrate HMAC support into CLI with -K flag (2464c45)
- Feat(consts): Refactor DES S-box generation and add precomputed lookup tables (5135c4d)
- Feat(des): Add CBC mode implementation and refactor ECB update/final (84a0539)
- Feat(des): Implement core DES cryptographic primitives (8369c5d)
- Feat(des): Implement ECB mode and PKCS#7 padding functions (514f2a3)
- Feat(encode): Add Base64 encoding/decoding implementation (54efbbe)
- Feat(pbkdf): Add PBKDF utility functions for key derivation (7e9c1a7)
- Feat(pbkdf): Implement BytesToKey key derivation functions (9b95382)
- Fix(pbkdf): Make EVP_BytesToKey implementation OpenSSL-compatible (068fcae)
- Perf(des): Implement optimized version using precomputed lookup tables (4c45c45)
- Refactor(cli): Split cipher I/O operations into separate module and add DES support (c7cb381)
- Refactor(cli): unify algorithm dispatch and improve -p/-q/-r output formatting (d94ba15)
- Refactor(crypto): Unify hash and cipher interfaces into generic dispatch system (43f7d5e)
- Refactor(encoding): Reorganize Base64 module and add CLI streaming support (7167043)

## [v0.4.0] - 11 Mar 2026

- feat(argon2): Add complete Argon2 password hashing implementation (08c4a96)
- feat(argon2): Add encoding/decoding and verification functions (381ca6b)
- feat(argon2): Add secure memory wiping and multi-threading support (88b71a7)
- feat(bcrypt): Add bcrypt password hashing algorithm (e365f3d)
- feat(blake2b): Add Blake2b hash implementation and constant generator (d6ac19c)
- feat(blake2b): Integrate Blake2b into CLI and benchmark suite (fa8bd0a)
- feat(blowfish): Add core Blowfish cipher implementation (26ce850)
- fix(argon2): Fix crashes, division by zero, and buffer overflows (1f0f894)

## [v0.5.0] - 16 Mar 2026

- feat(aes): Add AES block encryption/decryption implementation (e6132f1)
- feat(aes): Add AES constant generator (4378106)
- feat(aes): Add AES-ECB and AES-CBC mode implementations (62078a4)
- feat(aes): Add ARM64 NEON accelerated AES implementation (6fb3a8e)
- feat(aes): Update AES headers and add secure utilities (5184547)
- feat(bench): Add AES performance benchmark and switched to MB/s (6826a2d)
- feat(cli): Add AES-192/256 support and improve interactive mode (19fac8c)
- feat(cli): Complete cipher CLI with password prompting and base64 support (cacd50c)
- fix(aes): Fix undefined behavior in AES key expansion and improve bcrypt KDF (24a7091)

## [v0.6.0] - 31 Mar 2026

- feat(cipher): Add PCBC mode support for AES and DES (fbfe21d)
- feat(cipher): Add x86 AES-NI optimized transformations for AES                                                                                             (feature/cipher-modes)% (e355953)
- feat(cipher): Implement CFB mode support for AES and DES (e98966a)
- feat(cipher): Implement CTR mode support for AES and DES (fe99f27)
- feat(cipher): Implement GCM mode support for AES with ARM64 optimizations (2c1c372)
- feat(cipher): Implement OFB mode support for AES and DES (4284c2c)

## [v0.7.0] - 01 Apr 2026

- feat(cipher): Add Triple DES (3DES) CBC, CFB and CTR mode implementations (cf0a0dd)
- feat(cipher): Add Triple DES (3DES) ECB, OFB and PCBC mode implementations (e79df4c)
- feat(cli): Register Triple DES (3DES) commands and improve usage display (10a45cf)

## [v0.8.0] - 07 Apr 2026

- feat(blowfish): Add Blowfish CBC and ECB mode implementations (388de80)
- feat(blowfish): Add CFB, CTR, OFB and PCBC mode implementations (50f1622)
- perf(blowfish): Eliminate per-block key schedule copies and optimize block operations (6347080)

## [v0.9.0] - 08 Apr 2026

- feat(blowfish): Add Blowfish CBC and ECB mode implementations (e2411bb)
- feat(blowfish): Add CFB, CTR, OFB and PCBC mode implementations (043e731)
- feat(test): Add complete 3DES test suite for ECB and CBC modes (c3646ef)
- feat(test): Add complete DES test suite with all cipher modes (a888021)
- feat(test): Implement AES-128 test suite with all cipher modes (30ca562)
- fix(des3): Correct Triple DES decryption order and enhance test reporting (86d7632)
- perf(blowfish): Eliminate per-block key schedule copies and optimize block operations (546155f)

## [v0.11.0] - 19 May 2026

- feat(cli): Add `rsa` command with full key management and password handling (f2d8ea4)
- feat(cli): Add rsautl/pkeyutl command for RSA encryption, decryption, sign and verify (ad1ac4a)
- feat(install): Add make install/uninstall targets with shell completion support (32400c9)
- feat(rsa): Add bigint header and remove legacy math implementation (43bf41e)
- feat(rsa): Add bigint library with Montgomery modular exponentiation (d569e66)
- feat(rsa): Add genrsa command with PEM encoding and key output (c8363db)
- feat(rsa): Add PKCS#1 v1.5 encryption, decryption, sign and verify (8564430)
- feat(rsa): Add PKCS#1 v1.5 padding, pkeyutl command, and hash enhancements (02ef0af)
- feat(rsa): Enhance RSA key validation with comprehensive security checks (d3cc441)
- feat(rsa): Port RSA to bigint library with proper key generation (533eca7)
- feat(x509): Add ASN.1 and PEM headers (1483f40)
- feat(x509): Add PKCS#1/PKCS#8 PEM encryption and ASN.1 parsing enhancements (7405a64)
- feat(x509): Implement ASN.1 DER and PEM encoding/decoding (7f6db9a)
- fix(bcrypt): fix buffer size and add hash length validation (504d313)

## [v0.12.0] - 27 May 2026

- feat(asymmetric): Add constant-time operations and side-channel mitigations (e06141b)
- feat(asymmetric): Add generic pkey implementation with PEM handling (de41656)
- feat(dsa): Add DSA key generation and PEM support (ea022b2)
- feat(dsa): Add DSA signing and verification with PKCS#1.5 padding (3bb4669)
- feat(DSA): Added dsa key check and print (ac812c4)
- feat(dsa): Implement DSA signing and verification (e8a3d83)
- feat(rsa): Unify RSA API with generic pkey interface (88f189e)
- fix(asymmetric): Add missing key validation and fix constant-time unpad (8893dd1)
- fix/refactor(pkey): Split public/private key encoding for PKCS#1 and PKCS#8 (90e7eba)

## [v0.13.0] - 01 Jun 2026

- feat(chacha20-poly1305): Add AEAD mode implementation (60bda8b)
- feat(cipher): Add ChaCha20-Poly1305 AEAD header (d13d899)
- feat(cipher): Add ChaCha20 stream cipher implementation (0673e83)
- feat(poly1305): Add Poly1305 message authentication code implementation (f6f76ff)
- feat(rsa): Add Pollard's Rho factorization attack (6c7a77e)
- fix(bcrypt, bigint): Add hash length validation and fix multiplication tests (90725b6)
- fix(bigint): Correct Pollard's Rho memory and logic issues (0cd2797)
- fix(chacha20, bcrypt): Fix NEON endian conversion and add bcrypt constant (cd40aa4)

## [v0.14.0] - 04 Jun 2026

- feat(hash): Add SHA family headers and HMAC declarations (77e009d)
- feat(sha): Add ARM64 NEON acceleration for SHA-1 (9e1067c)
- feat(sha): Add full SHA family implementation (b5ca66d)
- feat(sha): Add SHA constant generation and fix pad params (ab89042)
- feat(sha): Enable ARM64 NEON acceleration for SHA-224 and SHA-256 (c540d98)
- fix(build, aes, secure): Improve cross-platform compatibility and memory clearing (081af7f)

## [v0.15.0] - 06 Jul 2026

- feat!: Add version management (0468c81)
- feat(cli): Add --nopad option to disable padding for block ciphers (022e22d)

