#ifndef HAJCRYPT_TEST_H
#define HAJCRYPT_TEST_H

#include <stdint.h>
#include <stddef.h>

#define COLOR_RESET   "\033[0m"
#define COLOR_RED	 "\033[31m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_BLUE	"\033[34m"
#define COLOR_MAGENTA "\033[35m"
#define COLOR_CYAN	"\033[36m"

/**
 * @brief Holds a test vector for hash function testing, including input message, its length, and the expected hash output.
 * This structure is used to define test cases for validating the correctness of hash function implementations.
 * - input: pointer to the input message to be hashed (can be binary data)
 * - input_len: length of the input message in bytes
 * - expected: pointer to the expected hash output in hexadecimal string format (for easy comparison and display)
 */
typedef struct {
	const char	*input;
	size_t		input_len;
	const char	*expected;
} testVector_t;

/**
 * @brief Holds test entry information for executing a test function.
 * This structure maps a test name to its corresponding test function pointer,
 * allowing for dynamic test execution and reporting.
 * - name: descriptive name of the test (used for logging and identification)
 * - func: pointer to the test function that returns 0 on success, non-zero on failure
 */
typedef struct {
	const char	*name;
	int			(*func)(void);
} testEntry_t;

extern int g_totalTests;
extern int g_passedTests;

/* Utility functions for test reporting and comparison */
void printSuccess(const char *msg);
void printFailure(const char *msg);
void printInfo(const char *msg);
int compareHex(const char *expected, const uint8_t *actual, size_t len);
void hexDump(const uint8_t *data, size_t len);
int isZeroed(const void *ptr, size_t len);
int hexToBytes(const char *hex, uint8_t *out, size_t maxLen);

/* Test function declarations */
int testMd5Basic(void);
int testMd5Update(void);
int testMd5Large(void);

int testSha256Basic(void);
int testSha256Update(void);
int testSha256Large(void);

int testWhirlpoolBasic(void);
int testWhirlpoolUpdate(void);
int testWhirlpoolLarge(void);

/* AES tests */

/* 128 */
int testAes128Ecb(void);
int testAes128Cbc(void);
int testAes128Cfb(void);
int testAes128Cfb8(void);
int testAes128Cfb1(void);
int testAes128Ofb(void);
int testAes128Ctr(void);
int testAes128Gcm(void);
int testAes128Pcbc(void);

/* DES tests */
int testDesEcb(void);
int testDesCbc(void);
int testDesMultiBlock(void);
int testDesCfb(void);
int testDesCfb8(void);
int testDesCfb1(void);
int testDesOfb(void);
int testDesCtr(void);
int testDesPcbc(void);

/* 3DES tests */
int testDes3Ecb(void);
int testDes3Cbc(void);

/* Blowfish tests */
int testBlowfishEcb(void);
int testBlowfishCbc(void);
int testBlowfishCfb(void);
int testBlowfishCfb8(void);
int testBlowfishCfb1(void);
int testBlowfishOfb(void);
int testBlowfishCtr(void);
int testBlowfishPcbc(void);

int testBase64(void);

/* BLAKE2b tests */
int testBlake2bUnkeyed(void);
int testBlake2bIncremental(void);
int testBlake2bKeyed(void);
int testBlake2bLong(void);

/* PBKDF2 tests */
int testPbkdf2Sha256(void);
int testPbkdf2Md5(void);
int testPbkdf2DeriveKeyIv(void);
int testPbkdf2EdgeCases(void);

/* Argon2 tests */
int testArgon2d(void);
int testArgon2i(void);
int testArgon2id(void);
int testArgon2idOneShot(void);
int testArgon2EncodeDecode(void);
int testArgon2Verify(void);
int testArgon2EdgeCases(void);

/* Bcrypt tests */
int testBcryptHash(void);
int testBcryptVerify(void);
int testBcryptGenSalt(void);
int testBcryptEdgeCases(void);
int testBcryptHashWithSaltStr(void);

/* BigInt tests */
int testBigIntIsOddEven(void);
int testBigIntAdd(void);
int testBigIntSub(void);
int testBigIntMul(void);
int testBigIntDivMod(void);
int testModularArithmetic(void);

#endif /* HAJCRYPT_TEST_H */
