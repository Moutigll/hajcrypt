#include "../../hajlib/include/hmemory.h"
#include "../../hajlib/include/hprintf.h"

#include "../../includes/cipher/aes.h"
#include "../test.h"
#include <stdio.h>

/* ============================================================================
 * AES-128 Test Vectors
 * ============================================================================ */

static const struct {
	const char	*key;
	const char	*plaintext;
	const char	*ciphertext;
} aes128EcbVectors[] = {
	{
		"00000000000000000000000000000000",
		"00000000000000000000000000000000",
		"66e94bd4ef8a2c3b884cfa59ca342b2e"
	},
	{
		"ffffffffffffffffffffffffffffffff",
		"00000000000000000000000000000000",
		"a1f6258c877d5fcd8964484538bfc92c"
	},
	{
		"00112233445566778899aabbccddeeff",
		"000102030405060708090a0b0c0d0e0f",
		"279fb74a7572135e8f9b8ef6d1eee003"
	},
	{
		"2b7e151628aed2a6abf7158809cf4f3c",
		"6bc1bee22e409f96e93d7e117393172a",
		"3ad77bb40d7a3660a89ecaf32466ef97"
	},
	{
		"000102030405060708090a0b0c0d0e0f",
		"00112233445566778899aabbccddeeff",
		"69c4e0d86a7b0430d8cdb78070b4c55a"
	},
	{ NULL, NULL, NULL }
};

static const struct {
	const char	*key;
	const char	*iv;
	const char	*plaintext;
	const char	*ciphertext;
} aes128CbcVectors[] = {
	{
		"00000000000000000000000000000000",
		"00000000000000000000000000000000",
		"00000000000000000000000000000000",
		"66e94bd4ef8a2c3b884cfa59ca342b2e"
	},
	{
		"ffffffffffffffffffffffffffffffff",
		"00000000000000000000000000000000",
		"00000000000000000000000000000000",
		"a1f6258c877d5fcd8964484538bfc92c"
	},
	{
		"00112233445566778899aabbccddeeff",
		"102030405060708090a0b0c0d0e0f001",
		"000102030405060708090a0b0c0d0e0f",
		"854f06d0f45a50b6a1081e819820a86c"
	},
	{
		"2b7e151628aed2a6abf7158809cf4f3c",
		"000102030405060708090a0b0c0d0e0f",
		"6bc1bee22e409f96e93d7e117393172a",
		"7649abac8119b246cee98e9b12e9197d"
	},
	{
		"000102030405060708090a0b0c0d0e0f",
		"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
		"00112233445566778899aabbccddeeff",
		"7702fc9b71c63d26a2f09df5c445102a"
	},
	{ NULL, NULL, NULL, NULL }
};

static const struct {
	const char	*key;
	const char	*iv;
	const char	*plaintext;
	const char	*ciphertext;
} aes128CfbVectors[] = {
	{
		"00000000000000000000000000000000",
		"00000000000000000000000000000000",
		"00000000000000000000000000000000",
		"66e94bd4ef8a2c3b884cfa59ca342b2e"
	},
	{
		"ffffffffffffffffffffffffffffffff",
		"00000000000000000000000000000000",
		"00000000000000000000000000000000",
		"a1f6258c877d5fcd8964484538bfc92c"
	},
	{
		"00112233445566778899aabbccddeeff",
		"102030405060708090a0b0c0d0e0f001",
		"000102030405060708090a0b0c0d0e0f",
		"b4c7efcc8622c13c5edea1b61633bf40"
	},
	{
		"2b7e151628aed2a6abf7158809cf4f3c",
		"000102030405060708090a0b0c0d0e0f",
		"6bc1bee22e409f96e93d7e117393172a",
		"3b3fd92eb72dad20333449f8e83cfb4a"
	},
	{
		"000102030405060708090a0b0c0d0e0f",
		"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
		"00112233445566778899aabbccddeeff",
		"66b6e5db7007573f1fc874bcffcb4352"
	},
	{ NULL, NULL, NULL, NULL }
};

static const struct {
	const char	*key;
	const char	*iv;
	const char	*plaintext;
	const char	*ciphertext;
} aes128Cfb8Vectors[] = {
	{
		"00000000000000000000000000000000",
		"00000000000000000000000000000000",
		"00000000000000000000000000000000",
		"6616f92e42a8f11a911668578ec3aa0f"
	},
	{
		"ffffffffffffffffffffffffffffffff",
		"00000000000000000000000000000000",
		"00000000000000000000000000000000",
		"a143afec3e68c65f691408c3e74314fc"
	},
	{
		"00112233445566778899aabbccddeeff",
		"102030405060708090a0b0c0d0e0f001",
		"000102030405060708090a0b0c0d0e0f",
		"b4c1cf3f4396094e1b6348a4ed3bedd4"
	},
	{
		"2b7e151628aed2a6abf7158809cf4f3c",
		"000102030405060708090a0b0c0d0e0f",
		"6bc1bee22e409f96e93d7e117393172a",
		"3b79424c9c0dd436bace9e0ed4586a4f"
	},
	{
		"000102030405060708090a0b0c0d0e0f",
		"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
		"00112233445566778899aabbccddeeff",
		"66ae2b061cce426197cbc31e1b871f0f"
	},
	{ NULL, NULL, NULL, NULL }
};

static const struct {
	const char	*key;
	const char	*iv;
	const char	*plaintext;
	const char	*ciphertext;
} aes128Cfb1Vectors[] = {
	{
		"00000000000000000000000000000000",
		"00000000000000000000000000000000",
		"00000000000000000000000000000000",
		"00000000000000000000000000000000"
	},
	{
		"ffffffffffffffffffffffffffffffff",
		"00000000000000000000000000000000",
		"00000000000000000000000000000000",
		"8d5e997f9d3996a5715f706d4adb2376"
	},
	{
		"00112233445566778899aabbccddeeff",
		"102030405060708090a0b0c0d0e0f001",
		"000102030405060708090a0b0c0d0e0f",
		"c1d415e7da6e162034666e5f615d6398"
	},
	{
		"2b7e151628aed2a6abf7158809cf4f3c",
		"000102030405060708090a0b0c0d0e0f",
		"6bc1bee22e409f96e93d7e117393172a",
		"68b3a264f838f5f8c3101070d1ab4c2e"
	},
	{
		"000102030405060708090a0b0c0d0e0f",
		"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
		"00112233445566778899aabbccddeeff",
		"11dc67e8b6a334abbd630e1da4cedcc4"
	},
	{ NULL, NULL, NULL, NULL }
};

static const struct {
	const char	*key;
	const char	*iv;
	const char	*plaintext;
	const char	*ciphertext;
} aes128OfbVectors[] = {
	{
		"00000000000000000000000000000000",
		"00000000000000000000000000000000",
		"00000000000000000000000000000000",
		"66e94bd4ef8a2c3b884cfa59ca342b2e"
	},
	{
		"ffffffffffffffffffffffffffffffff",
		"00000000000000000000000000000000",
		"00000000000000000000000000000000",
		"a1f6258c877d5fcd8964484538bfc92c"
	},
	{
		"00112233445566778899aabbccddeeff",
		"102030405060708090a0b0c0d0e0f001",
		"000102030405060708090a0b0c0d0e0f",
		"b4c7efcc8622c13c5edea1b61633bf40"
	},
	{
		"2b7e151628aed2a6abf7158809cf4f3c",
		"000102030405060708090a0b0c0d0e0f",
		"6bc1bee22e409f96e93d7e117393172a",
		"3b3fd92eb72dad20333449f8e83cfb4a"
	},
	{
		"000102030405060708090a0b0c0d0e0f",
		"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
		"00112233445566778899aabbccddeeff",
		"66b6e5db7007573f1fc874bcffcb4352"
	},
	{ NULL, NULL, NULL, NULL }
};

static const struct {
	const char	*key;
	const char	*iv;
	const char	*plaintext;
	const char	*ciphertext;
} aes128CtrVectors[] = {
	{
		"00000000000000000000000000000000",
		"00000000000000000000000000000000",
		"00000000000000000000000000000000",
		"66e94bd4ef8a2c3b884cfa59ca342b2e"
	},
	{
		"ffffffffffffffffffffffffffffffff",
		"00000000000000000000000000000000",
		"00000000000000000000000000000000",
		"a1f6258c877d5fcd8964484538bfc92c"
	},
	{
		"00112233445566778899aabbccddeeff",
		"102030405060708090a0b0c0d0e0f001",
		"000102030405060708090a0b0c0d0e0f",
		"b4c7efcc8622c13c5edea1b61633bf40"
	},
	{
		"2b7e151628aed2a6abf7158809cf4f3c",
		"000102030405060708090a0b0c0d0e0f",
		"6bc1bee22e409f96e93d7e117393172a",
		"3b3fd92eb72dad20333449f8e83cfb4a"
	},
	{
		"000102030405060708090a0b0c0d0e0f",
		"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
		"00112233445566778899aabbccddeeff",
		"66b6e5db7007573f1fc874bcffcb4352"
	},
	{ NULL, NULL, NULL, NULL }
};

static const struct {
	const char  *key;
	const char  *iv;
	const char  *plaintext;
	const char  *ciphertext;
} aes128PcbcVectors[] = {
	{
		"00000000000000000000000000000000",
		"00000000000000000000000000000000",
		"00000000000000000000000000000000",
		"66e94bd4ef8a2c3b884cfa59ca342b2e9434dec2d00fdac765f00c0c11628cd1" },
	{
		"ffffffffffffffffffffffffffffffff",
		"ffffffffffffffffffffffffffffffff",
		"ffffffffffffffffffffffffffffffff",
		"a1f6258c877d5fcd8964484538bfc92ce596b54192331d3f879c1d0bc3d2b3d0" },
	{
		"2b7e151628aed2a6abf7158809cf4f3c",
		"000102030405060708090a0b0c0d0e0f",
		"6bc1bee22e409f96e93d7e117393172a",
		"7649abac8119b246cee98e9b12e9197d0f5ea4709d2393720bb889134796b04c" },
	{
		"000102030405060708090a0b0c0d0e0f",
		"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
		"00112233445566778899aabbccddeeff",
		"7702fc9b71c63d26a2f09df5c445102a333c7a7fc94478f5cfdf0b2f3e0e55f2" },
	{
		"1bb46016387910bc4d32362b1a22345a",
		"6e2e585257994eb75f970956a771e7c3",
		"b7bfe43dd428a4f86af7a3380d02d00e",
		"6be36ecca4903513dac236c38d81ee745a9785e1bb2c1ee80ee2ea88bf761676" },
	{ NULL, NULL, NULL, NULL }
};

static const struct {
	const char  *key;
	const char  *iv;
	const char  *aad;
	const char  *plaintext;
	const char  *ciphertext;
	const char  *tag;
} aes128GcmVectors[] = {
{
		"ae7042f562e3c0852b0ec6dfe1d77626",
		"d24c0a18a82895e2b37c43d5",
		"cfb77d57987ab8b5",
		"637968b82d01d3a2f7a2ff4b169165a2d1bf8c6cb9b7ae127b0ab5898138e058",
		"8f6865c0816ef66af2b8ed25d4412a96d68b43c980a1bafadf26f192213062a0",
		"d955a45f0ae36e3127d995501be07fec"
	},
	{
		"75b610caeb4d2735853eca83e8351a53",
		"a86e3e5df3d11cc8dea1339d",
		"731c3c3e9d034a9d",
		"99d656348eaa373f99c6ca714366d1a3cbc39e61a33e5f51792a5db5da2292da",
		"7e656d4a2549c79c349d56c03b46b0b2b9c23a1e8a968caa3734003bf705e6bb",
		"12be0b342c22f82caf8c79de7ff273f6"
	},
	{
		"49b3c78c7b22a16c2585b5a4c6803c2e",
		"1b14576f5c0c09edc09f1659",
		"99ddbbd8eb3ce49c",
		"550b2ebf89f7587eddb81911ce3dc85d537ee10310703a002c5e43eada2da30c",
		"a612cf6c3fd2ecc0e92e0f20f80027dd8e676f11679ad86546f83f679636bfd9",
		"ad6f31ed88eb3e45c4c11d65cf9dbd86"
	},
	{
		"032afb84cc927bd52ba37e94aacb86e2",
		"63acadaeccc81e27a0e01d72",
		"61631c53ca2a1259",
		"ac02c70a5c86319a1fa56855fad6b01584a9d2174472c91973302b13e4d789bc",
		"6e26a372d7895bf6be3214655705b7ad34fc3a9909b3c54c9fb1ae6c96680f4c",
		"81cb1db9d851f39045ebf3306328dd7f"
	},
	{
		"a78b61e0938d71cf9a7f5344aebf893a",
		"83d3c31bc87e1948ec17d2b0",
		"799a9befd52ac4ee",
		"b69858c7541925ec08cef6a3899c46cfca48f96f71d39174a3abc3c78c78bf25",
		"12f6f36362a6a16d438868420930e70fbbd4b6843c6521eb6024b77f28c879e8",
		"375c97af01132f092d7bda013ead9361"
	},
	{ NULL, NULL, NULL, NULL, NULL, NULL }
};

/* --------------- Test Functions for Each Mode --------------- */

/* ----------------------------------------------------------------------------
 * ECB Mode Tests
 * -------------------------------------------------------------------------- */
int testAes128Ecb(void) {
	int passed = 0;
	int total = 0;
	printInfo("Testing AES-128-ECB...");

	for (int i = 0; aes128EcbVectors[i].key != NULL; i++) {
		uint8_t		key[16], plain[16], cipher[16];
		uint8_t		result[32] = {0};  /* larger than needed */
		t_aesEcbCtx	ctx;
		size_t		outLen, written;

		hexToBytes(aes128EcbVectors[i].key, key, 16);
		hexToBytes(aes128EcbVectors[i].plaintext, plain, 16);
		hexToBytes(aes128EcbVectors[i].ciphertext, cipher, 16);

		/* Encryption */
		ft_memset(result, 0, sizeof(result));
		aesEcbInit(&ctx, key, 16, NULL, CIPHER_ENCRYPT);
		aesEcbUpdate(&ctx, plain, 16, result, &written);
		outLen = written;
		aesEcbFinal(&ctx, result + outLen, &written);
		outLen += written;
		if (ft_memcmp(cipher, result, 16) == 0) {
			passed++; printSuccess("ECB encrypt vector");
		} else {
			printFailure("ECB encrypt vector");
			hexDump(result, 16);
		}
		total++;

		/* Decryption */
		ft_memset(result, 0, sizeof(result));
		aesEcbInit(&ctx, key, 16, NULL, CIPHER_DECRYPT);
		aesEcbUpdate(&ctx, cipher, 16, result, &written);
		outLen = written;
		aesEcbFinal(&ctx, result + outLen, &written);
		outLen += written;
		if (ft_memcmp(plain, result, 16) == 0) {
			passed++; printSuccess("ECB decrypt vector");
		} else
			printFailure("ECB decrypt vector");
		total++;

		/* Cleanup */
		aesEcbFree(&ctx);
		if (isZeroed(ctx.roundKeys, sizeof(ctx.roundKeys)) &&
			isZeroed(ctx.buffer, sizeof(ctx.buffer))) {
			passed++; printSuccess("ECB context cleared");
		} else
			printFailure("ECB context not cleared");
		total++;
	}
	ft_printf("AES-128-ECB: %d/%d passed\n", passed, total);
	g_totalTests += total;
	g_passedTests += passed;
	return (passed == total);
}

/* ----------------------------------------------------------------------------
 * CBC Mode Tests
 * -------------------------------------------------------------------------- */
int testAes128Cbc(void) {
	int passed = 0, total = 0;
	printInfo("Testing AES-128-CBC...");

	for (int i = 0; aes128CbcVectors[i].key != NULL; i++) {
		uint8_t		key[16], iv[16], plain[16], cipher[16];
		uint8_t		result[32] = {0};
		t_aesCbcCtx	ctx;
		size_t		written, outLen;

		hexToBytes(aes128CbcVectors[i].key, key, 16);
		hexToBytes(aes128CbcVectors[i].iv, iv, 16);
		hexToBytes(aes128CbcVectors[i].plaintext, plain, 16);
		hexToBytes(aes128CbcVectors[i].ciphertext, cipher, 16);

		/* Encryption */
		ft_memset(result, 0, sizeof(result));
		aesCbcInit(&ctx, key, 16, iv, CIPHER_ENCRYPT);
		aesCbcUpdate(&ctx, plain, 16, result, &written);
		outLen = written;
		aesCbcFinal(&ctx, result + outLen, &written);
		outLen += written;
		if (ft_memcmp(cipher, result, 16) == 0) {
			passed++; printSuccess("CBC encrypt vector");
		} else
			printFailure("CBC encrypt vector");
		total++;

		/* Decryption */
		ft_memset(result, 0, sizeof(result));
		aesCbcInit(&ctx, key, 16, iv, CIPHER_DECRYPT);
		aesCbcUpdate(&ctx, cipher, 16, result, &written);
		outLen = written;
		aesCbcFinal(&ctx, result + outLen, &written);
		outLen += written;
		if (ft_memcmp(plain, result, 16) == 0) {
			passed++; printSuccess("CBC decrypt vector");
		} else
			printFailure("CBC decrypt vector");
		total++;

		/* Cleanup */
		aesCbcFree(&ctx);
		if (isZeroed(ctx.roundKeys, sizeof(ctx.roundKeys)) &&
			isZeroed(ctx.cbcCtx.iv, sizeof(ctx.cbcCtx.iv)) &&
			isZeroed(ctx.cbcCtx.buffer, sizeof(ctx.cbcCtx.buffer))) {
			passed++; printSuccess("CBC context cleared");
		} else
			printFailure("CBC context not cleared");
		total++;
	}
	ft_printf("AES-128-CBC: %d/%d passed\n", passed, total);
	g_totalTests += total;
	g_passedTests += passed;
	return (passed == total);
}

/* ----------------------------------------------------------------------------
 * CFB Mode (128-bit) Tests
 * -------------------------------------------------------------------------- */
int testAes128Cfb(void) {
	int passed = 0, total = 0;
	printInfo("Testing AES-128-CFB...");

	for (int i = 0; aes128CfbVectors[i].key != NULL; i++) {
		uint8_t		key[16], iv[16], plain[16], cipher[16];
		uint8_t		result[32] = {0};
		t_aesCfbCtx	ctx;
		size_t		written, outLen;

		hexToBytes(aes128CfbVectors[i].key, key, 16);
		hexToBytes(aes128CfbVectors[i].iv, iv, 16);
		hexToBytes(aes128CfbVectors[i].plaintext, plain, 16);
		hexToBytes(aes128CfbVectors[i].ciphertext, cipher, 16);

		/* Encryption */
		ft_memset(result, 0, sizeof(result));
		aesCfbInit(&ctx, key, 16, iv, CIPHER_ENCRYPT);
		aesCfbUpdate(&ctx, plain, 16, result, &written);
		outLen = written;
		aesCfbFinal(&ctx, result + outLen, &written);
		outLen += written;
		if (ft_memcmp(cipher, result, 16) == 0) {
			passed++; printSuccess("CFB encrypt vector");
		} else
			printFailure("CFB encrypt vector");
		total++;

		/* Decryption */
		ft_memset(result, 0, sizeof(result));
		aesCfbInit(&ctx, key, 16, iv, CIPHER_DECRYPT);
		aesCfbUpdate(&ctx, cipher, 16, result, &written);
		outLen = written;
		aesCfbFinal(&ctx, result + outLen, &written);
		outLen += written;
		if (ft_memcmp(plain, result, 16) == 0) {
			passed++; printSuccess("CFB decrypt vector");
		} else
			printFailure("CFB decrypt vector");
		total++;

		/* Cleanup */
		aesCfbFree(&ctx);
		if (isZeroed(ctx.roundKeys, sizeof(ctx.roundKeys)) &&
			isZeroed(ctx.cfbCtx.iv, sizeof(ctx.cfbCtx.iv)) &&
			isZeroed(ctx.cfbCtx.shiftRegister, sizeof(ctx.cfbCtx.shiftRegister)) &&
			isZeroed(ctx.cfbCtx.inputBuf, sizeof(ctx.cfbCtx.inputBuf))) {
			passed++; printSuccess("CFB context cleared");
		} else
			printFailure("CFB context not cleared");
		total++;
	}
	ft_printf("AES-128-CFB: %d/%d passed\n", passed, total);
	g_totalTests += total;
	g_passedTests += passed;
	return (passed == total);
}

/* ----------------------------------------------------------------------------
 * CFB8 Mode Tests
 * -------------------------------------------------------------------------- */
int testAes128Cfb8(void) {
	int passed = 0, total = 0;
	printInfo("Testing AES-128-CFB8...");

	for (int i = 0; aes128Cfb8Vectors[i].key != NULL; i++) {
		uint8_t		key[16], iv[16], plain[16], cipher[16];
		uint8_t		result[32] = {0};
		t_aesCfbCtx	ctx;
		size_t		plainLen, written, outLen;

		hexToBytes(aes128Cfb8Vectors[i].key, key, 16);
		hexToBytes(aes128Cfb8Vectors[i].iv, iv, 16);
		plainLen = hexToBytes(aes128Cfb8Vectors[i].plaintext, plain, 16);
		hexToBytes(aes128Cfb8Vectors[i].ciphertext, cipher, 16);

		/* Encryption */
		ft_memset(result, 0, sizeof(result));
		aesCfb8Init(&ctx, key, 16, iv, CIPHER_ENCRYPT);
		aesCfbUpdate(&ctx, plain, plainLen, result, &written);
		outLen = written;
		aesCfbFinal(&ctx, result + outLen, &written);
		outLen += written;
		if (ft_memcmp(cipher, result, plainLen) == 0) {
			passed++; printSuccess("CFB8 encrypt vector");
		} else
			printFailure("CFB8 encrypt vector");
		total++;

		/* Decryption */
		ft_memset(result, 0, sizeof(result));
		aesCfb8Init(&ctx, key, 16, iv, CIPHER_DECRYPT);
		aesCfbUpdate(&ctx, cipher, plainLen, result, &written);
		outLen = written;
		aesCfbFinal(&ctx, result + outLen, &written);
		outLen += written;
		if (ft_memcmp(plain, result, plainLen) == 0) {
			passed++; printSuccess("CFB8 decrypt vector");
		} else
			printFailure("CFB8 decrypt vector");
		total++;

		/* Cleanup */
		aesCfbFree(&ctx);
		if (isZeroed(ctx.roundKeys, sizeof(ctx.roundKeys)) &&
			isZeroed(ctx.cfbCtx.iv, sizeof(ctx.cfbCtx.iv)) &&
			isZeroed(ctx.cfbCtx.shiftRegister, sizeof(ctx.cfbCtx.shiftRegister)) &&
			isZeroed(ctx.cfbCtx.inputBuf, sizeof(ctx.cfbCtx.inputBuf))) {
			passed++; printSuccess("CFB8 context cleared");
		} else
			printFailure("CFB8 context not cleared");
		total++;
	}
	ft_printf("AES-128-CFB8: %d/%d passed\n", passed, total);
	g_totalTests += total;
	g_passedTests += passed;
	return (passed == total);
}

/* ----------------------------------------------------------------------------
 * CFB1 Mode Tests (bit‑oriented)
 * -------------------------------------------------------------------------- */
int testAes128Cfb1(void) {
	int passed = 0, total = 0;
	printInfo("Testing AES-128-CFB1...");

	for (int i = 0; aes128Cfb1Vectors[i].key != NULL; i++) {
		uint8_t		key[16], iv[16], plain[16], cipher[16];
		uint8_t		result[32] = {0};
		t_aesCfbCtx	ctx;
		size_t		plainLen = 16;		  /* all vectors are 16 bytes */
		size_t		outLen = 0, writtenLen;

		hexToBytes(aes128Cfb1Vectors[i].key, key, 16);
		hexToBytes(aes128Cfb1Vectors[i].iv, iv, 16);
		hexToBytes(aes128Cfb1Vectors[i].plaintext, plain, 16);
		hexToBytes(aes128Cfb1Vectors[i].ciphertext, cipher, 16);

		/* Encryption - now passing bytes */
		ft_memset(result, 0, sizeof(result));
		aesCfb1Init(&ctx, key, 16, iv, CIPHER_ENCRYPT);
		aesCfb1Update(&ctx, plain, plainLen, result, &writtenLen);  // plainLen bytes, not bits!
		outLen = writtenLen;
		aesCfb1Final(&ctx, result + outLen, &writtenLen);
		outLen += writtenLen;
		if (outLen == plainLen && (ft_memcmp(cipher, result, plainLen) == 0)) {
			passed++; printSuccess("CFB1 encrypt vector");
		} else {
			printFailure("CFB1 encrypt vector");
			hexDump(result, plainLen);
		}
		total++;

		/* Decryption - passing bytes */
		ft_memset(result, 0, sizeof(result));
		aesCfb1Init(&ctx, key, 16, iv, CIPHER_DECRYPT);
		aesCfb1Update(&ctx, cipher, plainLen, result, &writtenLen);  // plainLen bytes
		outLen = writtenLen;
		aesCfb1Final(&ctx, result + outLen, &writtenLen);
		outLen += writtenLen;
		if (outLen == plainLen && (ft_memcmp(plain, result, plainLen) == 0)) {
			passed++; printSuccess("CFB1 decrypt vector");
		} else
			printFailure("CFB1 decrypt vector");
		total++;

		/* Cleanup */
		aesCfbFree(&ctx);
		if (isZeroed(ctx.roundKeys, sizeof(ctx.roundKeys)) &&
			isZeroed(ctx.cfbCtx.iv, sizeof(ctx.cfbCtx.iv)) &&
			isZeroed(ctx.cfbCtx.shiftRegister, sizeof(ctx.cfbCtx.shiftRegister)) &&
			isZeroed(ctx.cfbCtx.inputBuf, sizeof(ctx.cfbCtx.inputBuf))) {
			passed++; printSuccess("CFB1 context cleared");
		} else
			printFailure("CFB1 context not cleared");
		total++;
	}
	ft_printf("AES-128-CFB1: %d/%d passed\n", passed, total);
	g_totalTests += total;
	g_passedTests += passed;
	return (passed == total);
}

/* ----------------------------------------------------------------------------
 * CTR Mode Tests
 * -------------------------------------------------------------------------- */
int testAes128Ctr(void) {
	int passed = 0, total = 0;
	printInfo("Testing AES-128-CTR...");

	for (int i = 0; aes128CtrVectors[i].key != NULL; i++) {
		uint8_t		key[16], iv[16], plain[16], cipher[16];
		uint8_t		result[32] = {0};
		t_aesCtrCtx	ctx;
		size_t		plainLen, written, outLen;

		hexToBytes(aes128CtrVectors[i].key, key, 16);
		hexToBytes(aes128CtrVectors[i].iv, iv, 16);
		plainLen = hexToBytes(aes128CtrVectors[i].plaintext, plain, 16);
		hexToBytes(aes128CtrVectors[i].ciphertext, cipher, 16);

		/* Encryption */
		ft_memset(result, 0, sizeof(result));
		aesCtrInit(&ctx, key, 16, iv, CIPHER_ENCRYPT);
		aesCtrUpdate(&ctx, plain, plainLen, result, &written);
		outLen = written;
		aesCtrFinal(&ctx, result + outLen, &written);
		outLen += written;
		if (ft_memcmp(cipher, result, plainLen) == 0) {
			passed++; printSuccess("CTR encrypt vector");
		} else
			printFailure("CTR encrypt vector");
		total++;

		/* Decryption */
		ft_memset(result, 0, sizeof(result));
		aesCtrInit(&ctx, key, 16, iv, CIPHER_DECRYPT);
		aesCtrUpdate(&ctx, cipher, plainLen, result, &written);
		outLen = written;
		aesCtrFinal(&ctx, result + outLen, &written);
		outLen += written;
		if (ft_memcmp(plain, result, plainLen) == 0) {
			passed++; printSuccess("CTR decrypt vector");
		} else
			printFailure("CTR decrypt vector");
		total++;

		/* Cleanup */
		aesCtrFree(&ctx);
		if (isZeroed(ctx.roundKeys, sizeof(ctx.roundKeys)) &&
			isZeroed(ctx.ctrCtx.iv, sizeof(ctx.ctrCtx.iv)) &&
			isZeroed(ctx.ctrCtx.counter, sizeof(ctx.ctrCtx.counter)) &&
			isZeroed(ctx.ctrCtx.keystream, sizeof(ctx.ctrCtx.keystream))) {
			passed++; printSuccess("CTR context cleared");
		} else
			printFailure("CTR context not cleared");
		total++;
	}
	ft_printf("AES-128-CTR: %d/%d passed\n", passed, total);
	g_totalTests += total;
	g_passedTests += passed;
	return (passed == total);
}

/* ----------------------------------------------------------------------------
 * OFB Mode Tests
 * -------------------------------------------------------------------------- */
int testAes128Ofb(void) {
	int passed = 0, total = 0;
	printInfo("Testing AES-128-OFB...");

	for (int i = 0; aes128OfbVectors[i].key != NULL; i++) {
		uint8_t key[16], iv[16], plain[16], cipher[16];
		uint8_t		result[32] = {0};
		t_aesOfbCtx	ctx;
		size_t		plainLen, written, outLen;

		hexToBytes(aes128OfbVectors[i].key, key, 16);
		hexToBytes(aes128OfbVectors[i].iv, iv, 16);
		plainLen = hexToBytes(aes128OfbVectors[i].plaintext, plain, 16);
		hexToBytes(aes128OfbVectors[i].ciphertext, cipher, 16);

		/* Encryption */
		ft_memset(result, 0, sizeof(result));
		aesOfbInit(&ctx, key, 16, iv, CIPHER_ENCRYPT);
		aesOfbUpdate(&ctx, plain, plainLen, result, &written);
		outLen = written;
		aesOfbFinal(&ctx, result + outLen, &written);
		outLen += written;
		if (ft_memcmp(cipher, result, plainLen) == 0) {
			passed++; printSuccess("OFB encrypt vector");
		} else
			printFailure("OFB encrypt vector");
		total++;

		/* Decryption */
		ft_memset(result, 0, sizeof(result));
		aesOfbInit(&ctx, key, 16, iv, CIPHER_DECRYPT);
		aesOfbUpdate(&ctx, cipher, plainLen, result, &written);
		outLen = written;
		aesOfbFinal(&ctx, result + outLen, &written);
		outLen += written;
		if (ft_memcmp(plain, result, plainLen) == 0) {
			passed++; printSuccess("OFB decrypt vector");
		} else
			printFailure("OFB decrypt vector");
		total++;

		/* Cleanup */
		aesOfbFree(&ctx);
		if (isZeroed(ctx.roundKeys, sizeof(ctx.roundKeys)) &&
			isZeroed(ctx.ofbCtx.iv, sizeof(ctx.ofbCtx.iv)) &&
			isZeroed(ctx.ofbCtx.keystream, sizeof(ctx.ofbCtx.keystream)) &&
			isZeroed(ctx.ofbCtx.inputBuf, sizeof(ctx.ofbCtx.inputBuf))) {
			passed++; printSuccess("OFB context cleared");
		} else
			printFailure("OFB context not cleared");
		total++;
	}
	ft_printf("AES-128-OFB: %d/%d passed\n", passed, total);
	g_totalTests += total;
	g_passedTests += passed;
	return (passed == total);
}

/* ----------------------------------------------------------------------------
 * PCBC Mode Tests
 * -------------------------------------------------------------------------- */
int testAes128Pcbc(void) {
	int passed = 0, total = 0;
	printInfo("Testing AES-128-PCBC multi-block (32 bytes)...");

	for (int i = 0; aes128PcbcVectors[i].key != NULL; i++) {
		uint8_t key[16], iv[16], plain[16], cipher[32];
		uint8_t result[64] = {0};
		t_aesPcbcCtx ctx;
		size_t written, outLen;

		hexToBytes(aes128PcbcVectors[i].key, key, 16);
		hexToBytes(aes128PcbcVectors[i].iv, iv, 16);
		hexToBytes(aes128PcbcVectors[i].plaintext, plain, 16);
		hexToBytes(aes128PcbcVectors[i].ciphertext, cipher, 32);

		/* ---------- Encryption ---------- */
		ft_memset(result, 0, sizeof(result));
		aesPcbcInit(&ctx, key, 16, iv, CIPHER_ENCRYPT);
		aesPcbcUpdate(&ctx, plain, 16, result, &written);
		outLen = written;
		aesPcbcFinal(&ctx, result + outLen, &written);
		outLen += written;

		if (outLen == 32 && ft_memcmp(cipher, result, 32) == 0) {
			passed++; printSuccess("PCBC multi-block encrypt vector");
		} else {
			printFailure("PCBC multi-block encrypt vector");
			ft_printf("Expected: "); hexDump(cipher, 32);
			ft_printf("Got:	  "); hexDump(result, outLen);
		}
		total++;
		aesPcbcFree(&ctx);

		/* ---------- Decryption ---------- */
		ft_memset(result, 0, sizeof(result));
		aesPcbcInit(&ctx, key, 16, iv, CIPHER_DECRYPT);

		aesPcbcUpdate(&ctx, cipher, 16, result, &written);
		outLen = written;
		aesPcbcFinal(&ctx, result + outLen, &written);
		outLen += written;

		if (outLen == 16 && ft_memcmp(plain, result, 16) == 0) {
			passed++; printSuccess("PCBC multi-block decrypt vector");
		} else {
			printFailure("PCBC multi-block decrypt vector");
			ft_printf("Expected: "); hexDump(plain, 16);
			ft_printf("Got:	  "); hexDump(result, outLen);
		}
		total++;

		/* ---------- Context cleanup ---------- */
		aesPcbcFree(&ctx);
		if (isZeroed(ctx.roundKeys, sizeof(ctx.roundKeys)) &&
			isZeroed(ctx.pcbcCtx.iv, sizeof(ctx.pcbcCtx.iv)) &&
			isZeroed(ctx.pcbcCtx.prevPlain, sizeof(ctx.pcbcCtx.prevPlain)) &&
			isZeroed(ctx.pcbcCtx.buffer, sizeof(ctx.pcbcCtx.buffer))) {
			passed++; printSuccess("PCBC context cleared");
		} else
			printFailure("PCBC context not cleared");
		total++;
	}
	ft_printf("AES-128-PCBC multi-block: %d/%d passed\n", passed, total);
	g_totalTests += total;
	g_passedTests += passed;
	return (passed == total);
}

/* ----------------------------------------------------------------------------
 * GCM Mode Tests
 * -------------------------------------------------------------------------- */
int testAes128Gcm(void) {
	int passed = 0, total = 0;
	printInfo("Testing AES-128-GCM...");

	for (int i = 0; aes128GcmVectors[i].key != NULL; i++) {
		uint8_t		key[16], iv[64], aad[128], plain[128], cipher[128], expectedTag[16];
		uint8_t		result[256] = {0}; 
		t_aesGcmCtx	ctx;
		size_t		ivLen, aadLen, plainLen, tagLen, written, outLen;

		hexToBytes(aes128GcmVectors[i].key, key, 16);
		ivLen = hexToBytes(aes128GcmVectors[i].iv, iv, sizeof(iv));
		aadLen = hexToBytes(aes128GcmVectors[i].aad, aad, sizeof(aad));
		plainLen = hexToBytes(aes128GcmVectors[i].plaintext, plain, sizeof(plain));
		hexToBytes(aes128GcmVectors[i].ciphertext, cipher, sizeof(cipher));
		tagLen = hexToBytes(aes128GcmVectors[i].tag, expectedTag, sizeof(expectedTag));

		/* Encryption */
		ft_memset(result, 0, sizeof(result));
		aesGcmInit(&ctx, key, 16, iv, ivLen, CIPHER_ENCRYPT);
		
		if (aadLen > 0)
			aesGcmUpdateAAD(&ctx, aad, aadLen);

		if (plainLen > 0)
			aesGcmUpdate(&ctx, plain, plainLen, result, &written);
		else
			written = 0;

		outLen = written;

		aesGcmFinal(&ctx, result + outLen, &written);
		outLen += written;
		
		int encOk = 1;
		if (plainLen > 0 && ft_memcmp(cipher, result, plainLen) != 0)
			encOk = 0;

		if (outLen >= plainLen + 16) {
			if (ft_memcmp(expectedTag, result + plainLen, 16) != 0)
				encOk = 0;
		}

		if (encOk) {
			passed++;
			printSuccess("GCM encrypt vector");
		} else
			printFailure("GCM encrypt vector");
		total++;

		/* Decryption & Authentification */
		ft_memset(result, 0, sizeof(result));
		aesGcmInit(&ctx, key, 16, iv, ivLen, CIPHER_DECRYPT);
		
		if (aadLen > 0) {
			aesGcmUpdateAAD(&ctx, aad, aadLen);
		}
		
		if (plainLen > 0)
			aesGcmUpdate(&ctx, cipher, plainLen, result, &written);
		else
			written = 0;
		outLen = written;
		
		aesGcmFinal(&ctx, result + outLen, &written);
		outLen += written;

		int isTagValid = aesGcmVerifyTag(&ctx, expectedTag, tagLen);

		int decOk = 1;
		if (plainLen > 0 && ft_memcmp(plain, result, plainLen) != 0) decOk = 0;
		if (!isTagValid) decOk = 0;

		if (decOk) {
			passed++;
			printSuccess("GCM decrypt & Auth verify vector");
		} else
			printFailure("GCM decrypt & Auth verify vector");
		total++;

		/* Cleanup */
		aesGcmFree(&ctx);
		passed++; printSuccess("GCM context cleared");
		total++;
	}
	
	ft_printf("AES-128-GCM: %d/%d passed\n", passed, total);
	g_totalTests += total;
	g_passedTests += passed;
	return (passed == total);
}
