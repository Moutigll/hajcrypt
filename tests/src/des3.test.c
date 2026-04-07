#include "../../hajlib/include/hmemory.h"
#include "../../hajlib/include/hprintf.h"

#include "../../includes/cipher/des3.h"
#include "../test.h"

/* 3DES Ecb Test Vectors (10 vectors) */
static const struct {
	const char	*key;
	const char	*plaintext;
	const char	*ciphertext;
} des3EcbVectors[] = {
	{
		"b585b9ec2ad002d298a456dd6a6e0c1d7bb58c90d7b05191",
		"0000000000000000",
		"46657bdaac78cbeace0bbaf3623cf413"
	},
	{
		"6dc79c7ea6d61d4d81c4848aee8ce49b64d7640d14aab7e8",
		"ffffffffffffffff",
		"fa5b708859e7ba385c54da414de16ef7"
	},
	{
		"0118f98facaf70d98e9272ef4ac72354fff0fe4c4b5bc47f",
		"0101010101010101",
		"2c73dde3e830440acf27dfaef7e0fc6c"
	},
	{
		"0123456789abcdeffedcba98765432100011223344556677",
		"0123456789abcdef",
		"372c1d08a4f057ba538a86fcaffb9a6a"
	},
	{
		"104691348998013120169134899801323016913489980133",
		"0000000000000000",
		"7fdb1607adac5b252a937ec49c61d404"
	},
	{
		"800000000000000040000000000000002000000000000000",
		"8000000000000000",
		"e320f41200d9e7822476fae67f10914a"
	},
	{
		"0e329232ea6d0d731e329232ea6d0d742e329232ea6d0d75",
		"8787878787878787",
		"4c20e11f88fc6e093dd19f04f392267b"
	},
	{
		"aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbcccccccccccccccc",
		"aaaaaaaaaaaaaaaa",
		"c3f16bf4fd61f151a3652eb69e8ef526"
	},
	{
		"1bb46016387910bc4d32362b1a22345a6e2e585257994eb7",
		"b7bfe43dd428a4f8",
		"6c9a1f90f90518400de47a1cd50b3c36"
	},
	{
		"ffffffffffffffff0000000000000000fffffffffffffffe",
		"0001020304050607",
		"3d75d6321d212111c93c00e7c3515cb2"
	},
	{ NULL, NULL, NULL }
};


/* 3DES Cbc Test Vectors (10 vectors) */
static const struct {
	const char	*key;		/* 24 bytes (48 hex chars) */
	const char	*iv;		/* 8 bytes (16 hex chars) */
	const char	*plaintext;	/* 8 bytes (16 hex chars) */
	const char	*ciphertext;	/* 16 bytes (32 hex chars) - includes padding */
} des3CbcVectors[] = {
	{
		"18426ee368a6e5400842f13a48e92ed488238a6ad31fa8b1",
		"0000000000000000",
		"0000000000000000",
		"edf15c9a7217518a7fb007345bc7f9e8"
	},
	{
		"2d61b8c326b99d1dfa9883411c581cdc5c3665334f897b52",
		"0000000000000000",
		"ffffffffffffffff",
		"80d790266c8fd683a8bb751567c994ee"
	},
	{
		"d12173faee36531017a0ce844e43f80b793b2294ef398c66",
		"1234567890abcdef",
		"0101010101010101",
		"f8d8642301dfb48a9d8819f584c75a56"
	},
	{
		"0123456789abcdeffedcba98765432100011223344556677",
		"fedcba9876543210",
		"0123456789abcdef",
		"8107de90011c63b2b494dcdc94840a8d"
	},
	{
		"104691348998013120169134899801323016913489980133",
		"0000000000000000",
		"0000000000000000",
		"7fdb1607adac5b253bdc687a99d4ab5d"
	},
	{
		"800000000000000040000000000000002000000000000000",
		"8000000000000000",
		"8000000000000000",
		"ee6be145771e48a933c8a31ed92a248f"
	},
	{
		"0e329232ea6d0d731e329232ea6d0d742e329232ea6d0d75",
		"8787878787878787",
		"8787878787878787",
		"db3d8207eb1a6c12e66f03d1f9e85ca6"
	},
	{
		"aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbcccccccccccccccc",
		"aaaaaaaaaaaaaaaa",
		"aaaaaaaaaaaaaaaa",
		"4c3cdda1d833151878cc1d9e2a95358a"
	},
	{
		"1bb46016387910bc4d32362b1a22345a6e2e585257994eb7",
		"6e2e585257994eb7",
		"b7bfe43dd428a4f8",
		"9cb979578bfa25e3822d8020e784bc7f"
	},
	{
		"ffffffffffffffff0000000000000000fffffffffffffffe",
		"0001020304050607",
		"0001020304050607",
		"3e680aa78b75df180a66ce54a72f714e"
	},
	{ NULL, NULL, NULL, NULL }
};


/* ---------- 3DES ECB Test ---------- */
int testDes3Ecb(void) {
	int passed = 0, total = 0;
	printInfo("Testing 3DES-ECB...");

	for (int i = 0; des3EcbVectors[i].key != NULL; i++) {
		uint8_t			key[24], plain[8], cipher[16];
		uint8_t			result[32] = {0};
		t_des3EcbCtx	ctx;
		size_t			outLen, written;

		hexToBytes(des3EcbVectors[i].key, key, 24);
		hexToBytes(des3EcbVectors[i].plaintext, plain, 8);
		hexToBytes(des3EcbVectors[i].ciphertext, cipher, 16);

		/* ---------- Encryption ---------- */
		ft_memset(result, 0, sizeof(result));
		des3EcbInit(&ctx, key, 24, NULL, CIPHER_ENCRYPT);
		des3EcbUpdate(&ctx, plain, 8, result, &written);
		outLen = written;
		des3EcbFinal(&ctx, result + outLen, &written);
		outLen += written;
		if (outLen == 16 && ft_memcmp(cipher, result, 16) == 0) {
			passed++; printSuccess("3DES ECB encrypt vector");
		} else {
			printFailure("3DES ECB encrypt vector");
			ft_printf("Expected: "); hexDump(cipher, 16);
			ft_printf("Got:	  "); hexDump(result, outLen);
		}
		total++;
		des3EcbFree(&ctx);

		/* ---------- Decryption ---------- */
		ft_memset(result, 0, sizeof(result));
		des3EcbInit(&ctx, key, 24, NULL, CIPHER_DECRYPT);
		
		/* Pass first block (8 bytes) to update */
		des3EcbUpdate(&ctx, cipher, 8, result, &written);
		outLen = written;
		/* Pass second block (8 bytes) to final (which will unpad) */
		des3EcbFinal(&ctx, result + outLen, &written);
		outLen += written;
		
		if (outLen == 8 && ft_memcmp(plain, result, 8) == 0) {
			passed++; printSuccess("3DES ECB decrypt vector");
		} else {
			printFailure("3DES ECB decrypt vector");
			ft_printf("Expected: "); hexDump(plain, 8);
			ft_printf("Got:	  "); hexDump(result, outLen);
		}
		total++;

		/* Cleanup */
		des3EcbFree(&ctx);
		if (isZeroed(ctx.subkeys1, sizeof(ctx.subkeys1)) &&
			isZeroed(ctx.subkeys2, sizeof(ctx.subkeys2)) &&
			isZeroed(ctx.subkeys3, sizeof(ctx.subkeys3)) &&
			isZeroed(ctx.buffer, sizeof(ctx.buffer))) {
			passed++; printSuccess("3DES ECB context cleared");
		} else
			printFailure("3DES ECB context not cleared");
		total++;
	}
	ft_printf("3DES-ECB: %d/%d passed\n", passed, total);
	g_totalTests += total;
	g_passedTests += passed;
	return (passed == total);
}

int testDes3Cbc(void) {
	int passed = 0, total = 0;
	printInfo("Testing 3DES-CBC...");

	for (int i = 0; des3CbcVectors[i].key != NULL; i++) {
		uint8_t			key[24], iv[8], plain[8], cipher[16];
		uint8_t			result[32] = {0};
		t_des3CbcCtx	ctx;
		size_t			outLen, written;

		hexToBytes(des3CbcVectors[i].key, key, 24);
		hexToBytes(des3CbcVectors[i].iv, iv, 8);
		hexToBytes(des3CbcVectors[i].plaintext, plain, 8);
		hexToBytes(des3CbcVectors[i].ciphertext, cipher, 16);

		/* ---------- Encryption ---------- */
		ft_memset(result, 0, sizeof(result));
		des3CbcInit(&ctx, key, 24, iv, CIPHER_ENCRYPT);
		des3CbcUpdate(&ctx, plain, 8, result, &written);
		outLen = written;
		des3CbcFinal(&ctx, result + outLen, &written);
		outLen += written;
		if (outLen == 16 && ft_memcmp(cipher, result, 16) == 0) {
			passed++; printSuccess("3DES CBC encrypt vector");
		} else {
			printFailure("3DES CBC encrypt vector");
			ft_printf("Expected: "); hexDump(cipher, 16);
			ft_printf("Got:	  "); hexDump(result, outLen);
		}
		total++;
		des3CbcFree(&ctx);

		/* ---------- Decryption ---------- */
		ft_memset(result, 0, sizeof(result));
		des3CbcInit(&ctx, key, 24, iv, CIPHER_DECRYPT);
		
		/* First block (8 bytes) to update */
		des3CbcUpdate(&ctx, cipher, 8, result, &written);
		outLen = written;
		/* Second block (8 bytes) to final */
		des3CbcFinal(&ctx, result + outLen, &written);
		outLen += written;
		
		if (outLen == 8 && ft_memcmp(plain, result, 8) == 0) {
			passed++; printSuccess("3DES CBC decrypt vector");
		} else {
			printFailure("3DES CBC decrypt vector");
			ft_printf("Expected: "); hexDump(plain, 8);
			ft_printf("Got:	  "); hexDump(result, outLen);
		}
		total++;

		/* Cleanup */
		des3CbcFree(&ctx);
		if (isZeroed(ctx.subkeys1, sizeof(ctx.subkeys1)) &&
			isZeroed(ctx.subkeys2, sizeof(ctx.subkeys2)) &&
			isZeroed(ctx.subkeys3, sizeof(ctx.subkeys3)) &&
			isZeroed(ctx.cbcCtx.iv, sizeof(ctx.cbcCtx.iv)) &&
			isZeroed(ctx.cbcCtx.buffer, sizeof(ctx.cbcCtx.buffer))) {
			passed++; printSuccess("3DES CBC context cleared");
		} else
			printFailure("3DES CBC context not cleared");
		total++;
	}
	ft_printf("3DES-CBC: %d/%d passed\n", passed, total);
	g_totalTests += total;
	g_passedTests += passed;
	return (passed == total);
}
