#include "../../hajlib/include/hmemory.h"
#include "../../hajlib/include/hprintf.h"

#include "../../includes/cipher/blowfish.h"
#include "../test.h"
#include <stdio.h>

static const struct { const char *key; const char *plaintext; const char *ciphertext; } blowfishEcbVectors[] = {
	{ "0000000000000000", "0000000000000000", "4ef997456198dd78" },
	{ "ffffffffffffffff", "ffffffffffffffff", "51866fd5b85ecb8a" },
	{ "00112233445566778899aabbccddeeff", "0001020304050607", "223937dbafbf99ec" },
	{ "0123456789abcdef", "fedcba9876543210", "9f5fac53492e0761" },
	{ "1337c0de1337c0de1337c0de1337c0de", "deadbeefdeadbeef", "d972ea2596a0212e" },
	{ NULL, NULL, NULL }
};

static const struct { const char *key; const char *iv; const char *plaintext; const char *ciphertext; } blowfishCbcVectors[] = {
	{ "0000000000000000", "0000000000000000", "0000000000000000", "4ef997456198dd78b1cb8d069562c76b" },
	{ "ffffffffffffffff", "ffffffffffffffff", "ffffffffffffffff", "f21e9a77b71c49bcee36ee394295895f" },
	{ "00112233445566778899aabbccddeeff", "1020304050607080", "0001020304050607", "9d996b10ab2a1950b1e855b31d74e20e" },
	{ "0123456789abcdef", "fedcba9876543210", "1337c0de1337c0de", "1138ead9f2e9cd7b32ac91ea842b1900" },
	{ "deadbeefdeadbeefdeadbeefdeadbeef", "cafebabecafebabe", "0123456789abcdef", "b1d334e7c57976db03ec544380c97f02" },
	{ NULL, NULL, NULL, NULL }
};

static const struct { const char *key; const char *iv; const char *plaintext; const char *ciphertext; } blowfishCfbVectors[] = {
	{ "0000000000000000", "0000000000000000", "0000000000000000", "4ef997456198dd78" },
	{ "ffffffffffffffff", "ffffffffffffffff", "ffffffffffffffff", "ae79902a47a13475" },
	{ "00112233445566778899aabbccddeeff", "1020304050607080", "0001020304050607", "9c2c779c2fc83477" },
	{ "0123456789abcdef", "fedcba9876543210", "1337c0de1337c0de", "8c686c8d5a19c7bf" },
	{ "deadbeefdeadbeefdeadbeefdeadbeef", "cafebabecafebabe", "0123456789abcdef", "da207e86e158e25f" },
	{ NULL, NULL, NULL, NULL }
};

static const struct { const char *key; const char *iv; const char *plaintext; const char *ciphertext; } blowfishCfb8Vectors[] = {
	{ "0000000000000000", "0000000000000000", "0000000000000000", "4ec88e83a88e46df" },
	{ "ffffffffffffffff", "ffffffffffffffff", "ffffffffffffffff", "ae28518734e65483" },
	{ "00112233445566778899aabbccddeeff", "1020304050607080", "0001020304050607", "9c3005b0b153c911" },
	{ "0123456789abcdef", "fedcba9876543210", "1337c0de1337c0de", "8c66395d978d0fe2" },
	{ "deadbeefdeadbeefdeadbeefdeadbeef", "cafebabecafebabe", "0123456789abcdef", "da915391804bd2f0" },
	{ NULL, NULL, NULL, NULL }
};

static const struct { const char *key; const char *iv; const char *plaintext; const char *ciphertext; } blowfishCfb1Vectors[] = {
	{ "0000000000000000", "0000000000000000", "0000000000000000", "0000000000000000" },
	{ "ffffffffffffffff", "ffffffffffffffff", "ffffffffffffffff", "ffffffffffffffff" },
	{ "00112233445566778899aabbccddeeff", "1020304050607080", "0001020304050607", "bf350250a2c67b16" },
	{ "0123456789abcdef", "fedcba9876543210", "1337c0de1337c0de", "ed67e8ccb67af39e" },
	{ "deadbeefdeadbeefdeadbeefdeadbeef", "cafebabecafebabe", "0123456789abcdef", "9224edf71542246d" },
	{ NULL, NULL, NULL, NULL }
};

static const struct { const char *key; const char *iv; const char *plaintext; const char *ciphertext; } blowfishOfbVectors[] = {
	{ "0000000000000000", "0000000000000000", "0000000000000000", "4ef997456198dd78" },
	{ "ffffffffffffffff", "ffffffffffffffff", "ffffffffffffffff", "ae79902a47a13475" },
	{ "00112233445566778899aabbccddeeff", "1020304050607080", "0001020304050607", "9c2c779c2fc83477" },
	{ "0123456789abcdef", "fedcba9876543210", "1337c0de1337c0de", "8c686c8d5a19c7bf" },
	{ "deadbeefdeadbeefdeadbeefdeadbeef", "cafebabecafebabe", "0123456789abcdef", "da207e86e158e25f" },
	{ NULL, NULL, NULL, NULL }
};

static const struct { const char *key; const char *iv; const char *plaintext; const char *ciphertext; } blowfishCtrVectors[] = {
	{ "0000000000000000", "0000000000000000", "0000000000000000", "4ef997456198dd78" },
	{ "ffffffffffffffff", "ffffffffffffffff", "ffffffffffffffff", "ae79902a47a13475" },
	{ "00112233445566778899aabbccddeeff", "1020304050607080", "0001020304050607", "9c2c779c2fc83477" },
	{ "0123456789abcdef", "fedcba9876543210", "1337c0de1337c0de", "8c686c8d5a19c7bf" },
	{ "deadbeefdeadbeefdeadbeefdeadbeef", "cafebabecafebabe", "0123456789abcdef", "da207e86e158e25f" },
	{ NULL, NULL, NULL, NULL }
};

static const struct { const char *key; const char *iv; const char *plaintext; const char *ciphertext; } blowfishPcbcVectors[] = {
	{ "59454C4C4F57205355424D4152494E45", "3132333435363738",  "56656374657572315665637465757231", "80a6449199abb0bb3f374c55bf2eefc1b90602fb746f4b5e" },
	{ "4B33795F533363723374", "0000000000000000",  "48656C6C6F576F726C64313233343536",  "b608fe2eac40c3179e203eb41dda8e7da9d41aca9d5d41d5" },
	{ "426C6F776669736850434243", "4142434445464748",  "54657374696E675F3839303132333435",  "98253e83f029fd1974388060792b3dbc95df8d4b8810809f" },
	{ "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", "4242424242424242",  "5374726963746C795F5365637265745F",  "71962917f8af4843af8bce2e77528ba5e10c05de5d6fbd6d" },
	{ "53686F72744B6579", "49565F5354415254",  "4C6F6E676572506C61696E74657874446174615F5769746850616464696E675F",  "8bbf4488bf24f43972f4455cd69524c5332a86c77a7c279823690f513de0e29b225ec146e1dd0f11" },
	{ NULL, NULL, NULL, NULL }
};

/* ---------- Test Functions ---------- */

int testBlowfishEcb(void) {
	int passed = 0, total = 0;
	printInfo("Testing Blowfish-ECB...");

	for (int i = 0; blowfishEcbVectors[i].key != NULL; i++) {
		uint8_t				key[56], plain[8], cipher[8], result[16] = {0};
		size_t				keyLen = hexToBytes(blowfishEcbVectors[i].key, key, sizeof(key));
		size_t				plainLen = hexToBytes(blowfishEcbVectors[i].plaintext, plain, 8);
		size_t				cipherLen = hexToBytes(blowfishEcbVectors[i].ciphertext, cipher, 8);
		t_blowfishEcbCtx	ctx;
		size_t				written, outLen;

		/* Encryption */
		ft_memset(result, 0, sizeof(result));
		blowfishEcbInit(&ctx, key, keyLen, NULL, CIPHER_ENCRYPT);
		blowfishEcbUpdate(&ctx, plain, plainLen, result, &written);
		outLen = written;
		blowfishEcbFinal(&ctx, result + outLen, &written);
		outLen += written;

		if (outLen == cipherLen && ft_memcmp(cipher, result, cipherLen) == 0) {
			passed++; printSuccess("ECB encrypt");
		} else {
			printFailure("ECB encrypt");
			hexDump(result, outLen);
		}
		total++;

		/* Decryption */
		ft_memset(result, 0, sizeof(result));
		blowfishEcbInit(&ctx, key, keyLen, NULL, CIPHER_DECRYPT);
		blowfishEcbUpdate(&ctx, cipher, cipherLen, result, &written);
		outLen = written;
		blowfishEcbFinal(&ctx, result + outLen, &written);
		outLen += written;

		if (outLen == plainLen && ft_memcmp(plain, result, plainLen) == 0) {
			passed++; printSuccess("ECB decrypt");
		} else
			printFailure("ECB decrypt");
		total++;

		/* Cleanup */
		blowfishEcbFree(&ctx);
		if (isZeroed(ctx.P, sizeof(ctx.P)) && isZeroed(ctx.S, sizeof(ctx.S))) {
			passed++; printSuccess("ECB context cleared");
		} else
			printFailure("ECB context not cleared");
		total++;
	}
	ft_printf("Blowfish-ECB: %d/%d passed\n", passed, total);
	g_totalTests += total;
	g_passedTests += passed;
	return (passed == total);
}

int testBlowfishCbc(void) {
	int passed = 0, total = 0;
	printInfo("Testing Blowfish-CBC...");

	for (int i = 0; blowfishCbcVectors[i].key != NULL; i++) {
		uint8_t				key[56], iv[8], plain[8], cipher[16], result[24] = {0};
		size_t				keyLen = hexToBytes(blowfishCbcVectors[i].key, key, sizeof(key));
		hexToBytes(blowfishCbcVectors[i].iv, iv, 8);
		size_t				plainLen  = hexToBytes(blowfishCbcVectors[i].plaintext,  plain,  8);
		size_t				cipherLen = hexToBytes(blowfishCbcVectors[i].ciphertext, cipher, 16);
		t_blowfishCbcCtx	ctx;
		size_t				written, outLen;

		/* Encryption */
		ft_memset(result, 0, sizeof(result));
		blowfishCbcInit(&ctx, key, keyLen, iv, CIPHER_ENCRYPT);
		blowfishCbcUpdate(&ctx, plain, plainLen, result, &written);
		outLen = written;
		blowfishCbcFinal(&ctx, result + outLen, &written);
		outLen += written;

		if (outLen == cipherLen && ft_memcmp(cipher, result, cipherLen) == 0) {
			passed++; printSuccess("CBC encrypt");
		} else {
			printFailure("CBC encrypt");
			hexDump(result, outLen);
		}
		total++;

		/* Decryption */
		ft_memset(result, 0, sizeof(result));
		blowfishCbcInit(&ctx, key, keyLen, iv, CIPHER_DECRYPT);
		blowfishCbcUpdate(&ctx, cipher, cipherLen, result, &written);
		outLen = written;
		blowfishCbcFinal(&ctx, result + outLen, &written);
		outLen += written;

		if (ft_memcmp(plain, result, plainLen) == 0) {
			passed++; printSuccess("CBC decrypt");
		} else
			printFailure("CBC decrypt");
		total++;

		blowfishCbcFree(&ctx);
		if (isZeroed(ctx.P, sizeof(ctx.P)) && isZeroed(ctx.S, sizeof(ctx.S)) &&
			isZeroed(ctx.cbcCtx.iv, sizeof(ctx.cbcCtx.iv))) {
			passed++; printSuccess("CBC context cleared");
		} else
			printFailure("CBC context not cleared");
		total++;
	}
	ft_printf("Blowfish-CBC: %d/%d passed\n", passed, total);
	g_totalTests += total;
	g_passedTests += passed;
	return (passed == total);
}

int testBlowfishCfb(void) {
	int passed = 0, total = 0;
	printInfo("Testing Blowfish-CFB (full block)...");

	for (int i = 0; blowfishCfbVectors[i].key != NULL; i++) {
		uint8_t				key[56], iv[8], plain[8], cipher[8], result[16] = {0};
		size_t				keyLen = hexToBytes(blowfishCfbVectors[i].key, key, sizeof(key));
		hexToBytes(blowfishCfbVectors[i].iv, iv, 8);
		size_t				plainLen = hexToBytes(blowfishCfbVectors[i].plaintext, plain, 8);
		size_t				cipherLen = hexToBytes(blowfishCfbVectors[i].ciphertext, cipher, 8);
		t_blowfishCfbCtx	ctx;
		size_t				written, outLen;

		/* Encryption */
		ft_memset(result, 0, sizeof(result));
		blowfishCfbInit(&ctx, key, keyLen, iv, CIPHER_ENCRYPT);
		blowfishCfbUpdate(&ctx, plain, plainLen, result, &written);
		outLen = written;
		blowfishCfbFinal(&ctx, result + outLen, &written);
		outLen += written;

		if (outLen == cipherLen && ft_memcmp(cipher, result, cipherLen) == 0) {
			passed++; printSuccess("CFB encrypt");
		} else
			printFailure("CFB encrypt");
		total++;

		/* Decryption */
		ft_memset(result, 0, sizeof(result));
		blowfishCfbInit(&ctx, key, keyLen, iv, CIPHER_DECRYPT);
		blowfishCfbUpdate(&ctx, cipher, cipherLen, result, &written);
		outLen = written;
		blowfishCfbFinal(&ctx, result + outLen, &written);
		outLen += written;

		if (outLen == plainLen && ft_memcmp(plain, result, plainLen) == 0) {
			passed++; printSuccess("CFB decrypt");
		} else
			printFailure("CFB decrypt");
		total++;

		blowfishCfbFree(&ctx);
		if (isZeroed(ctx.P, sizeof(ctx.P)) && isZeroed(ctx.S, sizeof(ctx.S)) &&
			isZeroed(ctx.cfbCtx.iv, sizeof(ctx.cfbCtx.iv))) {
			passed++; printSuccess("CFB context cleared");
		} else
			printFailure("CFB context not cleared");
		total++;
	}
	ft_printf("Blowfish-CFB: %d/%d passed\n", passed, total);
	g_totalTests += total;
	g_passedTests += passed;
	return (passed == total);
}

int testBlowfishCfb8(void) {
	int passed = 0, total = 0;
	printInfo("Testing Blowfish-CFB8...");

	for (int i = 0; blowfishCfb8Vectors[i].key != NULL; i++) {
		uint8_t				key[56], iv[8], plain[8], cipher[8], result[16] = {0};
		size_t				keyLen = hexToBytes(blowfishCfb8Vectors[i].key, key, sizeof(key));
		hexToBytes(blowfishCfb8Vectors[i].iv, iv, 8);
		size_t				plainLen = hexToBytes(blowfishCfb8Vectors[i].plaintext, plain, 8);
		size_t				cipherLen = hexToBytes(blowfishCfb8Vectors[i].ciphertext, cipher, 8);
		t_blowfishCfbCtx	ctx;
		size_t				written, outLen;

		/* Encryption */
		ft_memset(result, 0, sizeof(result));
		blowfishCfb8Init(&ctx, key, keyLen, iv, CIPHER_ENCRYPT);
		blowfishCfbUpdate(&ctx, plain, plainLen, result, &written);
		outLen = written;
		blowfishCfbFinal(&ctx, result + outLen, &written);
		outLen += written;

		if (outLen == cipherLen && ft_memcmp(cipher, result, cipherLen) == 0) {
			passed++; printSuccess("CFB8 encrypt");
		} else
			printFailure("CFB8 encrypt");
		total++;

		/* Decryption */
		ft_memset(result, 0, sizeof(result));
		blowfishCfb8Init(&ctx, key, keyLen, iv, CIPHER_DECRYPT);
		blowfishCfbUpdate(&ctx, cipher, cipherLen, result, &written);
		outLen = written;
		blowfishCfbFinal(&ctx, result + outLen, &written);
		outLen += written;

		if (outLen == plainLen && ft_memcmp(plain, result, plainLen) == 0) {
			passed++; printSuccess("CFB8 decrypt");
		} else
			printFailure("CFB8 decrypt");
		total++;

		blowfishCfbFree(&ctx);
		if (isZeroed(ctx.P, sizeof(ctx.P)) && isZeroed(ctx.S, sizeof(ctx.S))) {
			passed++; printSuccess("CFB8 context cleared");
		} else
			printFailure("CFB8 context not cleared");
		total++;
	}
	ft_printf("Blowfish-CFB8: %d/%d passed\n", passed, total);
	g_totalTests += total;
	g_passedTests += passed;
	return (passed == total);
}

int testBlowfishCfb1(void)
{
	int					p = 0, t = 0;
	uint8_t				k[56], iv[8], pt[8], ct[8], res[16];
	size_t				kl, pl, cl, w, tmp;
	t_blowfishCfbCtx	ctx;

	printInfo("Testing Blowfish-CFB1...");
	for (int i = 0; blowfishCfb1Vectors[i].key; i++)
	{
		kl = hexToBytes(blowfishCfb1Vectors[i].key, k, 56);
		hexToBytes(blowfishCfb1Vectors[i].iv, iv, 8);
		pl = hexToBytes(blowfishCfb1Vectors[i].plaintext, pt, 8);
		cl = hexToBytes(blowfishCfb1Vectors[i].ciphertext, ct, 8);

		/* Encryption */
		ft_memset(res, 0, sizeof(res));
		blowfishCfb1Init(&ctx, k, kl, iv, CIPHER_ENCRYPT);
		blowfishCfb1Update(&ctx, pt, pl, res, &w);
		blowfishCfb1Final(&ctx, res + w, &tmp);
		
		if ((w + tmp) == cl && !ft_memcmp(ct, res, cl))
			{ p++; printSuccess("CFB1 encrypt"); }
		else
			{ printFailure("CFB1 encrypt"); hexDump(res, w + tmp); }
		t++;

		/* Decryption */
		ft_memset(res, 0, sizeof(res));
		blowfishCfb1Init(&ctx, k, kl, iv, CIPHER_DECRYPT);
		blowfishCfb1Update(&ctx, ct, cl, res, &w);
		blowfishCfb1Final(&ctx, res + w, &tmp);

		if ((w + tmp) == pl && !ft_memcmp(pt, res, pl))
			{ p++; printSuccess("CFB1 decrypt"); }
		else
			printFailure("CFB1 decrypt");
		t++;

		/* Cleanup check */
		blowfishCfbFree(&ctx);
		if (isZeroed(ctx.P, sizeof(ctx.P)) && isZeroed(ctx.S, sizeof(ctx.S)))
			{ p++; printSuccess("CFB1 context cleared"); }
		else
			printFailure("CFB1 context not cleared");
		t++;
	}
	ft_printf("Blowfish-CFB1: %d/%d passed\n", p, t);
	g_totalTests += t; g_passedTests += p;
	return (p == t);
}

int testBlowfishOfb(void) {
	int passed = 0, total = 0;
	printInfo("Testing Blowfish-OFB...");

	for (int i = 0; blowfishOfbVectors[i].key != NULL; i++) {
		uint8_t				key[56], iv[8], plain[8], cipher[8], result[16] = {0};
		size_t				keyLen = hexToBytes(blowfishOfbVectors[i].key, key, sizeof(key));
		hexToBytes(blowfishOfbVectors[i].iv, iv, 8);
		size_t				plainLen = hexToBytes(blowfishOfbVectors[i].plaintext, plain, 8);
		size_t				cipherLen = hexToBytes(blowfishOfbVectors[i].ciphertext, cipher, 8);
		t_blowfishOfbCtx	ctx;
		size_t				written, outLen;

		/* Encryption */
		ft_memset(result, 0, sizeof(result));
		blowfishOfbInit(&ctx, key, keyLen, iv, CIPHER_ENCRYPT);
		blowfishOfbUpdate(&ctx, plain, plainLen, result, &written);
		outLen = written;
		blowfishOfbFinal(&ctx, result + outLen, &written);
		outLen += written;

		if (outLen == cipherLen && ft_memcmp(cipher, result, cipherLen) == 0) {
			passed++; printSuccess("OFB encrypt");
		} else
			printFailure("OFB encrypt");
		total++;

		/* Decryption */
		ft_memset(result, 0, sizeof(result));
		blowfishOfbInit(&ctx, key, keyLen, iv, CIPHER_DECRYPT);
		blowfishOfbUpdate(&ctx, cipher, cipherLen, result, &written);
		outLen = written;
		blowfishOfbFinal(&ctx, result + outLen, &written);
		outLen += written;

		if (outLen == plainLen && ft_memcmp(plain, result, plainLen) == 0) {
			passed++; printSuccess("OFB decrypt");
		} else
			printFailure("OFB decrypt");
		total++;

		blowfishOfbFree(&ctx);
		if (isZeroed(ctx.P, sizeof(ctx.P)) && isZeroed(ctx.S, sizeof(ctx.S))) {
			passed++; printSuccess("OFB context cleared");
		} else
			printFailure("OFB context not cleared");
		total++;
	}
	ft_printf("Blowfish-OFB: %d/%d passed\n", passed, total);
	g_totalTests += total;
	g_passedTests += passed;
	return (passed == total);
}

int testBlowfishCtr(void) {
	int passed = 0, total = 0;
	printInfo("Testing Blowfish-CTR...");

	for (int i = 0; blowfishCtrVectors[i].key != NULL; i++) {
		uint8_t				key[56], iv[8], plain[8], cipher[8], result[16] = {0};
		size_t				keyLen = hexToBytes(blowfishCtrVectors[i].key, key, sizeof(key));
		hexToBytes(blowfishCtrVectors[i].iv, iv, 8);
		size_t				plainLen = hexToBytes(blowfishCtrVectors[i].plaintext, plain, 8);
		size_t				cipherLen = hexToBytes(blowfishCtrVectors[i].ciphertext, cipher, 8);
		t_blowfishCtrCtx	ctx;
		size_t				written, outLen;

		/* Encryption */
		ft_memset(result, 0, sizeof(result));
		blowfishCtrInit(&ctx, key, keyLen, iv, CIPHER_ENCRYPT);
		blowfishCtrUpdate(&ctx, plain, plainLen, result, &written);
		outLen = written;
		blowfishCtrFinal(&ctx, result + outLen, &written);
		outLen += written;

		if (outLen == cipherLen && ft_memcmp(cipher, result, cipherLen) == 0) {
			passed++; printSuccess("CTR encrypt");
		} else
			printFailure("CTR encrypt");
		total++;

		/* Decryption */
		ft_memset(result, 0, sizeof(result));
		blowfishCtrInit(&ctx, key, keyLen, iv, CIPHER_DECRYPT);
		blowfishCtrUpdate(&ctx, cipher, cipherLen, result, &written);
		outLen = written;
		blowfishCtrFinal(&ctx, result + outLen, &written);
		outLen += written;

		if (outLen == plainLen && ft_memcmp(plain, result, plainLen) == 0) {
			passed++; printSuccess("CTR decrypt");
		} else
			printFailure("CTR decrypt");
		total++;

		blowfishCtrFree(&ctx);
		if (isZeroed(ctx.P, sizeof(ctx.P)) && isZeroed(ctx.S, sizeof(ctx.S))) {
			passed++; printSuccess("CTR context cleared");
		} else
			printFailure("CTR context not cleared");
		total++;
	}
	ft_printf("Blowfish-CTR: %d/%d passed\n", passed, total);
	g_totalTests += total;
	g_passedTests += passed;
	return (passed == total);
}

int testBlowfishPcbc(void)
{
	int					p = 0, t = 0;
	uint8_t				k[56], iv[8], pt[64], ct[64], res[128];
	size_t				kl, pl, w, tmp;
	t_blowfishPcbcCtx   ctx;

	printInfo("Testing Blowfish-PCBC...");
	for (int i = 0; blowfishPcbcVectors[i].key; i++)
	{
		kl = hexToBytes(blowfishPcbcVectors[i].key, k, 56);
		hexToBytes(blowfishPcbcVectors[i].iv, iv, 8);
		pl = hexToBytes(blowfishPcbcVectors[i].plaintext, pt, 64);
		hexToBytes(blowfishPcbcVectors[i].ciphertext, ct, 64);

		/* Encryption */
		ft_memset(res, 0, sizeof(res));
		blowfishPcbcInit(&ctx, k, kl, iv, CIPHER_ENCRYPT);
		blowfishPcbcUpdate(&ctx, pt, pl, res, &w);
		blowfishPcbcFinal(&ctx, res + w, &tmp);

		if (!ft_memcmp(ct, res, pl)) // On compare sur pl comme dans ton original
			{ p++; printSuccess("PCBC encrypt"); }
		else
			{ printFailure("PCBC encrypt"); hexDump(res, w + tmp); }
		t++;

		/* Decryption */
		ft_memset(res, 0, sizeof(res));
		blowfishPcbcInit(&ctx, k, kl, iv, CIPHER_DECRYPT);
		blowfishPcbcUpdate(&ctx, ct, pl, res, &w);
		blowfishPcbcFinal(&ctx, res + w, &tmp);

		if (!ft_memcmp(pt, res, pl))
			{ p++; printSuccess("PCBC decrypt"); }
		else
			printFailure("PCBC decrypt");
		t++;

		/* Cleanup */
		blowfishPcbcFree(&ctx);
		if (isZeroed(ctx.P, sizeof(ctx.P)) && isZeroed(ctx.S, sizeof(ctx.S)))
			{ p++; printSuccess("PCBC context cleared"); }
		else
			printFailure("PCBC context not cleared");
		t++;
	}
	ft_printf("Blowfish-PCBC: %d/%d passed\n", p, t);
	g_totalTests += t; g_passedTests += p;
	return (p == t);
}
