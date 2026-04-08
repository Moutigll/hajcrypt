#include "../../hajlib/include/hmemory.h"
#include "../../hajlib/include/hprintf.h"

#include "../../includes/cipher/des.h"
#include "../test.h"


/* DES ECB */
static const struct {
	const char	*key;
	const char	*plaintext;
	const char	*ciphertext;
} desEcbVectors[] = {
	{ "0000000000000000", "0000000000000000", "8ca64de9c1b123a7" },
	{ "ffffffffffffffff", "ffffffffffffffff", "7359b2163e4edc58" },
	{ "0123456789abcdef", "0123456789abcdef", "56cc09e7cfdc4cef" },
	{ "fedcba9876543210", "fedcba9876543210", "a933f6183023b310" },
	{ "8000000000000000", "0000000000000000", "95a8d72813daa94d" },
	{ NULL, NULL, NULL }
};

/* DES CBC */
static const struct {
	const char	*key;
	const char	*iv;
	const char	*plaintext;
	const char	*ciphertext;
} desCbcVectors[] = {
	{ "0000000000000000", "0000000000000000", "0000000000000000", "8ca64de9c1b123a7" },
	{ "ffffffffffffffff", "ffffffffffffffff", "ffffffffffffffff", "caaaaf4deaf1dbae" },
	{ "0123456789abcdef", "1234567890abcdef", "0123456789abcdef", "b55d00dc39555416" },
	{ "fedcba9876543210", "fedcba9876543210", "fedcba9876543210", "a68cdca90c9021f9" },
	{ "8000000000000000", "0000000000000000", "0000000000000000", "95a8d72813daa94d" },
	{ NULL, NULL, NULL, NULL }
};

static const struct {
	const char	*key;
	const char	*iv;
	const char	*plaintext;
	const char	*ciphertext;
} desMultiBlockVectors[] = {
	{ "0123456789abcdef", "1234567890abcdef", "0123456789abcdef0123456789abcdef", "b55d00dc395554169eb11aa05b2564ba" },
	{ "0000000000000000", "0000000000000000", "00000000000000000000000000000000", "8ca64de9c1b123a70000000000000000" },
	{ "ffffffffffffffff", "ffffffffffffffff", "ffffffffffffffffffffffffffffffff", "caaaaf4deaf1dbae32a83405f72724c5" },
	{ "8000000000000000", "0000000000000000", "00000000000000000000000000000000", "95a8d72813daa94deab608d40a48bb4e" },
	{ "0123456789abcdef", "0000000000000000", "0123456789abcdef0123456789abcdef", "56cc09e7cfdc4cef474b9fe187b22555" },
	{ NULL, NULL, NULL, NULL }
};


/* DES CFB */
static const struct {
	const char	*key;
	const char	*iv;
	const char	*plaintext;
	const char	*ciphertext;
} desCfbVectors[] = {
	{ "0000000000000000", "0000000000000000", "0000000000000000", "8ca64de9c1b123a7" },
	{ "ffffffffffffffff", "ffffffffffffffff", "ffffffffffffffff", "8ca64de9c1b123a7" },
	{ "0123456789abcdef", "1234567890abcdef", "0123456789abcdef", "bc45500e272c83ca" },
	{ "fedcba9876543210", "fedcba9876543210", "fedcba9876543210", "57ef4c8046778100" },
	{ "8000000000000000", "0000000000000000", "0000000000000000", "95a8d72813daa94d" },
	{ NULL, NULL, NULL, NULL }
};

/* DES CFB8 */
static const struct {
	const char	*key;
	const char	*iv;
	const char	*plaintext;
	const char	*ciphertext;
} desCfb8Vectors[] = {
	{ "0000000000000000", "0000000000000000", "0000000000000000", "8c18e616cdeb8874" },
	{ "ffffffffffffffff", "ffffffffffffffff", "ffffffffffffffff", "8cb1000c25872954" },
	{ "0123456789abcdef", "1234567890abcdef", "0123456789abcdef", "bc1bfe44c7116438" },
	{ "fedcba9876543210", "fedcba9876543210", "fedcba9876543210", "576f71d3cb8a60ba" },
	{ "8000000000000000", "0000000000000000", "0000000000000000", "95812f4b5a41f8f3" },
	{ NULL, NULL, NULL, NULL }
};

/* DES CFB1 (bit‑oriented) */
static const struct {
	const char	*key;
	const char	*iv;
	const char	*plaintext;
	const char	*ciphertext;
} desCfb1Vectors[] = {
	{ "0000000000000000", "0000000000000000", "0000000000000000", "975d8e6bb6f23a77" },  // was 8191182064460819
	{ "ffffffffffffffff", "ffffffffffffffff", "ffffffffffffffff", "ffffffffffffffff" },
{ "0123456789abcdef", "1234567890abcdef", "0123456789abcdef", "aca2be5a093e8a44" },  // was bed2e4345f510b2f
{ "fedcba9876543210", "fedcba9876543210", "fedcba9876543210", "006cdd3c226c947f" },  // was 3a294df64aca9551
{ "8000000000000000", "0000000000000000", "0000000000000000", "e5b9ce73116e656b" },  // was fa8f674273674273
	{ NULL, NULL, NULL, NULL }
};

/* DES OFB */
static const struct {
	const char	*key;
	const char	*iv;
	const char	*plaintext;
	const char	*ciphertext;
} desOfbVectors[] = {
	{ "0000000000000000", "0000000000000000", "0000000000000000", "8ca64de9c1b123a7" },
	{ "ffffffffffffffff", "ffffffffffffffff", "ffffffffffffffff", "8ca64de9c1b123a7" },
	{ "0123456789abcdef", "1234567890abcdef", "0123456789abcdef", "bc45500e272c83ca" },
	{ "fedcba9876543210", "fedcba9876543210", "fedcba9876543210", "57ef4c8046778100" },
	{ "8000000000000000", "0000000000000000", "0000000000000000", "95a8d72813daa94d" },
	{ NULL, NULL, NULL, NULL }
};

/* DES CTR */
static const struct {
	const char	*key;
	const char	*iv;
	const char	*plaintext;
	const char	*ciphertext;
} desCtrVectors[] = {
	{ "0000000000000000", "0000000000000000", "0000000000000000", "8ca64de9c1b123a7" },
	{ "ffffffffffffffff", "ffffffffffffffff", "ffffffffffffffff", "8ca64de9c1b123a7" },  // was e1eceaa84715eb8e
{ "0123456789abcdef", "1234567890abcdef", "0123456789abcdef", "bc45500e272c83ca" },  // was e5a30214a0b1433c
{ "fedcba9876543210", "fedcba9876543210", "fedcba9876543210", "57ef4c8046778100" },  // was 12672b94125870b7
	{ "8000000000000000", "0000000000000000", "0000000000000000", "95a8d72813daa94d" },
	{ NULL, NULL, NULL, NULL }
};

/* DES PCBC */
static const struct {
	const char *key;
	const char *iv;
	const char *plaintext;
	const char *ciphertext;
} desPcbcVectors[] = {
	{ "0000000000000000", "0000000000000000", "0000000000000000", "8ca64de9c1b123a7" },
	{ "ffffffffffffffff", "ffffffffffffffff", "ffffffffffffffff", "caaaaf4deaf1dbae" },
	{ "0123456789abcdef", "1234567890abcdef", "0123456789abcdef", "b55d00dc39555416" },
	{ "fedcba9876543210", "fedcba9876543210", "fedcba9876543210", "a68cdca90c9021f9" },
	{ "8000000000000000", "0000000000000000", "0000000000000000", "95a8d72813daa94d" },
	{ NULL, NULL, NULL, NULL }
};

/* ---------- ECB ---------- */
int testDesEcb(void) {
	int passed = 0, total = 0;
	printInfo("Testing DES-ECB...");

	for (int i = 0; desEcbVectors[i].key != NULL; i++) {
		uint8_t		key[8], plain[8], cipher[8], result[16] = {0};
		t_desEcbCtx	ctx;
		size_t		outLen, written;

		hexToBytes(desEcbVectors[i].key, key, 8);
		hexToBytes(desEcbVectors[i].plaintext, plain, 8);
		hexToBytes(desEcbVectors[i].ciphertext, cipher, 8);

		/* Encryption */
		ft_memset(result, 0, sizeof(result));
		desEcbInit(&ctx, key, 8, NULL, CIPHER_ENCRYPT);
		desEcbUpdate(&ctx, plain, 8, result, &written);
		outLen = written;
		desEcbFinal(&ctx, result + outLen, &written);
		outLen += written;
		if (ft_memcmp(cipher, result, 8) == 0) {
			passed++; printSuccess("ECB encrypt vector");
		} else {
			printFailure("ECB encrypt vector");
			hexDump(result, 8);
		}
		total++;

		/* Decryption */
		ft_memset(result, 0, sizeof(result));
		desEcbInit(&ctx, key, 8, NULL, CIPHER_DECRYPT);
		desEcbUpdate(&ctx, cipher, 8, result, &written);
		outLen = written;
		desEcbFinal(&ctx, result + outLen, &written);
		outLen += written;
		if (ft_memcmp(plain, result, 8) == 0) {
			passed++; printSuccess("ECB decrypt vector");
		} else
			printFailure("ECB decrypt vector");
		total++;

		/* Cleanup */
		desEcbFree(&ctx);
		if (isZeroed(ctx.subkeys, sizeof(ctx.subkeys)) &&
			isZeroed(ctx.buffer, sizeof(ctx.buffer))) {
			passed++; printSuccess("ECB context cleared");
		} else
			printFailure("ECB context not cleared");
		total++;
	}
	ft_printf("DES-ECB: %d/%d passed\n", passed, total);
	g_totalTests += total;
	g_passedTests += passed;
	return (passed == total);
}

/* ---------- CBC ---------- */
int testDesCbc(void) {
	int passed = 0, total = 0;
	printInfo("Testing DES-CBC...");

	for (int i = 0; desCbcVectors[i].key != NULL; i++) {
		uint8_t		key[8], iv[8], plain[8], cipher[8], result[16] = {0};
		t_desCbcCtx	ctx;
		size_t		written, outLen;

		hexToBytes(desCbcVectors[i].key, key, 8);
		hexToBytes(desCbcVectors[i].iv, iv, 8);
		hexToBytes(desCbcVectors[i].plaintext, plain, 8);
		hexToBytes(desCbcVectors[i].ciphertext, cipher, 8);

		/* Encryption */
		ft_memset(result, 0, sizeof(result));
		desCbcInit(&ctx, key, 8, iv, CIPHER_ENCRYPT);
		desCbcUpdate(&ctx, plain, 8, result, &written);
		outLen = written;
		desCbcFinal(&ctx, result + outLen, &written);
		outLen += written;
		if (ft_memcmp(cipher, result, 8) == 0) {
			passed++; printSuccess("CBC encrypt vector");
		} else
			printFailure("CBC encrypt vector");
		total++;

		/* Decryption */
		ft_memset(result, 0, sizeof(result));
		desCbcInit(&ctx, key, 8, iv, CIPHER_DECRYPT);
		desCbcUpdate(&ctx, cipher, 8, result, &written);
		outLen = written;
		desCbcFinal(&ctx, result + outLen, &written);
		outLen += written;
		if (ft_memcmp(plain, result, 8) == 0) {
			passed++; printSuccess("CBC decrypt vector");
		} else
			printFailure("CBC decrypt vector");
		total++;

		/* Cleanup */
		desCbcFree(&ctx);
		if (isZeroed(ctx.subkeys, sizeof(ctx.subkeys)) &&
			isZeroed(ctx.cbcCtx.iv, sizeof(ctx.cbcCtx.iv)) &&
			isZeroed(ctx.cbcCtx.buffer, sizeof(ctx.cbcCtx.buffer))) {
			passed++; printSuccess("CBC context cleared");
		} else
			printFailure("CBC context not cleared");
		total++;
	}
	ft_printf("DES-CBC: %d/%d passed\n", passed, total);
	g_totalTests += total;
	g_passedTests += passed;
	return (passed == total);
}

/* ---------- Multi-block CBC ---------- */
int testDesMultiBlock(void) {
	int passed = 0, total = 0;
	printInfo("Testing DES-CBC multi-block...");

	for (int i = 0; desMultiBlockVectors[i].key != NULL; i++) {
		uint8_t		key[8], iv[8], plain[32], cipher[32], result[64] = {0};
		t_desCbcCtx	ctx;
		size_t		plainLen, cipherLen, written, outLen;

		hexToBytes(desMultiBlockVectors[i].key, key, 8);
		hexToBytes(desMultiBlockVectors[i].iv, iv, 8);
		plainLen = hexToBytes(desMultiBlockVectors[i].plaintext, plain, 32);
		cipherLen = hexToBytes(desMultiBlockVectors[i].ciphertext, cipher, 32);

		/* ---------- Chiffrement ---------- */
		ft_memset(result, 0, sizeof(result));
		desCbcInit(&ctx, key, 8, iv, CIPHER_ENCRYPT);
		desCbcUpdate(&ctx, plain, plainLen, result, &written);
		outLen = written;
		if (outLen == cipherLen && ft_memcmp(cipher, result, cipherLen) == 0) {
			passed++; printSuccess("Multi-block encrypt vector");
		} else
			printFailure("Multi-block encrypt vector");
		total++;
		desCbcFree(&ctx);

		/* ---------- Déchiffrement ---------- */
		ft_memset(result, 0, sizeof(result));
		desCbcInit(&ctx, key, 8, iv, CIPHER_DECRYPT);
		desCbcUpdate(&ctx, cipher, cipherLen, result, &written);
		outLen = written;
		if (ft_memcmp(plain, result, plainLen) == 0) {
			passed++; printSuccess("Multi-block decrypt vector");
		} else
			printFailure("Multi-block decrypt vector");
		total++;
		desCbcFree(&ctx);
	}
	ft_printf("DES-CBC multi-block: %d/%d passed\n", passed, total);
	g_totalTests += total;
	g_passedTests += passed;
	return (passed == total);
}

/* ---------- CFB (64-bit) ---------- */
int testDesCfb(void) {
	int passed = 0, total = 0;
	printInfo("Testing DES-CFB...");

	for (int i = 0; desCfbVectors[i].key != NULL; i++) {
		uint8_t		key[8], iv[8], plain[8], cipher[8], result[16] = {0};
		t_desCfbCtx	ctx;
		size_t		written, outLen;

		hexToBytes(desCfbVectors[i].key, key, 8);
		hexToBytes(desCfbVectors[i].iv, iv, 8);
		hexToBytes(desCfbVectors[i].plaintext, plain, 8);
		hexToBytes(desCfbVectors[i].ciphertext, cipher, 8);

		/* Encryption */
		ft_memset(result, 0, sizeof(result));
		desCfbInit(&ctx, key, 8, iv, CIPHER_ENCRYPT);
		desCfbUpdate(&ctx, plain, 8, result, &written);
		outLen = written;
		desCfbFinal(&ctx, result + outLen, &written);
		outLen += written;
		if (ft_memcmp(cipher, result, 8) == 0) {
			passed++; printSuccess("CFB encrypt vector");
		} else
			printFailure("CFB encrypt vector");
		total++;

		/* Decryption */
		ft_memset(result, 0, sizeof(result));
		desCfbInit(&ctx, key, 8, iv, CIPHER_DECRYPT);
		desCfbUpdate(&ctx, cipher, 8, result, &written);
		outLen = written;
		desCfbFinal(&ctx, result + outLen, &written);
		outLen += written;
		if (ft_memcmp(plain, result, 8) == 0) {
			passed++; printSuccess("CFB decrypt vector");
		} else
			printFailure("CFB decrypt vector");
		total++;

		/* Cleanup */
		desCfbFree(&ctx);
		if (isZeroed(ctx.subkeys, sizeof(ctx.subkeys)) &&
			isZeroed(ctx.cfbCtx.iv, sizeof(ctx.cfbCtx.iv)) &&
			isZeroed(ctx.cfbCtx.shiftRegister, sizeof(ctx.cfbCtx.shiftRegister))) {
			passed++; printSuccess("CFB context cleared");
		} else
			printFailure("CFB context not cleared");
		total++;
	}
	ft_printf("DES-CFB: %d/%d passed\n", passed, total);
	g_totalTests += total;
	g_passedTests += passed;
	return (passed == total);
}

/* ---------- CFB8 ---------- */
int testDesCfb8(void) {
	int passed = 0, total = 0;
	printInfo("Testing DES-CFB8...");

	for (int i = 0; desCfb8Vectors[i].key != NULL; i++) {
		uint8_t		key[8], iv[8], plain[8], cipher[8], result[16] = {0};
		t_desCfbCtx	ctx;
		size_t		plainLen, written, outLen;

		hexToBytes(desCfb8Vectors[i].key, key, 8);
		hexToBytes(desCfb8Vectors[i].iv, iv, 8);
		plainLen = hexToBytes(desCfb8Vectors[i].plaintext, plain, 8);
		hexToBytes(desCfb8Vectors[i].ciphertext, cipher, 8);

		/* Encryption */
		ft_memset(result, 0, sizeof(result));
		desCfb8Init(&ctx, key, 8, iv, CIPHER_ENCRYPT);
		desCfbUpdate(&ctx, plain, plainLen, result, &written);
		outLen = written;
		desCfbFinal(&ctx, result + outLen, &written);
		outLen += written;
		if (ft_memcmp(cipher, result, plainLen) == 0) {
			passed++; printSuccess("CFB8 encrypt vector");
		} else
			printFailure("CFB8 encrypt vector");
		total++;

		/* Decryption */
		ft_memset(result, 0, sizeof(result));
		desCfb8Init(&ctx, key, 8, iv, CIPHER_DECRYPT);
		desCfbUpdate(&ctx, cipher, plainLen, result, &written);
		outLen = written;
		desCfbFinal(&ctx, result + outLen, &written);
		outLen += written;
		if (ft_memcmp(plain, result, plainLen) == 0) {
			passed++; printSuccess("CFB8 decrypt vector");
		} else
			printFailure("CFB8 decrypt vector");
		total++;

		/* Cleanup */
		desCfbFree(&ctx);
		if (isZeroed(ctx.subkeys, sizeof(ctx.subkeys)) &&
			isZeroed(ctx.cfbCtx.iv, sizeof(ctx.cfbCtx.iv)) &&
			isZeroed(ctx.cfbCtx.shiftRegister, sizeof(ctx.cfbCtx.shiftRegister))) {
			passed++; printSuccess("CFB8 context cleared");
		} else
			printFailure("CFB8 context not cleared");
		total++;
	}
	ft_printf("DES-CFB8: %d/%d passed\n", passed, total);
	g_totalTests += total;
	g_passedTests += passed;
	return (passed == total);
}

/* ---------- CFB1 ---------- */
int testDesCfb1(void) {
	int passed = 0, total = 0;
	printInfo("Testing DES-CFB1...");

	for (int i = 0; desCfb1Vectors[i].key != NULL; i++) {
		uint8_t		key[8], iv[8], plain[8], cipher[8], result[16] = {0};
		t_desCfbCtx	ctx;
		size_t		plainLen = 8, written, outLen;

		hexToBytes(desCfb1Vectors[i].key, key, 8);
		hexToBytes(desCfb1Vectors[i].iv, iv, 8);
		hexToBytes(desCfb1Vectors[i].plaintext, plain, 8);
		hexToBytes(desCfb1Vectors[i].ciphertext, cipher, 8);

		/* Encryption */
		ft_memset(result, 0, sizeof(result));
		desCfb1Init(&ctx, key, 8, iv, CIPHER_ENCRYPT);
		desCfb1Update(&ctx, plain, plainLen, result, &written);
		outLen = written;
		desCfb1Final(&ctx, result + outLen, &written);
		outLen += written;
		if (outLen == plainLen && ft_memcmp(cipher, result, plainLen) == 0) {
			passed++; printSuccess("CFB1 encrypt vector");
		} else {
			printFailure("CFB1 encrypt vector");
			hexDump(result, plainLen);
		}
		total++;

		/* Decryption */
		ft_memset(result, 0, sizeof(result));
		desCfb1Init(&ctx, key, 8, iv, CIPHER_DECRYPT);
		desCfb1Update(&ctx, cipher, plainLen, result, &written);
		outLen = written;
		desCfb1Final(&ctx, result + outLen, &written);
		outLen += written;
		if (outLen == plainLen && ft_memcmp(plain, result, plainLen) == 0) {
			passed++; printSuccess("CFB1 decrypt vector");
		} else
			printFailure("CFB1 decrypt vector");
		total++;

		/* Cleanup */
		desCfbFree(&ctx);
		if (isZeroed(ctx.subkeys, sizeof(ctx.subkeys)) &&
			isZeroed(ctx.cfbCtx.iv, sizeof(ctx.cfbCtx.iv)) &&
			isZeroed(ctx.cfbCtx.shiftRegister, sizeof(ctx.cfbCtx.shiftRegister))) {
			passed++; printSuccess("CFB1 context cleared");
		} else
			printFailure("CFB1 context not cleared");
		total++;
	}
	ft_printf("DES-CFB1: %d/%d passed\n", passed, total);
	g_totalTests += total;
	g_passedTests += passed;
	return (passed == total);
}

/* ---------- OFB ---------- */
int testDesOfb(void) {
	int passed = 0, total = 0;
	printInfo("Testing DES-OFB...");

	for (int i = 0; desOfbVectors[i].key != NULL; i++) {
		uint8_t		key[8], iv[8], plain[8], cipher[8], result[16] = {0};
		t_desOfbCtx	ctx;
		size_t		plainLen, written, outLen;

		hexToBytes(desOfbVectors[i].key, key, 8);
		hexToBytes(desOfbVectors[i].iv, iv, 8);
		plainLen = hexToBytes(desOfbVectors[i].plaintext, plain, 8);
		hexToBytes(desOfbVectors[i].ciphertext, cipher, 8);

		/* Encryption */
		ft_memset(result, 0, sizeof(result));
		desOfbInit(&ctx, key, 8, iv, CIPHER_ENCRYPT);
		desOfbUpdate(&ctx, plain, plainLen, result, &written);
		outLen = written;
		desOfbFinal(&ctx, result + outLen, &written);
		outLen += written;
		if (ft_memcmp(cipher, result, plainLen) == 0) {
			passed++; printSuccess("OFB encrypt vector");
		} else
			printFailure("OFB encrypt vector");
		total++;

		/* Decryption */
		ft_memset(result, 0, sizeof(result));
		desOfbInit(&ctx, key, 8, iv, CIPHER_DECRYPT);
		desOfbUpdate(&ctx, cipher, plainLen, result, &written);
		outLen = written;
		desOfbFinal(&ctx, result + outLen, &written);
		outLen += written;
		if (ft_memcmp(plain, result, plainLen) == 0) {
			passed++; printSuccess("OFB decrypt vector");
		} else
			printFailure("OFB decrypt vector");
		total++;

		/* Cleanup */
		desOfbFree(&ctx);
		if (isZeroed(ctx.subkeys, sizeof(ctx.subkeys)) &&
			isZeroed(ctx.ofbCtx.iv, sizeof(ctx.ofbCtx.iv)) &&
			isZeroed(ctx.ofbCtx.keystream, sizeof(ctx.ofbCtx.keystream))) {
			passed++; printSuccess("OFB context cleared");
		} else
			printFailure("OFB context not cleared");
		total++;
	}
	ft_printf("DES-OFB: %d/%d passed\n", passed, total);
	g_totalTests += total;
	g_passedTests += passed;
	return (passed == total);
}

/* ---------- CTR ---------- */
int testDesCtr(void) {
	int passed = 0, total = 0;
	printInfo("Testing DES-CTR...");

	for (int i = 0; desCtrVectors[i].key != NULL; i++) {
		uint8_t		key[8], iv[8], plain[8], cipher[8], result[16] = {0};
		t_desCtrCtx	ctx;
		size_t		plainLen, written, outLen;

		hexToBytes(desCtrVectors[i].key, key, 8);
		hexToBytes(desCtrVectors[i].iv, iv, 8);
		plainLen = hexToBytes(desCtrVectors[i].plaintext, plain, 8);
		hexToBytes(desCtrVectors[i].ciphertext, cipher, 8);

		/* Encryption */
		ft_memset(result, 0, sizeof(result));
		desCtrInit(&ctx, key, 8, iv, CIPHER_ENCRYPT);
		desCtrUpdate(&ctx, plain, plainLen, result, &written);
		outLen = written;
		desCtrFinal(&ctx, result + outLen, &written);
		outLen += written;
		if (ft_memcmp(cipher, result, plainLen) == 0) {
			passed++; printSuccess("CTR encrypt vector");
		} else
			printFailure("CTR encrypt vector");
		total++;

		/* Decryption */
		ft_memset(result, 0, sizeof(result));
		desCtrInit(&ctx, key, 8, iv, CIPHER_DECRYPT);
		desCtrUpdate(&ctx, cipher, plainLen, result, &written);
		outLen = written;
		desCtrFinal(&ctx, result + outLen, &written);
		outLen += written;
		if (ft_memcmp(plain, result, plainLen) == 0) {
			passed++; printSuccess("CTR decrypt vector");
		} else
			printFailure("CTR decrypt vector");
		total++;

		/* Cleanup */
		desCtrFree(&ctx);
		if (isZeroed(ctx.subkeys, sizeof(ctx.subkeys)) &&
			isZeroed(ctx.ctrCtx.iv, sizeof(ctx.ctrCtx.iv)) &&
			isZeroed(ctx.ctrCtx.counter, sizeof(ctx.ctrCtx.counter))) {
			passed++; printSuccess("CTR context cleared");
		} else
			printFailure("CTR context not cleared");
		total++;
	}
	ft_printf("DES-CTR: %d/%d passed\n", passed, total);
	g_totalTests += total;
	g_passedTests += passed;
	return (passed == total);
}

/* ---------- PCBC ---------- */
int testDesPcbc(void) {
	int passed = 0, total = 0;
	printInfo("Testing DES-PCBC...");

	for (int i = 0; desPcbcVectors[i].key != NULL; i++) {
		uint8_t			key[8], iv[8], plain[8], cipher[8], result[16] = {0};
		t_desPcbcCtx	ctx;
		size_t			plainLen, written, outLen;

		hexToBytes(desPcbcVectors[i].key, key, 8);
		hexToBytes(desPcbcVectors[i].iv, iv, 8);
		plainLen = hexToBytes(desPcbcVectors[i].plaintext, plain, 8);
		hexToBytes(desPcbcVectors[i].ciphertext, cipher, 8);

		/* Encryption */
		ft_memset(result, 0, sizeof(result));
		desPcbcInit(&ctx, key, 8, iv, CIPHER_ENCRYPT);
		desPcbcUpdate(&ctx, plain, plainLen, result, &written);
		outLen = written;
		desPcbcFinal(&ctx, result + outLen, &written);
		outLen += written;
		if (ft_memcmp(cipher, result, plainLen) == 0) {
			passed++; printSuccess("PCBC encrypt vector");
		} else
			printFailure("PCBC encrypt vector");
		total++;

		/* Decryption */
		ft_memset(result, 0, sizeof(result));
		desPcbcInit(&ctx, key, 8, iv, CIPHER_DECRYPT);
		desPcbcUpdate(&ctx, cipher, plainLen, result, &written);
		outLen = written;
		desPcbcFinal(&ctx, result + outLen, &written);
		outLen += written;
		if (ft_memcmp(plain, result, plainLen) == 0) {
			passed++; printSuccess("PCBC decrypt vector");
		} else
			printFailure("PCBC decrypt vector");
		total++;

		/* Cleanup */
		desPcbcFree(&ctx);
		if (isZeroed(ctx.subkeys, sizeof(ctx.subkeys)) &&
			isZeroed(ctx.pcbcCtx.iv, sizeof(ctx.pcbcCtx.iv)) &&
			isZeroed(ctx.pcbcCtx.prevPlain, sizeof(ctx.pcbcCtx.prevPlain))) {
			passed++; printSuccess("PCBC context cleared");
		} else
			printFailure("PCBC context not cleared");
		total++;
	}
	ft_printf("DES-PCBC: %d/%d passed\n", passed, total);
	g_totalTests += total;
	g_passedTests += passed;
	return (passed == total);
}
