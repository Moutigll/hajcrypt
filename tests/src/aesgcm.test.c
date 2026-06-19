#include "../../hajlib/include/hmemory.h"
#include "../../hajlib/include/hstring.h"
#include "../../hajlib/include/hprintf.h"

#include "../../includes/cipher/aes.h"
#include "../test.h"

/* -------------------------------------------------------------------------- */
/*  AES‑GCM test vectors                                                      */
/* -------------------------------------------------------------------------- */
typedef struct {
	const char	*key;		/* hex string (length depends on key size) */
	const char	*iv;		/* hex string */
	const char	*aad;		/* hex string, "" for empty */
	const char	*plaintext;	/* hex string, "" for empty */
	const char	*ciphertext;/* hex string, same length as plaintext */
	const char	*tag;		/* 32‑hex characters (16 bytes) */
} t_aesGcmVector;

/* ---------- AES‑128 ---------- */
static const t_aesGcmVector aes128GcmVectors[] = {
	{
		"00000000000000000000000000000000",
		"000000000000000000000000",
		"",
		"",
		"",
		"58e2fccefa7e3061367f1d57a4e7455a"
	},
	{
		"00000000000000000000000000000000",
		"000000000000000000000000",
		"",
		"00000000000000000000000000000000",
		"0388dace60b6a392f328c2b971b2fe78",
		"ab6e47d42cec13bdf53a67b21257bddf"
	},
	{
		"feffe9928665731c6d6a8f9467308308",
		"cafebabefacedbaddecaf888",
		"",
		"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
		"1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
		"42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
		"21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
		"4d5c2af327cd64a62cf35abd2ba6fab4"
	},
	{
		"feffe9928665731c6d6a8f9467308308",
		"cafebabefacedbaddecaf888",
		"feedfacedeadbeeffeedfacedeadbeefabaddad2",
		"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
		"1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
		"42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
		"21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
		"5bc94fbc3221a5db94fae95ae7121a47"
	},
	{ NULL, NULL, NULL, NULL, NULL, NULL }
};

/* ---------- AES‑192 ---------- */
static const t_aesGcmVector aes192GcmVectors[] = {
	{
		"000000000000000000000000000000000000000000000000",
		"000000000000000000000000",
		"",
		"",
		"",
		"cd33b28ac773f74ba00ed1f312572435"
	},
	{
		"000000000000000000000000000000000000000000000000",
		"000000000000000000000000",
		"",
		"00000000000000000000000000000000",
		"98e7247c07f0fe411c267e4384b0f600",
		"2ff58d80033927ab8ef4d4587514f0fb"
	},
	{ NULL, NULL, NULL, NULL, NULL, NULL }
};

/* ---------- AES‑256 ---------- */
static const t_aesGcmVector aes256GcmVectors[] = {
	{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"000000000000000000000000",
		"",
		"",
		"",
		"530f8afbc74536b9a963b4f1c4cb738b"
	},
	{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"000000000000000000000000",
		"",
		"00000000000000000000000000000000",
		"cea7403d4d606b6e074ec5d3baf39d18",
		"d0d1c8a799996bf0265b98b5d48ab919"
	},
	{ NULL, NULL, NULL, NULL, NULL, NULL }
};

/* -------------------------------------------------------------------------- */
/*  Helper macros & functions                                                  */
/* -------------------------------------------------------------------------- */
#define MAX_BUF 2048


/* -------------------------------------------------------------------------- */
/*  AES‑GCM test for a single vector                                          */
/* -------------------------------------------------------------------------- */
static int testAesGcmVector(const t_aesGcmVector *v) {
	int		passed = 0, total = 0;
	uint8_t	key[32], iv[16], aad[MAX_BUF], pt[MAX_BUF], ct[MAX_BUF], tag[16];
	uint8_t	outBuf[MAX_BUF], outTag[16];
	size_t	kLen, ivLen, aLen, pLen, outLen, tagLen;
	t_aesGcmCtx	ctx;

	/* --- convert hex strings --- */
	kLen  = hexToBytes(v->key, key, sizeof(key));
	ivLen = hexToBytes(v->iv, iv, sizeof(iv));
	aLen  = hexToBytes(v->aad, aad, sizeof(aad));
	pLen  = hexToBytes(v->plaintext, pt, sizeof(pt));
	hexToBytes(v->ciphertext, ct, sizeof(ct));
	hexToBytes(v->tag, tag, sizeof(tag));

	/* ========== encryption ========== */
	ft_memset(&ctx, 0, sizeof(ctx));
	ft_memset(outBuf, 0, sizeof(outBuf));
	ft_memset(outTag, 0, sizeof(outTag));

	if (aesGcmInit(&ctx, key, kLen, iv, ivLen, CIPHER_ENCRYPT) != 0) {
		printFailure("GCM encryption init failed");
		total++;
		aesGcmFree(&ctx);
		return 0;
	}
	if (aLen > 0)
		aesGcmUpdateAAD(&ctx, aad, aLen);

	aesGcmUpdate(&ctx, pt, pLen, outBuf, &outLen);
	if (outLen != pLen)
		printFailure("GCM encrypt output length mismatch");
	else if (ft_memcmp(ct, outBuf, pLen) == 0) {
		passed++; printSuccess("GCM encrypt ciphertext");
	} else {
		printFailure("GCM encrypt ciphertext");
		hexDump(outBuf, pLen);
	}
	total++;

	aesGcmFinal(&ctx, outTag, &tagLen);
	if (tagLen != 16)
		printFailure("GCM encrypt tag length");
	else if (ft_memcmp(tag, outTag, 16) == 0) {
		passed++; printSuccess("GCM encrypt tag");
	} else {
		printFailure("GCM encrypt tag");
		hexDump(outTag, 16);
	}
	total++;

	aesGcmFree(&ctx);
	/* check that sensitive fields are cleared */
	if (isZeroed(ctx.roundKeys.rk, sizeof(ctx.roundKeys.rk)) &&
		isZeroed(ctx.H, sizeof(ctx.H)) &&
		isZeroed(ctx.J0, sizeof(ctx.J0)) &&
		isZeroed(ctx.counter, sizeof(ctx.counter)) &&
		isZeroed(ctx.ghashState, sizeof(ctx.ghashState))) {
		passed++; printSuccess("GCM encrypt context cleared");
	} else
		printFailure("GCM encrypt context not cleared");
	total++;

	/* ========== decryption ========== */
	ft_memset(&ctx, 0, sizeof(ctx));
	ft_memset(outBuf, 0, sizeof(outBuf));

	if (aesGcmInit(&ctx, key, kLen, iv, ivLen, CIPHER_DECRYPT) != 0) {
		printFailure("GCM decryption init failed");
		total++;
		aesGcmFree(&ctx);
		return (passed == total);
	}
	if (aLen > 0)
		aesGcmUpdateAAD(&ctx, aad, aLen);

	aesGcmUpdate(&ctx, ct, pLen, outBuf, &outLen);
	if (outLen != pLen)
		printFailure("GCM decrypt output length mismatch");
	else if (ft_memcmp(pt, outBuf, pLen) == 0) {
		passed++; printSuccess("GCM decrypt plaintext");
	} else {
		printFailure("GCM decrypt plaintext");
		hexDump(outBuf, pLen);
	}
	total++;

	aesGcmFinal(&ctx, outTag, &tagLen);
	if (tagLen != 16)
		printFailure("GCM decrypt tag length");
	else if (ft_memcmp(tag, outTag, 16) == 0) {
		passed++; printSuccess("GCM decrypt tag verified");
	} else {
		printFailure("GCM decrypt tag mismatch");
		hexDump(outTag, 16);
	}
	total++;

	aesGcmFree(&ctx);
	if (isZeroed(ctx.roundKeys.rk, sizeof(ctx.roundKeys.rk)) &&
		isZeroed(ctx.H, sizeof(ctx.H)) &&
		isZeroed(ctx.J0, sizeof(ctx.J0)) &&
		isZeroed(ctx.counter, sizeof(ctx.counter)) &&
		isZeroed(ctx.ghashState, sizeof(ctx.ghashState))) {
		passed++; printSuccess("GCM decrypt context cleared");
	} else
		printFailure("GCM decrypt context not cleared");
	total++;

	return (passed == total);
}

/* -------------------------------------------------------------------------- */
/*  Key‑size specific test loops                                              */
/* -------------------------------------------------------------------------- */
int testAesGcm128(void) {
	int passed = 0, total = 0;
	printInfo("Testing AES‑128 GCM...");
	for (int i = 0; aes128GcmVectors[i].key != NULL; i++) {
		int ok = testAesGcmVector(&aes128GcmVectors[i]);
		if (ok) passed += 7;	/* 7 checks per vector */
		total += 7;
	}
	ft_printf("AES‑128 GCM: %d/%d passed\n", passed, total);
	g_totalTests += total;
	g_passedTests += passed;
	return (passed == total);
}

int testAesGcm192(void) {
	int passed = 0, total = 0;
	printInfo("Testing AES‑192 GCM...");
	for (int i = 0; aes192GcmVectors[i].key != NULL; i++) {
		int ok = testAesGcmVector(&aes192GcmVectors[i]);
		if (ok) passed += 7;
		total += 7;
	}
	ft_printf("AES‑192 GCM: %d/%d passed\n", passed, total);
	g_totalTests += total;
	g_passedTests += passed;
	return (passed == total);
}

int testAesGcm256(void) {
	int passed = 0, total = 0;
	printInfo("Testing AES‑256 GCM...");
	for (int i = 0; aes256GcmVectors[i].key != NULL; i++) {
		int ok = testAesGcmVector(&aes256GcmVectors[i]);
		if (ok) passed += 7;
		total += 7;
	}
	ft_printf("AES‑256 GCM: %d/%d passed\n", passed, total);
	g_totalTests += total;
	g_passedTests += passed;
	return (passed == total);
}
