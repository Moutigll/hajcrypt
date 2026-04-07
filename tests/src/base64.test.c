#include "../../hajlib/include/hmemory.h"
#include "../../hajlib/include/hprintf.h"
#include "../../hajlib/include/hstring.h"
#include "../../includes/cipher/base64.h"

#include "../test.h"

/* Test vectors with explicit lengths (to handle binary data containing null bytes) */
static const struct {
	const char *plain;
	size_t		plainLen;
	const char *base64;
	size_t		base64Len;
} base64Vectors[] = {
	/* RFC 4648 standard vectors */
	{ "",		0,	"",				0 },
	{ "f",		1,	"Zg==",			4 },
	{ "fo",		2,	"Zm8=",			4 },
	{ "foo",	3,	"Zm9v",			4 },
	{ "foobar",	6,	"Zm9vYmFy",		8 },
	{ "L'exactitude est la politesse des rois.", 39,
	  "TCdleGFjdGl0dWRlIGVzdCBsYSBwb2xpdGVzc2UgZGVzIHJvaXMu", 52 },
	/* Binary data: bytes 0x00 .. 0x3f (64 bytes) */
	{ "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
	  "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
	  "\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f"
	  "\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f",
	  64,
	  "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+Pw==",
	  88 },
	{ NULL, 0, NULL, 0 }
};

/* Additional decode-only tests (ASCII only) */
static const struct {
	const char *base64;
	const char *expected;
} b64DecodeOnly[] = {
	{ "SGFqQ3J5cHQ=", "HajCrypt" },
	{ "VGhpcyBpcyBhIHRlc3Qgc3RyaW5nLg==", "This is a test string." },
	{ "SW5jb3JyZWN0IEJhc2U2NCBEYXRhIQ==", "Incorrect Base64 Data!" },
	{ "U29tZSBpbnZhbGlkIGJhc2U2NCBzdHJpbmc=", "Some invalid base64 string" },
	{ NULL, NULL }
};

int testBase64(void)
{
	int			 p = 0, t = 0;
	uint8_t		 res[256];
	size_t		  pl, bl, w, tmp;
	t_base64Ctx	 ctx;

	printInfo("Testing Base64 (Extended)...");

	/* --- TEST 1: ENCODE & DECODE (FULL CYCLE) --- */
	for (int i = 0; base64Vectors[i].plain; i++)
	{
		pl = base64Vectors[i].plainLen;
		bl = base64Vectors[i].base64Len;

		/* Encode plaintext -> base64 */
		base64Init(&ctx, NULL, 0, NULL, CIPHER_ENCRYPT);
		base64Update(&ctx, (uint8_t*)base64Vectors[i].plain, pl, res, &w);
		base64Final(&ctx, res + w, &tmp);
		if ((w + tmp) == bl && !ft_memcmp(base64Vectors[i].base64, res, bl))
			{ p++; printSuccess("B64 Full-Cycle Encode"); }
		else
			{ printFailure("B64 Full-Cycle Encode"); hexDump(res, w + tmp);}
		t++;

		/* Decode base64 -> plaintext */
		base64Init(&ctx, NULL, 0, NULL, CIPHER_DECRYPT);
		base64Update(&ctx, (uint8_t*)base64Vectors[i].base64, bl, res, &w);
		base64Final(&ctx, res + w, &tmp);
		if ((w + tmp) == pl && !ft_memcmp(base64Vectors[i].plain, res, pl))
			{ p++; printSuccess("B64 Full-Cycle Decode"); }
		else
			printFailure("B64 Full-Cycle Decode");
		t++;
		base64Free(&ctx);
	}

	/* --- TEST 2: DECODE ONLY (SPECIFIC VECTORS) --- */
	for (int i = 0; b64DecodeOnly[i].base64; i++)
	{
		bl = ft_strlen(b64DecodeOnly[i].base64);
		pl = ft_strlen(b64DecodeOnly[i].expected);

		base64Init(&ctx, NULL, 0, NULL, CIPHER_DECRYPT);
		base64Update(&ctx, (uint8_t*)b64DecodeOnly[i].base64, bl, res, &w);
		base64Final(&ctx, res + w, &tmp);

		if ((w + tmp) == pl && !ft_memcmp(b64DecodeOnly[i].expected, res, pl))
			{ p++; printSuccess("B64 Pure Decode"); }
		else
			{ printFailure("B64 Pure Decode"); hexDump(res, w + tmp); }
		t++;
		base64Free(&ctx);
	}

	ft_printf("Base64 Total: %d/%d passed\n", p, t);
	g_totalTests += t; g_passedTests += p;
	return (p == t);
}
