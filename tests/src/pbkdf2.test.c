#include <stdlib.h>

#include "../../hajlib/include/hmemory.h"
#include "../../hajlib/include/hprintf.h"
#include "../../hajlib/include/hstring.h"

#include "../../includes/hash/md5.h"
#include "../../includes/hash/sha256.h"
#include "../../includes/kdf/pbkdf2.h"
#include "../test.h"

/* ============================================================================
 * PBKDF2-HMAC-SHA256 Test Vectors
 * ============================================================================ */

static const struct {
	const char	*password;
	size_t		pass_len;
	const char	*salt;
	size_t		salt_len;
	uint32_t	iterations;
	size_t		dk_len;
	const char	*expected;
} pbkdf2Sha256Vectors[] = {
	{
		"password", 8,
		"salt", 4,
		1, 32,
		"120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
	},
	{
		"password", 8,
		"salt", 4,
		2, 32,
		"ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"
	},
	{
		"password", 8,
		"salt", 4,
		4096, 32,
		"c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"
	},
	{
		"passwordPASSWORDpassword", 24,
		"saltSALTsaltSALTsaltSALTsaltSALTsalt", 36,
		4096, 40,
		"348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1"
		"c635518c7dac47e9"
	},
	{
		"pass\0word", 9,
		"sa\0lt", 5,
		4096, 16,
		"89b69d0516f829893c696226650a8687"
	},
	/* Long output (64 bytes) */
	{
		"password", 8,
		"salt", 4,
		1, 64,
		"120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b4dbf3a2f3dad3377264bb7b8e8330d4efc7451418617dabef683735361cdc18c"
	},
	{ NULL, 0, NULL, 0, 0, 0, NULL }
};

/* ============================================================================
 * PBKDF2-HMAC-MD5 Test Vectors
 * ============================================================================ */

static const struct {
	const char	*password;
	size_t		pass_len;
	const char	*salt;
	size_t		salt_len;
	uint32_t	iterations;
	size_t		dk_len;
	const char	*expected;
} pbkdf2Md5Vectors[] = {
	{
		"password", 8,
		"salt", 4,
		1, 16,
		"f31afb6d931392daa5e3130f47f9a9b6"
	},
	{
		"password", 8,
		"salt", 4,
		2, 16,
		"042407b552be345ad6eee2cf2f7ed01d"
	},
	{
		"password", 8,
		"salt", 4,
		4096, 16,
		"15001f89b9c29ee6998c520d1a0629e8"
	},
	{
		"passwordPASSWORDpassword", 24,
		"saltSALTsaltSALTsaltSALTsaltSALTsalt", 36,
		4096, 24,
		"8d5d0aad94d14420429fbc7e5b087d7a5527e65dfd0d486a"
	},
	{
		"pass\0word", 9,
		"sa\0lt", 5,
		4096, 8,
		"9d35f8f9b26aa9a8"
	},
	/* Long output (32 bytes) */
	{
		"password", 8,
		"salt", 4,
		1, 32,
		"f31afb6d931392daa5e3130f47f9a9b6e8e72029d8350b9fb27a9e0e00b9d991"
	},
	{ NULL, 0, NULL, 0, 0, 0, NULL }
};

typedef struct s_pbkdf2Vector {
	const char	*password;
	size_t		pass_len;
	const char	*salt;
	size_t		salt_len;
	uint32_t	iterations;
	size_t		dk_len;
	const char	*expected;
} t_pbkdf2Vector;

static int runPbkdf2Tests(const t_hash			*hash,
						  const t_pbkdf2Vector	*vectors,
						  const char			*algo_name)
{
	int passed = 0, total = 0;
	char outHex[65];
	ft_snprintf(outHex, sizeof(outHex), "Testing PBKDF2-%s...", algo_name);
	printInfo(outHex);

	for (int i = 0; vectors[i].expected != NULL; i++) {
		t_pbkdf2Ctx	ctx;
		uint8_t		*out = malloc(vectors[i].dk_len);
		if (!out) {
			printFailure("malloc failed");
			total++;
			continue;
		}

		/* Initialisation */
		int ret = pbkdf2Init(&ctx, hash,
							 (const uint8_t *)vectors[i].password,
							 vectors[i].pass_len,
							 (const uint8_t *)vectors[i].salt,
							 vectors[i].salt_len,
							 vectors[i].iterations);
		total++;
		if (ret != 0) {
			printFailure("pbkdf2Init failed");
			free(out);
			continue;
		}
		passed++;

		/* Derivation */
		ret = pbkdf2Derive(&ctx, out, vectors[i].dk_len);
		total++;
		if (ret != 0) {
			printFailure("pbkdf2Derive failed");
			free(out);
			continue;
		}
		if (compareHex(vectors[i].expected, out, vectors[i].dk_len)) {
			passed++;
			printSuccess("vector");
		} else {
			printFailure("vector mismatch");
			hexDump(out, vectors[i].dk_len);
		}
		free(out);
	}

	ft_printf("PBKDF2-%s: %d/%d passed\n", algo_name, passed, total);
	g_totalTests += total;
	g_passedTests += passed;
	return (passed == total);
}

/* ============================================================================
 * Public Test Functions
 * ============================================================================ */

int testPbkdf2Sha256(void)
{
	return runPbkdf2Tests(&g_sha256Hash,
						  (const t_pbkdf2Vector *)pbkdf2Sha256Vectors,
						  "SHA256");
}

int testPbkdf2Md5(void)
{
	return runPbkdf2Tests(&g_md5Hash,
						  (const t_pbkdf2Vector *)pbkdf2Md5Vectors,
						  "MD5");
}

/* ----------------------------------------------------------------------------
 * Test pbkdf2DeriveKeyIv (combined key + IV derivation)
 * -------------------------------------------------------------------------- */
int testPbkdf2DeriveKeyIv(void)
{
	int passed = 0, total = 0;
	printInfo("Testing PBKDF2 DeriveKeyIv (SHA256)...");

	t_pbkdf2Ctx ctx;
	const char *pass = "secret";
	const char *salt = "nacl";
	uint8_t key[32], iv[16];
	uint8_t expected_key[32] = {
		0x9f, 0x61, 0x9b, 0xc0, 0x32, 0xeb, 0xbf, 0xd2, 
		0x9a, 0x68, 0x62, 0x65, 0x76, 0xfa, 0xeb, 0x1c,
		0x61, 0x1f, 0x92, 0x7d, 0xbf, 0x23, 0x97, 0xed, 
		0x88, 0xa4, 0x29, 0x2f, 0x94, 0x06, 0x7a, 0x91
	};
	uint8_t expected_iv[16] = {
		0xd4, 0xc4, 0x95, 0x79, 0xcd, 0x27, 0x3d, 0xba, 
		0xdb, 0x07, 0x48, 0x5c, 0xc7, 0x0d, 0x44, 0x5e
	};

	/* Initialisation */
	int ret = pbkdf2Init(&ctx, &g_sha256Hash,
						 (const uint8_t *)pass, ft_strlen(pass),
						 (const uint8_t *)salt, ft_strlen(salt),
						 1);
	total++;
	if (ret != 0) {
		printFailure("Init failed");
		goto cleanup;
	}
	passed++;

	/* Derivation key + IV */
	ret = pbkdf2DeriveKeyIv(&ctx, key, iv, sizeof(key), sizeof(iv));
	total++;
	if (ret != 0) {
		printFailure("DeriveKeyIv failed");
		goto cleanup;
	}
	if (ft_memcmp(key, expected_key, sizeof(key)) == 0 &&
		ft_memcmp(iv, expected_iv, sizeof(iv)) == 0) {
		passed++;
		printSuccess("DeriveKeyIv vector");
	} else {
		printFailure("DeriveKeyIv vector mismatch");
		ft_printf("Expected key: "); hexDump(expected_key, 32);
		ft_printf("Got key:	  "); hexDump(key, 32);
		ft_printf("Expected IV:  "); hexDump(expected_iv, 16);
		ft_printf("Got IV:	   "); hexDump(iv, 16);
	}

	/* Zero-length output edge case */
	ret = pbkdf2DeriveKeyIv(&ctx, key, iv, 0, 0);
	total++;
	if (ret == 0) {
		passed++;
		printSuccess("Zero-length outputs handled");
	} else
		printFailure("Zero-length outputs failed");

cleanup:
	ft_printf("PBKDF2 DeriveKeyIv: %d/%d passed\n", passed, total);
	g_totalTests += total;
	g_passedTests += passed;
	return (passed == total);
}

/* ----------------------------------------------------------------------------
 * Edge Cases and Error Handling
 * -------------------------------------------------------------------------- */
int testPbkdf2EdgeCases(void)
{
	int passed = 0, total = 0;
	printInfo("Testing PBKDF2 edge cases...");

	t_pbkdf2Ctx	ctx;
	uint8_t		out[32];

	/* 1. NULL hash */
	int	ret = pbkdf2Init(&ctx, NULL, (uint8_t *)"p", 1, (uint8_t *)"s", 1, 1);
	total++;
	if (ret != 0) { passed++; printSuccess("NULL hash rejected"); }
	else		  { printFailure("NULL hash accepted"); }

	/* 2. Zero iterations */
	ret = pbkdf2Init(&ctx, &g_sha256Hash, (uint8_t *)"p", 1, (uint8_t *)"s", 1, 0);
	total++;
	if (ret != 0 || (ret == 0 && pbkdf2Derive(&ctx, out, 32) == 0)) {
		passed++; printSuccess("Zero iterations handled");
	} else {
		printFailure("Zero iterations caused error");
	}

	/* 3. NULL output buffer */
	ret = pbkdf2Init(&ctx, &g_sha256Hash, (uint8_t *)"p", 1, (uint8_t *)"s", 1, 1);
	if (ret == 0) {
		total++;
		ret = pbkdf2Derive(&ctx, NULL, 32);
		if (ret != 0) { passed++; printSuccess("NULL output rejected"); }
		else		  { printFailure("NULL output accepted"); }
	}

	ft_printf("PBKDF2 edge cases: %d/%d passed\n", passed, total);
	g_totalTests += total;
	g_passedTests += passed;
	return (passed == total);
}
