#include <stdlib.h>
#include <string.h>

#include "../../hajlib/include/hmemory.h"
#include "../../hajlib/include/hprintf.h"
#include "../../hajlib/include/hstring.h"

#include "../../includes/kdf/argon2.h"
#include "../test.h"

typedef struct s_argon2Vector {
	const char	*password;
	size_t		pass_len;
	const char	*salt;
	size_t		salt_len;
	uint32_t	memory;
	uint32_t	iterations;
	uint32_t	parallelism;
	size_t		hash_len;
	const char	*expected_encoded;
} t_argon2Vector;

static const t_argon2Vector argon2dVectors[] = {
	{ "password", 8, "somesalt", 8, 32, 3, 4, 32,
	  "$argon2d$v=19$m=32,t=3,p=4$c29tZXNhbHQ$2MVNYoPKLcFIQqhQnXyEuRibdik1YNfEd1stHw1pqWg" },
	{ "password", 8, "somesalt", 8, 64, 1, 1, 64,
	  "$argon2d$v=19$m=64,t=1,p=1$c29tZXNhbHQ$CqEs2z4EzEqD8IUqxs70C5ko/P565wq6ZJ8AUGO5RGWhVed6r+c4Sgv7jQjY8PHvsaObiMe0PpVtqauLhfNzCA" },
	{ NULL, 0, NULL, 0, 0, 0, 0, 0, NULL }
};

static const t_argon2Vector argon2iVectors[] = {
	{ "password", 8, "somesalt", 8, 32, 3, 4, 32,
	  "$argon2i$v=19$m=32,t=3,p=4$c29tZXNhbHQ$vXVJGX0zAxmVS0DF9PoP/nmMoHEzHOyyguwgIIaFDKg" },
	{ "password", 8, "somesalt", 8, 64, 1, 1, 64,
	  "$argon2i$v=19$m=64,t=1,p=1$c29tZXNhbHQ$FjufF/GZHIzej6P5Be6xoAOe+vZVzyHREggHtKfC0mB1nyFjGkU92BF8+qSC0Kd398brpgxYpMQBtoVCQ2ppvQ" },
	{ NULL, 0, NULL, 0, 0, 0, 0, 0, NULL }
};

static const t_argon2Vector argon2idVectors[] = {
	{ "password", 8, "somesalt", 8, 32, 3, 4, 32,
	  "$argon2id$v=19$m=32,t=3,p=4$c29tZXNhbHQ$uwzICj5nEUlSaRVBjG7v52G7GdXS1WegF3A+DOpqsFw" },
	{ "password", 8, "somesalt", 8, 64, 1, 1, 64,
	  "$argon2id$v=19$m=64,t=1,p=1$c29tZXNhbHQ$XGv1XIZW6Wn8Aqv++THGpS5sNOg9HNMtbaVEsw2qPvLsNXhH4DjfOd3zhSa4MAzKcr34ct1qwa5v1sC1m4Nuug" },
	{ NULL, 0, NULL, 0, 0, 0, 0, 0, NULL }
};


static int runArgon2Vectors(t_argon2Type type, const t_argon2Vector *vectors, const char *type_name)
{
	int passed = 0, total = 0;
	char info[64];
	ft_snprintf(info, sizeof(info), "Testing Argon2%s vectors...", type_name);
	printInfo(info);

	for (int i = 0; vectors[i].password != NULL; i++) {
		t_argon2Ctx	ctx;
		uint8_t		*hash = malloc(vectors[i].hash_len);
		char encoded[512];

		total++;
		if (!hash) {
			printFailure("malloc failed");
			continue;
		}

		/* Initialisation */
		if (argon2Init(&ctx,
		               (const uint8_t *)vectors[i].password, vectors[i].pass_len,
		               (const uint8_t *)vectors[i].salt,     vectors[i].salt_len,
		               vectors[i].memory, vectors[i].iterations,
		               vectors[i].parallelism, type) != 0) {
			printFailure("argon2Init failed");
			free(hash);
			continue;
		}
		ctx.outputLen = (uint32_t)vectors[i].hash_len;

		/* Hash + encodage */
		int ret = argon2Hash(&ctx, hash, vectors[i].hash_len);
		if (ret == 0)
			ret = argon2Encode(&ctx, hash, vectors[i].hash_len, encoded, sizeof(encoded));

		if (ret != 0) {
			printFailure("argon2Hash/Encode failed");
			free(hash);
			argon2Free(&ctx);
			continue;
		}


		ft_printf("Test vector %d: %s\n", i + 1, encoded);

		/* Comparaison */
		if (ft_strcmp(encoded, vectors[i].expected_encoded) == 0) {
			passed++;
			printSuccess("Encoded string matches");
		} else {
			printFailure("Encoded mismatch");
			ft_printf("Got:      %s\nExpected: %s\n", encoded, vectors[i].expected_encoded);
		}

		free(hash);
		argon2Free(&ctx);
	}

	ft_printf("Argon2%s: %d/%d passed\n", type_name, passed, total);
	g_totalTests  += total;
	g_passedTests += passed;
	return (passed == total);
}

int testArgon2d(void)
{
	return runArgon2Vectors(ARGON2_D, argon2dVectors, "d");
}

int testArgon2i(void)
{
	return runArgon2Vectors(ARGON2_I, argon2iVectors, "i");
}

int testArgon2id(void)
{
	return runArgon2Vectors(ARGON2_ID, argon2idVectors, "id");
}

int testArgon2idOneShot(void)
{
	int passed = 0, total = 0;
	printInfo("Testing argon2id() one-shot...");

	const char	*pass    = "password";
	size_t		passlen = 8;
	size_t		outlen  = 32;
	uint8_t		out[32];
	uint8_t		zeros[32];
	ft_bzero(zeros, sizeof(zeros));

	total++;
	int ret = argon2id((const uint8_t *)pass, passlen, out, outlen);
	if (ret == 0) {
		passed++;
		printSuccess("One-shot returns 0");
	} else {
		printFailure("One-shot failed (ret != 0)");
	}

	total++;
	if (ret == 0 && ft_memcmp(out, zeros, outlen) != 0) {
		passed++;
		printSuccess("One-shot output is non-zero");
	} else
		printFailure("One-shot output is all-zero");

	ft_printf("Argon2id one-shot: %d/%d passed\n", passed, total);
	g_totalTests  += total;
	g_passedTests += passed;
	return (passed == total);
}

int testArgon2EncodeDecode(void)
{
	int passed = 0, total = 0;
	printInfo("Testing Argon2 encode/decode...");

	t_argon2Ctx	ctx;
	uint8_t		hash[32];
	char		encoded[256];
	t_argon2Ctx	decodedCtx;
	uint8_t		decodedHash[32];
	size_t		decodedHashLen = sizeof(decodedHash);
	const char	*password = "secret";
	const char	*salt = "randomsalt";

	if (argon2Init(&ctx, (const uint8_t *)password, ft_strlen(password),
	               (const uint8_t *)salt, ft_strlen(salt), 32, 3, 4, ARGON2_ID) != 0) {
		printFailure("argon2Init failed");
		total++;
		goto encodeCleanup;
	}

	int ret = argon2Hash(&ctx, hash, sizeof(hash));
	total++;
	if (ret != 0) {
		printFailure("argon2Hash failed");
		argon2Free(&ctx);
		goto encodeCleanup;
	}
	passed++;

	ret = argon2Encode(&ctx, hash, sizeof(hash), encoded, sizeof(encoded));
	total++;
	if (ret != 0) {
		printFailure("argon2Encode failed");
		argon2Free(&ctx);
		goto encodeCleanup;
	}
	passed++;

	ret = argon2Decode(encoded, &decodedCtx, decodedHash, &decodedHashLen);
	total++;
	if (ret != 0) {
		printFailure("argon2Decode failed");
		argon2Free(&ctx);
		goto encodeCleanup;
	}
	passed++;

	total++;
	if (decodedCtx.type == ctx.type &&
	    decodedCtx.memory == ctx.memory &&
	    decodedCtx.iterations == ctx.iterations &&
	    decodedCtx.parallelism == ctx.parallelism &&
	    decodedCtx.saltLen == ctx.saltLen &&
	    ft_memcmp(decodedCtx.salt, ctx.salt, ctx.saltLen) == 0 &&
	    decodedHashLen == sizeof(hash) &&
	    ft_memcmp(decodedHash, hash, sizeof(hash)) == 0) {
		passed++;
		printSuccess("Encode/decode roundtrip");
	} else
		printFailure("Encode/decode mismatch");

	argon2Free(&ctx);
	argon2Free(&decodedCtx);

encodeCleanup:
	ft_printf("Argon2 encode/decode: %d/%d passed\n", passed, total);
	g_totalTests += total;
	g_passedTests += passed;
	return (passed == total);
}

/* ----------------------------------------------------------------------------
 * Verify function test
 * -------------------------------------------------------------------------- */
int testArgon2Verify(void)
{
	int passed = 0, total = 0;
	printInfo("Testing argon2Verify...");

	t_argon2Ctx	ctx;
	uint8_t		hash[32];
	char		encoded[256];
	const char	*password = "correct horse battery staple";
	size_t		passlen = ft_strlen(password);

	argon2Init(&ctx, (const uint8_t *)password, passlen,
	           (const uint8_t *)"randomsalt", 10, 64, 2, 2, ARGON2_ID);
	int ret = argon2Hash(&ctx, hash, sizeof(hash));
	if (ret != 0) {
		printFailure("argon2Hash failed");
		argon2Free(&ctx);
		goto verifyCleanup;
	}
	ret = argon2Encode(&ctx, hash, sizeof(hash), encoded, sizeof(encoded));
	argon2Free(&ctx);
	if (ret != 0) {
		printFailure("argon2Encode failed");
		goto verifyCleanup;
	}

	total++;
	int match = argon2Verify(encoded, (const uint8_t *)password, passlen);
	if (match == 1) {
		passed++;
		printSuccess("Correct password verified");
	} else
		printFailure("Correct password rejected");

	total++;
	match = argon2Verify(encoded, (const uint8_t *)"wrong", 5);
	if (match == 0) {
		passed++;
		printSuccess("Wrong password rejected");
	} else
		printFailure("Wrong password accepted");

verifyCleanup:
	ft_printf("Argon2 verify: %d/%d passed\n", passed, total);
	g_totalTests += total;
	g_passedTests += passed;
	return (passed == total);
}

int testArgon2EdgeCases(void)
{
	int passed = 0, total = 0;
	printInfo("Testing Argon2 edge cases...");

	t_argon2Ctx	ctx;
	uint8_t		out[32];

	argon2Init(&ctx, (uint8_t *)"p", 1, (uint8_t *)"s", 1,
	           ARGON2_MIN_MEMORY - 1, 1, 1, ARGON2_ID);
	total++;
	if (argon2Hash(&ctx, out, sizeof(out)) != 0) {
		passed++;
		printSuccess("Memory too small rejected");
	} else
		printFailure("Memory too small accepted");
	argon2Free(&ctx);

	argon2Init(&ctx, (uint8_t *)"p", 1, (uint8_t *)"s", 1, 32, 0, 1, ARGON2_ID);
	total++;
	if (argon2Hash(&ctx, out, sizeof(out)) != 0) {
		passed++;
		printSuccess("Zero iterations rejected");
	} else
		printFailure("Zero iterations accepted");
	argon2Free(&ctx);

	argon2Init(&ctx, (uint8_t *)"p", 1, (uint8_t *)"s", 1, 32, 1, 0, ARGON2_ID);
	total++;
	if (argon2Hash(&ctx, out, sizeof(out)) != 0) {
		passed++;
		printSuccess("Zero parallelism rejected");
	} else
		printFailure("Zero parallelism accepted");
	argon2Free(&ctx);

	argon2Init(&ctx, (uint8_t *)"p", 1, (uint8_t *)"s", 1, 32, 1, 1, ARGON2_ID);
	total++;
	if (argon2Hash(&ctx, NULL, 32) != 0) {
		passed++;
		printSuccess("NULL output rejected");
	} else
		printFailure("NULL output accepted");
	argon2Free(&ctx);

	argon2Init(&ctx, (uint8_t *)"p", 1, (uint8_t *)"s", 1, 32, 1, 1, ARGON2_ID);
	argon2Free(&ctx);
	total++;
	if (ctx.memoryArray == NULL && ctx.password == NULL && ctx.salt == NULL) {
		passed++;
		printSuccess("argon2Free zeroes context");
	} else
		printFailure("argon2Free did not fully clean");

	ft_printf("Argon2 edge cases: %d/%d passed\n", passed, total);
	g_totalTests += total;
	g_passedTests += passed;
	return (passed == total);
}

int testArgon2Default(void)
{
	int passed = 0, total = 0;
	printInfo("Testing Argon2 default parameters...");

	t_argon2Ctx	ctx;
	uint8_t		out[32];

	argon2InitDefault(&ctx);
	total++;
	if (ctx.memory == ARGON2_DEFAULT_MEMORY &&
	    ctx.iterations == ARGON2_DEFAULT_ITERATIONS &&
	    ctx.parallelism == ARGON2_DEFAULT_PARALLELISM &&
	    ctx.type == ARGON2_DEFAULT_TYPE) {
		passed++;
		printSuccess("InitDefault sets recommended params");
	} else
		printFailure("InitDefault params incorrect");

	argon2SetPassword(&ctx, (uint8_t *)"default", 7);
	argon2SetSalt(&ctx, (uint8_t *)"saltsalt", 8);
	int ret = argon2Hash(&ctx, out, sizeof(out));
	total++;
	if (ret == 0) {
		passed++;
		printSuccess("Default context hashes successfully");
	} else
		printFailure("Default context hash failed");
	argon2Free(&ctx);

	ft_printf("Argon2 default: %d/%d passed\n", passed, total);
	g_totalTests += total;
	g_passedTests += passed;
	return (passed == total);
}
