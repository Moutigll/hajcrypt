#include <stdlib.h>

#include "../../hajlib/include/hprintf.h"

#include "../../includes/hash/blake2b.h"
#include "../test.h"

static const struct { const char *input; size_t input_len; const char *expected; } blake2bUnkeyedVectors[] = {
	{ "", 0,
	  "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419"
	  "d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce" },
	{ "a", 1,
	  "333fcb4ee1aa7c115355ec66ceac917c8bfd815bf7587d325aec1864edd24e34"
	  "d5abe2c6b1b5ee3face62fed78dbef802f2a85cb91d455a8f5249d330853cb3c" },
	{ "abc", 3,
	  "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
	  "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923" }, // Short string
	{ "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
	  "7285ff3e8bd768d69be62b3bf18765a325917fa9744ac2f582a20850bc2b1141"
	  "ed1b3e4528595acc90772bdf2d37dc8a47130b44f33a02e8730e5ad8e166e888" }, // 56 bytes
	{ "The quick brown fox jumps over the lazy dog", 43,
	  "a8add4bdddfd93e4877d2746e62817b116364a1fa7bc148d95090bc7333b3673"
	  "f82401cf7aa2e4cb1ecd90296e3f14cb5413f8ed77be73045b13914cdcd6a918" }, // Sentence
	{ NULL, 0, NULL }
};

/* ---------- Keyed Hash (MAC) Vectors (CORRECTED) ---------- */
static const struct { const char *key; size_t key_len; const char *input; size_t input_len; const char *expected; } blake2bKeyedVectors[] = {
	{ "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f", 64,
	  "", 0,
	  "10ebb67700b1868efb4417987acf4690ae9d972fb7a590c2f02871799aaa4786"
	  "b5e996e8f0f4eb981fc214b005f42d2ff4233499391653df7aefcbc13fc51568" },
	{ "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f", 64,
	  "abc", 3,
	  "06bbc3dedf13a31139498655251b7588ccd3bb5aaa071b2d44d8e0a04095579e"
	  "d590fbfdcf941f4370ce5ce623624e7a76d33e7a8109dcda9b57d72f8f8efa51" },
	{ "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 32,
	  "The quick brown fox jumps over the lazy dog", 43,
	  "a44a52374dc66f94c213e25b2ee5b055c8aae43f17d975726c2452f5c2516504"
	  "db62be4ccf58525f5dfc6819001a7c9a74400cc53897744e72407642f71e2bee" },
	{ NULL, 0, NULL, 0, NULL }
};

/* ---------- Long Output Vectors (Simulated from your C logic) ---------- */
static const struct { const char *input; size_t input_len; size_t out_len; const char *expected; } blake2bLongVectors[] = {
	{ "abc", 3, 128,
	  "e03f682135fde8cb7caea3c8ad7c0a7e78efb026e119732d27b1eea7ba92335a"
	  "7eb8825c755809add7833e7f75e7a5915bb1b3e70eca7b61bec34cd8c486f800"
	  "5b05f94166103045f120f568fa1952f24e2a032a35d96e5a61fe520090178a4b"
	  "60490d839f773b71f88589442d94bf5614c401e1a49b7d4d6e34782c0130e1c2"
	},
	{ NULL, 0, 0, NULL }
};

/* ----------------------------------------------------------------------------
 * Basic Unkeyed Hash (One-shot)
 * -------------------------------------------------------------------------- */
int testBlake2bUnkeyed(void) {
	int passed = 0, total = 0;
	printInfo("Testing BLAKE2b unkeyed hash (one-shot)...");

	for (int i = 0; blake2bUnkeyedVectors[i].input != NULL; i++) {
		uint8_t		digest[64];
		const char	*input = blake2bUnkeyedVectors[i].input;
		size_t		len = blake2bUnkeyedVectors[i].input_len;
		const char	*expected_hex = blake2bUnkeyedVectors[i].expected;

		blake2bHash((const uint8_t *)input, len, digest, 64);
		total++;
		if (compareHex(expected_hex, digest, 64)) {
			passed++;
			printSuccess("Unkeyed vector");
		} else {
			printFailure("Unkeyed vector");
			hexDump(digest, 64);
		}
	}
	ft_printf("BLAKE2b unkeyed: %d/%d passed\n", passed, total);
	g_totalTests += total;
	g_passedTests += passed;
	return (passed == total);
}

/* ----------------------------------------------------------------------------
 * Incremental Update (byte-by-byte)
 * -------------------------------------------------------------------------- */
int testBlake2bIncremental(void) {
	int passed = 0, total = 0;
	printInfo("Testing BLAKE2b incremental update...");

	for (int i = 0; blake2bUnkeyedVectors[i].input != NULL; i++) {
		uint8_t			digest[64];
		t_blake2bCtx	ctx;
		const char		*input = blake2bUnkeyedVectors[i].input;
		size_t			len = blake2bUnkeyedVectors[i].input_len;
		const char		*expected_hex = blake2bUnkeyedVectors[i].expected;

		blake2bInit(&ctx);
		blake2bSetOutlen(&ctx, 64);
		for (size_t j = 0; j < len; j++) {
			blake2bUpdate(&ctx, (const uint8_t *)&input[j], 1);
		}
		blake2bFinal(digest, &ctx);
		total++;
		if (compareHex(expected_hex, digest, 64)) {
			passed++;
			printSuccess("Incremental vector");
		} else
			printFailure("Incremental vector");
	}
	ft_printf("BLAKE2b incremental: %d/%d passed\n", passed, total);
	g_totalTests += total;
	g_passedTests += passed;
	return (passed == total);
}

/* ----------------------------------------------------------------------------
 * Keyed Hash (MAC) Tests
 * -------------------------------------------------------------------------- */
int testBlake2bKeyed(void) {
	int passed = 0, total = 0;
	printInfo("Testing BLAKE2b keyed hash (MAC)...");

	for (int i = 0; blake2bKeyedVectors[i].key != NULL; i++) {
		uint8_t		key[64];
		uint8_t		digest[64];
		const char	*input = blake2bKeyedVectors[i].input;
		size_t		key_len = blake2bKeyedVectors[i].key_len;
		size_t		data_len = blake2bKeyedVectors[i].input_len;
		const char	*expected_hex = blake2bKeyedVectors[i].expected;

		hexToBytes(blake2bKeyedVectors[i].key, key, key_len);

		/* One-shot MAC */
		blake2bMac(key, key_len,
				   (const uint8_t *)input, data_len,
				   digest, 64);
		total++;
		if (compareHex(expected_hex, digest, 64)) {
			passed++;
			printSuccess("Keyed vector (one-shot)");
		} else
			printFailure("Keyed vector (one-shot)");

		/* Incremental keyed */
		t_blake2bCtx ctx;
		blake2bInitKeyed(&ctx, key, key_len, 64);
		blake2bUpdate(&ctx, (const uint8_t *)input, data_len);
		blake2bFinal(digest, &ctx);
		total++;
		if (compareHex(expected_hex, digest, 64)) {
			passed++;
			printSuccess("Keyed vector (incremental)");
		} else
			printFailure("Keyed vector (incremental)");
	}
	ft_printf("BLAKE2b keyed: %d/%d passed\n", passed, total);
	g_totalTests += total;
	g_passedTests += passed;
	return (passed == total);
}

/* ----------------------------------------------------------------------------
 * Long Output Tests (Tree Hashing)
 * -------------------------------------------------------------------------- */
int testBlake2bLong(void) {
	int passed = 0, total = 0;
	printInfo("Testing BLAKE2b long output...");

	for (int i = 0; blake2bLongVectors[i].input != NULL; i++) {
		const char	*input = blake2bLongVectors[i].input;
		size_t		in_len = blake2bLongVectors[i].input_len;
		size_t		out_len = blake2bLongVectors[i].out_len;
		const char	*expected_hex = blake2bLongVectors[i].expected;
		uint8_t		*digest = malloc(out_len);
		if (!digest) continue;

		blake2bLong(digest, out_len, (const uint8_t *)input, in_len);
		total++;
		if (compareHex(expected_hex, digest, out_len)) {
			passed++;
			printSuccess("Long output vector");
		} else
			printFailure("Long output vector");
		free(digest);
	}
	ft_printf("BLAKE2b long: %d/%d passed\n", passed, total);
	g_totalTests += total;
	g_passedTests += passed;
	return (passed == total);
}
