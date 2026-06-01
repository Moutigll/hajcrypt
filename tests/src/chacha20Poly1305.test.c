#include "../../hajlib/include/hmemory.h"
#include "../../hajlib/include/hprintf.h"
#include "../../hajlib/include/hstring.h"
#include "../../includes/cipher/chacha20Poly1305.h"

#include "../test.h"

int testPoly1305RFCVectors(void)
{
	int				passed = 0, total = 0;
	uint8_t			tag[POLY1305_TAG_SIZE];
	t_poly1305Ctx	ctx;

	printInfo("Testing Poly1305 RFC 7539 test vectors...");

	/* ---------- Test vector #1 : all zero ---------- */
	{
		const uint8_t key[POLY1305_KEY_SIZE] = {0};
		const uint8_t expected[POLY1305_TAG_SIZE] = {0};

		poly1305Init(&ctx, key);
		poly1305Update(&ctx, NULL, 0);
		poly1305Final(&ctx, tag);

		if (ft_memcmp(tag, expected, POLY1305_TAG_SIZE) == 0) {
			passed++; printSuccess("Poly1305 test vector #1 (all zeros)");
		} else {
			printFailure("Poly1305 test vector #1 (all zeros)");
			ft_printf("Expected: "); hexDump(expected, POLY1305_TAG_SIZE);
			ft_printf("Got:	  "); hexDump(tag, POLY1305_TAG_SIZE);
		}
		total++;
	}

	/* ---------- Test vector #2 : r = 0 ---------- */
	{
		const uint8_t key[POLY1305_KEY_SIZE] = {
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x36,0xe5,0xf6,0xb5,0xc5,0xe0,0x60,0x70,
			0xf0,0xef,0xca,0x96,0x22,0x7a,0x86,0x3e
		};
		const char *msg =
			"Any submission to the IETF intended by the Contributor "
			"for publication as all or part of an IETF Internet-Draft "
			"or RFC and any statement made within the context of an "
			"IETF activity is considered an \"IETF Contribution\". "
			"Such statements include oral statements in IETF sessions, "
			"as well as written and electronic communications made at "
			"any time or place, which are addressed to";
		const uint8_t expected[POLY1305_TAG_SIZE] = {
			0x36,0xe5,0xf6,0xb5,0xc5,0xe0,0x60,0x70,
			0xf0,0xef,0xca,0x96,0x22,0x7a,0x86,0x3e
		};

		poly1305Init(&ctx, key);
		poly1305Update(&ctx, (const uint8_t *)msg, ft_strlen(msg));
		poly1305Final(&ctx, tag);

		if (ft_memcmp(tag, expected, POLY1305_TAG_SIZE) == 0) {
			passed++; printSuccess("Poly1305 test vector #2 (r=0)");
		} else {
			printFailure("Poly1305 test vector #2 (r=0)");
			ft_printf("Expected: "); hexDump(expected, POLY1305_TAG_SIZE);
			ft_printf("Got:	  "); hexDump(tag, POLY1305_TAG_SIZE);
		}
		total++;
	}

	/* ---------- Test vector #3 : normal key, full message ---------- */
	{
		const uint8_t key[POLY1305_KEY_SIZE] = {
			0x36,0xe5,0xf6,0xb5,0xc5,0xe0,0x60,0x70,
			0xf0,0xef,0xca,0x96,0x22,0x7a,0x86,0x3e,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
		};
		const char *msg =
			"Any submission to the IETF intended by the Contributor "
			"for publication as all or part of an IETF Internet-Draft "
			"or RFC and any statement made within the context of an "
			"IETF activity is considered an \"IETF Contribution\". "
			"Such statements include oral statements in IETF sessions, "
			"as well as written and electronic communications made at "
			"any time or place, which are addressed to";
		const uint8_t expected[POLY1305_TAG_SIZE] = {
			0xf3,0x47,0x7e,0x7c,0xd9,0x54,0x17,0xaf,
			0x89,0xa6,0xb8,0x79,0x4c,0x31,0x0c,0xf0
		};

		poly1305Init(&ctx, key);
		poly1305Update(&ctx, (const uint8_t *)msg, ft_strlen(msg));
		poly1305Final(&ctx, tag);

		if (ft_memcmp(tag, expected, POLY1305_TAG_SIZE) == 0) {
			passed++; printSuccess("Poly1305 test vector #3 (normal)");
		} else {
			printFailure("Poly1305 test vector #3 (normal)");
			ft_printf("Expected: "); hexDump(expected, POLY1305_TAG_SIZE);
			ft_printf("Got:	  "); hexDump(tag, POLY1305_TAG_SIZE);
		}
		total++;
	}

	/* ---------- Test vector #4 : Jabberwocky ---------- */
	{
		const uint8_t key[POLY1305_KEY_SIZE] = {
			0x1c,0x92,0x40,0xa5,0xeb,0x55,0xd3,0x8a,
			0xf3,0x33,0x88,0x86,0x04,0xf6,0xb5,0xf0,
			0x47,0x39,0x17,0xc1,0x40,0x2b,0x80,0x09,
			0x9d,0xca,0x5c,0xbc,0x20,0x70,0x75,0xc0
		};
		const char *msg =
			"'Twas brillig, and the slithy toves\n"
			"Did gyre and gimble in the wabe:\n"
			"All mimsy were the borogoves,\n"
			"And the mome raths outgrabe.";
		const uint8_t expected[POLY1305_TAG_SIZE] = {
			0x45,0x41,0x66,0x9a,0x7e,0xaa,0xee,0x61,
			0xe7,0x08,0xdc,0x7c,0xbc,0xc5,0xeb,0x62
		};

		poly1305Init(&ctx, key);
		poly1305Update(&ctx, (const uint8_t *)msg, ft_strlen(msg));
		poly1305Final(&ctx, tag);

		if (ft_memcmp(tag, expected, POLY1305_TAG_SIZE) == 0) {
			passed++; printSuccess("Poly1305 test vector #4 (Jabberwocky)");
		} else {
			printFailure("Poly1305 test vector #4 (Jabberwocky)");
			ft_printf("Expected: "); hexDump(expected, POLY1305_TAG_SIZE);
			ft_printf("Got:	  "); hexDump(tag, POLY1305_TAG_SIZE);
		}
		total++;
	}

	/* ---------- Test vector #5 : edge case, r=2, s=0, data=all FF ---------- */
	{
		const uint8_t key[POLY1305_KEY_SIZE] = {
			0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
		};
		uint8_t msg[16];
		ft_memset(msg, 0xFF, 16);
		const uint8_t expected[POLY1305_TAG_SIZE] = {
			0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
		};

		poly1305Init(&ctx, key);
		poly1305Update(&ctx, msg, 16);
		poly1305Final(&ctx, tag);

		if (ft_memcmp(tag, expected, POLY1305_TAG_SIZE) == 0) {
			passed++; printSuccess("Poly1305 test vector #5 (edge case)");
		} else {
			printFailure("Poly1305 test vector #5 (edge case)");
			ft_printf("Expected: "); hexDump(expected, POLY1305_TAG_SIZE);
			ft_printf("Got:	  "); hexDump(tag, POLY1305_TAG_SIZE);
		}
		total++;
	}

	/* ---------- Test vector #6 : r=2, s=all FF, data=02..., tag=03... ---------- */
	{
		const uint8_t key[POLY1305_KEY_SIZE] = {
			0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
		};
		uint8_t msg[16];
		ft_memset(msg, 0, 16);
		msg[0] = 0x02;
		const uint8_t expected[POLY1305_TAG_SIZE] = {
			0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
		};

		poly1305Init(&ctx, key);
		poly1305Update(&ctx, msg, 16);
		poly1305Final(&ctx, tag);

		if (ft_memcmp(tag, expected, POLY1305_TAG_SIZE) == 0) {
			passed++; printSuccess("Poly1305 test vector #6 (edge case)");
		} else {
			printFailure("Poly1305 test vector #6 (edge case)");
			ft_printf("Expected: "); hexDump(expected, POLY1305_TAG_SIZE);
			ft_printf("Got:	  "); hexDump(tag, POLY1305_TAG_SIZE);
		}
		total++;
	}

	g_passedTests += passed;
	g_totalTests += total;
	return (passed == total);
}

int testChaCha20Poly1305RFCVectors(void)
{
	int passed = 0, total = 0;

	printInfo("Testing ChaCha20 and ChaCha20-Poly1305 RFC 7539 test vectors...");

	/* ---------- Test vector 1 (RFC 7539, Section 2.4.2) - ChaCha20 ONLY ---------- */
	{
		const uint8_t key[32] = {
			0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
			0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
			0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
			0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
		};
		const uint8_t nonce[12] = {
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x4a,0x00,0x00,0x00,0x00
		};
		const uint8_t plaintext[] = {
			0x4c,0x61,0x64,0x69,0x65,0x73,0x20,0x61,0x6e,0x64,0x20,0x47,
			0x65,0x6e,0x74,0x6c,0x65,0x6d,0x65,0x6e,0x20,0x6f,0x66,0x20,
			0x74,0x68,0x65,0x20,0x63,0x6c,0x61,0x73,0x73,0x20,0x6f,0x66,
			0x20,0x27,0x39,0x39,0x3a,0x20,0x49,0x66,0x20,0x49,0x20,0x63,
			0x6f,0x75,0x6c,0x64,0x20,0x6f,0x66,0x66,0x65,0x72,0x20,0x79,
			0x6f,0x75,0x20,0x6f,0x6e,0x6c,0x79,0x20,0x6f,0x6e,0x65,0x20,
			0x74,0x69,0x70,0x20,0x66,0x6f,0x72,0x20,0x74,0x68,0x65,0x20,
			0x66,0x75,0x74,0x75,0x72,0x65,0x2c,0x20,0x73,0x75,0x6e,0x73,
			0x63,0x72,0x65,0x65,0x6e,0x20,0x77,0x6f,0x75,0x6c,0x64,0x20,
			0x62,0x65,0x20,0x69,0x74,0x2e
		};
		const uint8_t expected_ct[] = {
			0x6e,0x2e,0x35,0x9a,0x25,0x68,0xf9,0x80,0x41,0xba,0x07,0x28,
			0xdd,0x0d,0x69,0x81,0xe9,0x7e,0x7a,0xec,0x1d,0x43,0x60,0xc2,
			0x0a,0x27,0xaf,0xcc,0xfd,0x9f,0xae,0x0b,0xf9,0x1b,0x65,0xc5,
			0x52,0x47,0x33,0xab,0x8f,0x59,0x3d,0xab,0xcd,0x62,0xb3,0x57,
			0x16,0x39,0xd6,0x24,0xe6,0x51,0x52,0xab,0x8f,0x53,0x0c,0x35,
			0x9f,0x08,0x61,0xd8,0x07,0xca,0x0d,0xbf,0x50,0x0d,0x6a,0x61,
			0x56,0xa3,0x8e,0x08,0x8a,0x22,0xb6,0x5e,0x52,0xbc,0x51,0x4d,
			0x16,0xcc,0xf8,0x06,0x81,0x8c,0xe9,0x1a,0xb7,0x79,0x37,0x36,
			0x5a,0xf9,0x0b,0xbf,0x74,0xa3,0x5b,0xe6,0xb4,0x0b,0x8e,0xed,
			0xf2,0x78,0x5e,0x42,0x87,0x4d
		};

		uint8_t ct[sizeof(plaintext)], pt2[sizeof(plaintext)];
		t_chacha20Ctx ctx;
		ft_bzero(ct, sizeof(ct));
		chacha20Init(&ctx, key, nonce, 1);
		chacha20Crypt(&ctx, plaintext, ct, sizeof(plaintext));

		if (ft_memcmp(ct, expected_ct, sizeof(plaintext)) == 0) {
			passed++;
			printSuccess("RFC 7539 test vector 1 (ChaCha20 encrypt)");
		} else {
			printFailure("RFC 7539 test vector 1 (ChaCha20 encrypt)");
			ft_printf("Expected:\n"); hexDump(expected_ct, sizeof(expected_ct));
			ft_printf("Got:\n"); hexDump(ct, sizeof(ct));
		}
		total++;

		ft_memset(pt2, 0, sizeof(pt2));
		chacha20Init(&ctx, key, nonce, 1);
		chacha20Crypt(&ctx, ct, pt2, sizeof(ct));
		if (ft_memcmp(pt2, plaintext, sizeof(plaintext)) == 0) {
			passed++;
			printSuccess("RFC 7539 test vector 1 (ChaCha20 decrypt)");
		} else
			printFailure("RFC 7539 test vector 1 (ChaCha20 decrypt)");
		total++;
		chacha20Free(&ctx);
	}

	/* ---------- Test vector 2 (RFC 7539, Section 2.8.2) - AEAD with AAD ---------- */
	{
		const uint8_t key[32] = {
			0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,0x88,0x89,0x8a,0x8b,
			0x8c,0x8d,0x8e,0x8f,0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,
			0x98,0x99,0x9a,0x9b,0x9c,0x9d,0x9e,0x9f
		};
		const uint8_t nonce[12] = {
			0x07,0x00,0x00,0x00,0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47
		};
		const uint8_t aad[] = {
			0x50,0x51,0x52,0x53,0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7
		};
		const uint8_t plaintext[] = {
			0x4c,0x61,0x64,0x69,0x65,0x73,0x20,0x61,0x6e,0x64,0x20,0x47,
			0x65,0x6e,0x74,0x6c,0x65,0x6d,0x65,0x6e,0x20,0x6f,0x66,0x20,
			0x74,0x68,0x65,0x20,0x63,0x6c,0x61,0x73,0x73,0x20,0x6f,0x66,
			0x20,0x27,0x39,0x39,0x3a,0x20,0x49,0x66,0x20,0x49,0x20,0x63,
			0x6f,0x75,0x6c,0x64,0x20,0x6f,0x66,0x66,0x65,0x72,0x20,0x79,
			0x6f,0x75,0x20,0x6f,0x6e,0x6c,0x79,0x20,0x6f,0x6e,0x65,0x20,
			0x74,0x69,0x70,0x20,0x66,0x6f,0x72,0x20,0x74,0x68,0x65,0x20,
			0x66,0x75,0x74,0x75,0x72,0x65,0x2c,0x20,0x73,0x75,0x6e,0x73,
			0x63,0x72,0x65,0x65,0x6e,0x20,0x77,0x6f,0x75,0x6c,0x64,0x20,
			0x62,0x65,0x20,0x69,0x74,0x2e
		};
		const uint8_t expected_tag[16] = {
			0x1a,0xe1,0x0b,0x59,0x4f,0x09,0xe2,0x6a,0x7e,0x90,0x2e,0xcb,
			0xd0,0x60,0x06,0x91
		};
		const uint8_t expected_ct[] = {
			0xd3,0x1a,0x8d,0x34,0x64,0x8e,0x60,0xdb,0x7b,0x86,0xaf,0xbc,
			0x53,0xef,0x7e,0xc2,0xa4,0xad,0xed,0x51,0x29,0x6e,0x08,0xfe,
			0xa9,0xe2,0xb5,0xa7,0x36,0xee,0x62,0xd6,0x3d,0xbe,0xa4,0x5e,
			0x8c,0xa9,0x67,0x12,0x82,0xfa,0xfb,0x69,0xda,0x92,0x72,0x8b,
			0x1a,0x71,0xde,0x0a,0x9e,0x06,0x0b,0x29,0x05,0xd6,0xa5,0xb6,
			0x7e,0xcd,0x3b,0x36,0x92,0xdd,0xbd,0x7f,0x2d,0x77,0x8b,0x8c,
			0x98,0x03,0xae,0xe3,0x28,0x09,0x1b,0x58,0xfa,0xb3,0x24,0xe4,
			0xfa,0xd6,0x75,0x94,0x55,0x85,0x80,0x8b,0x48,0x31,0xd7,0xbc,
			0x3f,0xf4,0xde,0xf0,0x8e,0x4b,0x7a,0x9d,0xe5,0x76,0xd2,0x65,
			0x86,0xce,0xc6,0x4b,0x61,0x16
		};

		uint8_t ct[sizeof(plaintext)], tag[16], pt2[sizeof(plaintext)];
		int ret;
		ft_memset(ct, 0, sizeof(ct));
		ft_memset(tag, 0, sizeof(tag));

		ret = chacha20Poly1305Seal(key, nonce, aad, sizeof(aad),
								   plaintext, sizeof(plaintext), ct, tag);
		if (ret == 0 &&
			ft_memcmp(tag, expected_tag, 16) == 0 &&
			ft_memcmp(ct, expected_ct, sizeof(plaintext)) == 0) {
			passed++;
			printSuccess("RFC 7539 test vector 2 (AEAD seal with AAD)");
		} else {
			printFailure("RFC 7539 test vector 2 (AEAD seal with AAD)");
			ft_printf("Expected tag:\n"); hexDump(expected_tag, 16);
			ft_printf("Got tag:\n"); hexDump(tag, 16);
			ft_printf("Expected ciphertext:\n"); hexDump(expected_ct, sizeof(expected_ct));
			ft_printf("Got ciphertext:\n"); hexDump(ct, sizeof(ct));
		}
		total++;

		ft_memset(pt2, 0, sizeof(pt2));
		ret = chacha20Poly1305Open(key, nonce, aad, sizeof(aad),
								   ct, sizeof(ct), pt2, tag);
		if (ret == 0 && ft_memcmp(pt2, plaintext, sizeof(plaintext)) == 0) {
			passed++;
			printSuccess("RFC 7539 test vector 2 (AEAD open with AAD)");
		} else {
			printFailure("RFC 7539 test vector 2 (AEAD open with AAD)");
			ft_printf("Expected plaintext:\n"); hexDump(plaintext, sizeof(plaintext));
			ft_printf("Got plaintext:\n"); hexDump(pt2, sizeof(pt2));
			ft_printf("Expected tag:\n"); hexDump(expected_tag, 16);
			ft_printf("Got tag:\n"); hexDump(tag, 16);
			ft_printf("Expected ciphertext:\n"); hexDump(expected_ct, sizeof(expected_ct));
			ft_printf("Got ciphertext:\n"); hexDump(ct, sizeof(ct));
		}
		total++;
	}

	g_totalTests += total;
	g_passedTests += passed;
	return (passed == total);
}

int testChaCha20Poly1305Empty(void)
{
	int passed = 0, total = 0;
	printInfo("Testing ChaCha20-Poly1305 with empty inputs...");

	/* empty plaintext, empty AAD */
	{
		const uint8_t	key[32] = {0};
		const uint8_t	nonce[12] = {0};
		uint8_t			ciphertext[1], tag[16], plaintext[1];
		int				ret;

		ft_bzero(ciphertext, sizeof(ciphertext));
		ft_bzero(tag, sizeof(tag));
		ret = chacha20Poly1305Seal(key, nonce, NULL, 0, NULL, 0, ciphertext, tag);
		if (ret == 0) { passed++; printSuccess("empty plaintext, empty AAD (seal)"); }
		else printFailure("empty plaintext, empty AAD (seal)");
		total++;

		ft_bzero(plaintext, sizeof(plaintext));
		ret = chacha20Poly1305Open(key, nonce, NULL, 0, NULL, 0, plaintext, tag);
		if (ret == 0) { passed++; printSuccess("empty plaintext, empty AAD (open)"); }
		else printFailure("empty plaintext, empty AAD (open)");
		total++;
	}

	/* non-empty AAD, empty plaintext */
	{
		const uint8_t	key[32] = {0};
		const uint8_t	nonce[12] = {0};
		const uint8_t	aad[] = "some additional data";
		uint8_t			ciphertext[1], tag[16], plaintext[1];
		int				ret;

		ft_bzero(ciphertext, sizeof(ciphertext));
		ft_bzero(tag, sizeof(tag));
		ret = chacha20Poly1305Seal(key, nonce, aad, sizeof(aad)-1, NULL, 0, ciphertext, tag);
		if (ret == 0) { passed++; printSuccess("empty plaintext, non-empty AAD (seal)"); }
		else printFailure("empty plaintext, non-empty AAD (seal)");
		total++;

		ft_bzero(plaintext, sizeof(plaintext));
		ret = chacha20Poly1305Open(key, nonce, aad, sizeof(aad)-1, NULL, 0, plaintext, tag);
		if (ret == 0) { passed++; printSuccess("empty plaintext, non-empty AAD (open)"); }
		else printFailure("empty plaintext, non-empty AAD (open)");
		total++;
	}

	g_totalTests += total;
	g_passedTests += passed;
	return (passed == total);
}

int testChaCha20Poly1305Incremental(void)
{
	int passed = 0, total = 0;
	printInfo("Testing ChaCha20-Poly1305 incremental API...");

	const uint8_t key[32] = {
		0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
		0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
		0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
		0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
	};
	const uint8_t nonce[12] = {
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01
	};
	const uint8_t			aad[] = "Hello AAD";
	const uint8_t			plaintext[] = "Hello ChaCha20-Poly1305! This is a test message.";
	uint8_t					ctFull[sizeof(plaintext)], ctInc[sizeof(plaintext)];
	uint8_t					tagFull[16], tagInc[16], ptInc[sizeof(plaintext)];
	t_chacha20Poly1305Ctx	ctx;
	size_t					outLen, outTotal;
	int						ret;
	int						refOk = 0;

	/* 1. Generate reference with one-shot API */
	ft_bzero(ctFull, sizeof(ctFull));
	ft_bzero(tagFull, sizeof(tagFull));
	ret = chacha20Poly1305Seal(key, nonce, aad, sizeof(aad), plaintext, sizeof(plaintext), ctFull, tagFull);
	if (ret == 0) {
		refOk = 1;
		passed++;
		printSuccess("reference seal succeeded");
	} else
		printFailure("reference seal failed");
	total++;

	/* 2. Incremental encryption */
	if (refOk) {
		ret = chacha20Poly1305Init(&ctx, key, CHACHA20_KEY_SIZE, nonce, CIPHER_ENCRYPT);
		if (ret == 0) {
			chacha20Poly1305UpdateAAD(&ctx, aad, sizeof(aad));
			outTotal = 0;
			chacha20Poly1305Update(&ctx, plaintext, sizeof(plaintext), ctInc, &outLen);
			outTotal += outLen;
			chacha20Poly1305Final(&ctx, ctInc + outTotal, &outLen);
			ft_memcpy(tagInc, ctx.tag, 16);
			chacha20Poly1305Free(&ctx);

			if (ft_memcmp(ctFull, ctInc, sizeof(plaintext)) == 0 &&
				ft_memcmp(tagFull, tagInc, 16) == 0) {
				passed++;
				printSuccess("incremental encryption matches one-shot");
			} else {
				printFailure("incremental encryption matches one-shot");
			}
		} else
			printFailure("incremental encryption init failed");
	} else
		printFailure("incremental encryption skipped (no reference)");
	total++;

	/* 3. Incremental decryption */
	if (refOk) {
		ret = chacha20Poly1305Init(&ctx, key, CHACHA20_KEY_SIZE, nonce, CIPHER_DECRYPT);
		if (ret == 0) {
			chacha20Poly1305UpdateAAD(&ctx, aad, sizeof(aad));
			outTotal = 0;
			chacha20Poly1305Update(&ctx, ctFull, sizeof(plaintext), ptInc, &outLen);
			outTotal += outLen;
			chacha20Poly1305Final(&ctx, ptInc + outTotal, &outLen);
			outTotal += outLen;
			ret = chacha20Poly1305VerifyTag(&ctx, tagFull, 16);
			chacha20Poly1305Free(&ctx);

			if (ret == 0 && ft_memcmp(ptInc, plaintext, sizeof(plaintext)) == 0) {
				passed++;
				printSuccess("incremental decryption matches one-shot");
			} else
				printFailure("incremental decryption matches one-shot");
		} else
			printFailure("incremental decryption init failed");
	} else
		printFailure("incremental decryption skipped (no reference)");
	total++;

	g_totalTests += total;
	g_passedTests += passed;
	return (passed == total);
}

int testChaCha20Poly1305BadTag(void)
{
	int passed = 0, total = 0;
	printInfo("Testing ChaCha20-Poly1305 with bad tags...");

	const uint8_t	key[32] = {0};
	const uint8_t	nonce[12] = {0};
	const uint8_t	aad[] = "test";
	const uint8_t	plaintext[] = "secret message";
	uint8_t			ct[sizeof(plaintext)], tag[16], pt2[sizeof(plaintext)], badTag[16];
	int				ret;
	int				sealOk = 0;

	/* 1. Generate valid ciphertext and tag */
	ret = chacha20Poly1305Seal(key, nonce, aad, sizeof(aad)-1, plaintext, sizeof(plaintext)-1, ct, tag);
	if (ret == 0) {
		sealOk = 1;
		passed++;
		printSuccess("reference seal succeeded");
	} else
		printFailure("reference seal failed");
	total++;

	/* 2. Bad tag rejection */
	if (sealOk) {
		ft_memcpy(badTag, tag, 16);
		badTag[0] ^= 0xFF;
		ft_bzero(pt2, sizeof(pt2));
		ret = chacha20Poly1305Open(key, nonce, aad, sizeof(aad)-1, ct, sizeof(plaintext)-1, pt2, badTag);
		if (ret == -1) {
			passed++;
			printSuccess("bad tag rejected");
		} else
			printFailure("bad tag not rejected");
	} else
		printFailure("bad tag test skipped (no reference)");
	total++;

	/* 3. Plaintext zeroed after bad tag */
	if (sealOk) {
		int zero_ok = 1;
		for (size_t i = 0; i < sizeof(plaintext)-1; i++) {
			if (pt2[i] != 0) { zero_ok = 0; break; }
		}
		if (zero_ok) {
			passed++;
			printSuccess("plaintext zeroed after bad tag");
		} else
			printFailure("plaintext not zeroed after bad tag");
	} else
		printFailure("plaintext zeroing test skipped (no reference)");
	total++;

	/* 4. Correct tag accepted */
	if (sealOk) {
		ft_bzero(pt2, sizeof(pt2));
		ret = chacha20Poly1305Open(key, nonce, aad, sizeof(aad)-1, ct, sizeof(plaintext)-1, pt2, tag);
		if (ret == 0 && ft_memcmp(pt2, plaintext, sizeof(plaintext)-1) == 0) {
			passed++;
			printSuccess("correct tag accepted");
		} else
			printFailure("correct tag rejected");
	} else
		printFailure("correct tag test skipped (no reference)");
	total++;

	g_totalTests += total;
	g_passedTests += passed;
	return (passed == total);
}

int testChaCha20Poly1305TamperedCiphertext(void)
{
	int passed = 0, total = 0;
	printInfo("Testing ChaCha20-Poly1305 with tampered ciphertext...");

	const uint8_t	key[32] = {0};
	const uint8_t	nonce[12] = {0};
	const uint8_t	aad[] = "test";
	const uint8_t	plaintext[] = "secret message";
	uint8_t			ct[sizeof(plaintext)], tag[16], pt2[sizeof(plaintext)];
	int				ret;
	int				sealOk = 0;

	/* 1. Reference seal */
	ret = chacha20Poly1305Seal(key, nonce, aad, sizeof(aad), plaintext, sizeof(plaintext), ct, tag);
	if (ret == 0) {
		sealOk = 1;
		passed++;
		printSuccess("reference seal succeeded");
	} else
		printFailure("reference seal failed");
	total++;

	/* 2. Tampered ciphertext rejection */
	if (sealOk) {
		ct[5] ^= 0xFF;
		ft_bzero(pt2, sizeof(pt2));
		ret = chacha20Poly1305Open(key, nonce, aad, sizeof(aad), ct, sizeof(ct), pt2, tag);
		if (ret == -1) {
			passed++;
			printSuccess("tampered ciphertext rejected");
		} else
			printFailure("tampered ciphertext not rejected");
	} else
		printFailure("tampered ciphertext test skipped (no reference)");
	total++;

	g_totalTests += total;
	g_passedTests += passed;
	return (passed == total);
}

int testChaCha20Poly1305TamperedAAD(void)
{
	int passed = 0, total = 0;
	printInfo("Testing ChaCha20-Poly1305 with tampered AAD...");

	const uint8_t	key[32] = {0};
	const uint8_t	nonce[12] = {0};
	const uint8_t	aad[] = "original AAD";
	const uint8_t	bad_aad[] = "tampered AAD";
	const uint8_t	plaintext[] = "secret message";
	uint8_t			ct[sizeof(plaintext)], tag[16], pt2[sizeof(plaintext)];
	int				ret;
	int				sealOk = 0;

	/* 1. Reference seal */
	ret = chacha20Poly1305Seal(key, nonce, aad, sizeof(aad), plaintext, sizeof(plaintext), ct, tag);
	if (ret == 0) {
		sealOk = 1;
		passed++;
		printSuccess("reference seal succeeded");
	} else
		printFailure("reference seal failed");
	total++;

	/* 2. Tampered AAD rejection */
	if (sealOk) {
		ft_bzero(pt2, sizeof(pt2));
		ret = chacha20Poly1305Open(key, nonce, bad_aad, sizeof(bad_aad), ct, sizeof(ct), pt2, tag);
		if (ret == -1) {
			passed++;
			printSuccess("tampered AAD rejected");
		} else
			printFailure("tampered AAD not rejected");
	} else
		printFailure("tampered AAD test skipped (no reference)");
	total++;

	g_totalTests += total;
	g_passedTests += passed;
	return (passed == total);
}

int testChaCha20Poly1305DifferentNonce(void)
{
	int passed = 0, total = 0;
	printInfo("Testing ChaCha20-Poly1305 with different nonces...");

	const uint8_t	key[32] = {0};
	const uint8_t	nonce1[12] = {0};
	const uint8_t	nonce2[12] = {0,0,0,0,0,0,0,0,0,0,0,1};
	const uint8_t	aad[] = "test";
	const uint8_t	plaintext[] = "secret message";
	uint8_t			ct1[sizeof(plaintext)], ct2[sizeof(plaintext)];
	uint8_t			tag1[16], tag2[16];
	int				ret, ok1 = 0, ok2 = 0;

	/* Encrypt with nonce1 */
	ret = chacha20Poly1305Seal(key, nonce1, aad, sizeof(aad), plaintext, sizeof(plaintext), ct1, tag1);
	if (ret == 0) { ok1 = 1; passed++; printSuccess("seal with nonce1 succeeded"); }
	else printFailure("seal with nonce1 failed");
	total++;

	/* Encrypt with nonce2 */
	ret = chacha20Poly1305Seal(key, nonce2, aad, sizeof(aad), plaintext, sizeof(plaintext), ct2, tag2);
	if (ret == 0) { ok2 = 1; passed++; printSuccess("seal with nonce2 succeeded"); }
	else printFailure("seal with nonce2 failed");
	total++;

	/* Compare outputs */
	if (ok1 && ok2) {
		if (ft_memcmp(ct1, ct2, sizeof(plaintext)) != 0 ||
			ft_memcmp(tag1, tag2, 16) != 0) {
			passed++;
			printSuccess("different nonces produce different outputs");
		} else
			printFailure("different nonces produced same output");
	} else
		printFailure("nonce comparison skipped (seal failed)");
	total++;

	g_totalTests += total;
	g_passedTests += passed;
	return (passed == total);
}

int testChaCha20Poly1305PartialBlocks(void)
{
	int passed = 0, total = 0;
	printInfo("Testing ChaCha20-Poly1305 with partial block updates...");

	const uint8_t			key[32] = {0};
	const uint8_t			nonce[12] = {0};
	const uint8_t			aad[] =			"test AAD that is longer than one block";
	const uint8_t			plaintext[] =	"This is a long message that spans multiple "
											"blocks of 16 bytes each for ChaCha20-Poly1305 testing purposes.";
	uint8_t					ctFull[sizeof(plaintext)], ctPartial[sizeof(plaintext)];
	uint8_t					tagFull[16], tagPartial[16], ptPartial[sizeof(plaintext)];
	t_chacha20Poly1305Ctx	ctx;
	size_t					outLen, outTotal, i;
	int						ret;
	int						refOk = 0;

	/* 1. Full one-shot encryption */
	ret = chacha20Poly1305Seal(key, nonce, aad, sizeof(aad)-1, plaintext, sizeof(plaintext)-1, ctFull, tagFull);
	if (ret == 0) {
		refOk = 1;
		passed++;
		printSuccess("reference seal succeeded");
	} else
		printFailure("reference seal failed");
	total++;

	/* 2. Byte-by-byte encryption */
	if (refOk) {
		ret = chacha20Poly1305Init(&ctx, key, CHACHA20_KEY_SIZE, nonce, CIPHER_ENCRYPT);
		if (ret == 0) {
			for (i = 0; i < sizeof(aad)-1; i++)
				chacha20Poly1305UpdateAAD(&ctx, aad + i, 1);
			outTotal = 0;
			for (i = 0; i < sizeof(plaintext)-1; i++) {
				chacha20Poly1305Update(&ctx, plaintext + i, 1, ctPartial + outTotal, &outLen);
				outTotal += outLen;
			}
			chacha20Poly1305Final(&ctx, ctPartial + outTotal, &outLen);
			ft_memcpy(tagPartial, ctx.tag, 16);
			chacha20Poly1305Free(&ctx);

			if (ft_memcmp(ctFull, ctPartial, sizeof(plaintext)-1) == 0 &&
				ft_memcmp(tagFull, tagPartial, 16) == 0) {
				passed++;
				printSuccess("byte-by-byte updates produce correct result");
			} else
				printFailure("byte-by-byte updates produce correct result");
		} else
			printFailure("incremental encryption init failed");
	} else
		printFailure("byte-by-byte encryption skipped (no reference)");
	total++;

	/* 3. Byte-by-byte decryption */
	if (refOk) {
		ret = chacha20Poly1305Init(&ctx, key, CHACHA20_KEY_SIZE, nonce, CIPHER_DECRYPT);
		if (ret == 0) {
			for (i = 0; i < sizeof(aad)-1; i++)
				chacha20Poly1305UpdateAAD(&ctx, aad + i, 1);
			outTotal = 0;
			for (i = 0; i < sizeof(plaintext)-1; i++) {
				chacha20Poly1305Update(&ctx, ctFull + i, 1, ptPartial + outTotal, &outLen);
				outTotal += outLen;
			}
			chacha20Poly1305Final(&ctx, ptPartial + outTotal, &outLen);
			outTotal += outLen;
			ret = chacha20Poly1305VerifyTag(&ctx, tagFull, 16);
			chacha20Poly1305Free(&ctx);

			if (ret == 0 && ft_memcmp(ptPartial, plaintext, sizeof(plaintext)-1) == 0) {
				passed++;
				printSuccess("byte-by-byte decryption works");
			} else
				printFailure("byte-by-byte decryption works");
		} else
			printFailure("incremental decryption init failed");
	} else
		printFailure("byte-by-byte decryption skipped (no reference)");
	total++;

	g_totalTests += total;
	g_passedTests += passed;
	return (passed == total);
}
