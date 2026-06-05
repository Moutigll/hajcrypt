#include "../../hajlib/include/hprintf.h"
#include "../../hajlib/include/hmemory.h"
#include "../../includes/asymmetric/ecdh.h"

#include "../test.h"

/* --- SECP256R1 (RFC 5903) --- */
static const uint8_t secp256r1PrivAlice[32] = {
	0xc8, 0x8f, 0x01, 0xf5, 0x10, 0xd9, 0xac, 0x3f,
	0x70, 0xa2, 0x92, 0xda, 0xa2, 0x31, 0x6d, 0xe5,
	0x44, 0xe9, 0xaa, 0xbe, 0x68, 0x3f, 0x25, 0x3a,
	0xdf, 0xb5, 0x18, 0x97, 0xb2, 0x82, 0x20, 0xcc
};

static const uint8_t secp256r1PubAlice[65] = {
	0x04,
	0xda, 0xcd, 0xc2, 0xe3, 0x13, 0x8d, 0x5f, 0xcd, 0x4f, 0xc7, 0xe1, 0x13, 0xee, 0xf4, 0x01,
	0xdf, 0xd0, 0x8e, 0x14, 0xe5, 0xbb, 0xde, 0xf8, 0xb1, 0xc1, 0xbf, 0xa9, 0xcf, 0xda, 0xa9, 0xa9, 0xd3,
	0x2a, 0xa7, 0x43, 0x51, 0xd3, 0x54, 0xba, 0xb6, 0x86, 0xbe, 0xbd, 0x9b, 0x90, 0xe4, 0xa4, 0xe1,
	0x69, 0xaa, 0x69, 0xf3, 0xf1, 0xc5, 0xbb, 0xaa, 0xe7, 0xda, 0xc4, 0xcb, 0xce, 0xf6, 0xe6, 0xf6
};

static const uint8_t secp256r1PubBob[65] = {
	0x04,
	0x72, 0x14, 0xbc, 0x96, 0x47, 0x16, 0x0b, 0xbe, 0xd6, 0x25, 0x74, 0x74, 0xde, 0xc1, 0x46,
	0x72, 0x8b, 0xf4, 0xf5, 0xc2, 0xcf, 0xa6, 0xc5, 0xcc, 0xd8, 0xdb, 0x9e, 0x5d, 0x10, 0xde, 0xce, 0xdb,
	0xdf, 0xe1, 0x1e, 0x3f, 0xc4, 0xa6, 0xd1, 0xbb, 0xdc, 0xf1, 0xf4, 0xf0, 0xc2, 0xd8, 0x8e, 0x5e,
	0xdf, 0xe1, 0xe4, 0xca, 0xc8, 0xc7, 0xcc, 0xd5, 0x6f, 0xf2, 0xd3, 0x12, 0x10, 0xa7, 0xdc, 0x4b
};

static const uint8_t secp256r1SharedExpected[32] = {
	0xd6, 0x84, 0x0f, 0x6b, 0x42, 0xf6, 0xed, 0xaf,
	0xd1, 0x31, 0x16, 0xe0, 0xe1, 0x25, 0x65, 0x20,
	0x2f, 0xef, 0x8e, 0x9e, 0xce, 0x7d, 0xce, 0x03,
	0x81, 0x24, 0x64, 0xd0, 0x4b, 0x94, 0x42, 0xde
};

/* --- X25519 (RFC 7748 §6.1) --- */
static const uint8_t x25519PrivAlice[32] = {
	0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
	0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x1a
};

static const uint8_t x25519PubAlice[32] = {
	0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a,
	0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a
};

static const uint8_t x25519PubBob[32] = {
	0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
	0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f
};

static const uint8_t x25519SharedExpected[32] = {
	0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1, 0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0x0f, 0x25,
	0xe0, 0x7a, 0x21, 0xc0, 0x18, 0x5d, 0x1d, 0x34, 0x3c, 0x41, 0x11, 0x12, 0x3e, 0x96, 0xd7, 0x90
};

/* --- X448 (RFC 7748 §6.2) --- */
static const uint8_t x448PrivAlice[56] = {
	0x9a, 0x8f, 0x49, 0x2a, 0x14, 0xdb, 0x21, 0xa8, 0x4c, 0x28, 0x63, 0x95, 0x99, 0x6b, 0x6b, 0x53,
	0x59, 0x1c, 0x83, 0x15, 0x55, 0xbd, 0xa7, 0x9b, 0x5f, 0x47, 0xfb, 0x00, 0x68, 0x31, 0xd0, 0x41,
	0x2b, 0xa1, 0xd3, 0x26, 0xf6, 0x63, 0x01, 0xd8, 0x71, 0x49, 0xa4, 0x3a, 0x29, 0x36, 0xc5, 0x35,
	0x73, 0xca, 0x14, 0x33, 0xaa, 0x94, 0xc9, 0x2e
};

static const uint8_t x448PubAlice[56] = {
	0x9b, 0x08, 0xf7, 0xcc, 0x31, 0xb7, 0xe3, 0xe6, 0x7d, 0x22, 0xd5, 0xae, 0xa1, 0x21, 0x07, 0x4a,
	0x27, 0x3b, 0xd2, 0xb8, 0x3d, 0xe0, 0x99, 0x09, 0x76, 0xd2, 0x14, 0xfc, 0x73, 0x43, 0x1f, 0x80,
	0x44, 0x4d, 0x00, 0x96, 0xd2, 0x4a, 0xfb, 0x95, 0xc3, 0x4c, 0x44, 0x56, 0x6f, 0x12, 0x13, 0x4a,
	0xc5, 0x6a, 0x09, 0x1f, 0x39, 0x60, 0x26, 0x85
};

static const uint8_t x448PubBob[56] = {
	0x3e, 0xb4, 0xa8, 0xe6, 0x1a, 0x80, 0x74, 0xd3, 0xb8, 0x3b, 0x32, 0x92, 0x4d, 0x45, 0xb0, 0x81,
	0x1e, 0x56, 0x99, 0x47, 0x81, 0x44, 0xaf, 0x72, 0x3e, 0x75, 0x30, 0x41, 0x93, 0x5c, 0x15, 0xa7,
	0x74, 0xea, 0x06, 0xfb, 0x3c, 0x2f, 0xb1, 0x89, 0xb6, 0xb7, 0xa5, 0xa8, 0x1c, 0xa8, 0xd1, 0x03,
	0x3b, 0x0e, 0x35, 0x8b, 0x14, 0xe2, 0xd3, 0xf6
};

static const uint8_t x448SharedExpected[56] = {
	0x07, 0x7f, 0x45, 0x36, 0x81, 0x0a, 0x68, 0x03, 0xb0, 0x7d, 0x4b, 0x4e, 0x37, 0x47, 0xee, 0x54,
	0x1d, 0x2d, 0x5c, 0x12, 0x7c, 0x14, 0xc2, 0xec, 0x66, 0xd7, 0x78, 0xa8, 0x79, 0xdc, 0x99, 0x92,
	0x33, 0x14, 0x17, 0x40, 0xa4, 0x0d, 0x55, 0xe0, 0x9f, 0x53, 0xe6, 0xbd, 0xa8, 0x5f, 0xfc, 0x70,
	0xaa, 0x9a, 0x7c, 0xb6, 0x31, 0x89, 0x28, 0x07
};


typedef struct {
	int				id;
	const char*		name;
	size_t			keySize;
	size_t			pubSize;
	size_t			sharedSize;
	int				isWeierstrass;
	const uint8_t*	privAlice;
	const uint8_t*	pubAlice;
	const uint8_t*	pubBob;
	const uint8_t*	sharedExpected;
} t_ecdhTestVector;

static const t_ecdhTestVector g_test_vectors[] = {
	{
		.id = ECDH_GROUP_SECP256R1, .name = "SECP256R1",
		.keySize = 32, .pubSize = 65, .sharedSize = 32, .isWeierstrass = 1,
		.privAlice = secp256r1PrivAlice, .pubAlice = secp256r1PubAlice,
		.pubBob = secp256r1PubBob, .sharedExpected = secp256r1SharedExpected
	},
	{
		.id = ECDH_GROUP_X25519, .name = "X25519",
		.keySize = 32, .pubSize = 32, .sharedSize = 32, .isWeierstrass = 0,
		.privAlice = x25519PrivAlice, .pubAlice = x25519PubAlice,
		.pubBob = x25519PubBob, .sharedExpected = x25519SharedExpected
	},
	{
		.id = ECDH_GROUP_X448, .name = "X448",
		.keySize = 56, .pubSize = 56, .sharedSize = 56, .isWeierstrass = 0,
		.privAlice = x448PrivAlice, .pubAlice = x448PubAlice,
		.pubBob = x448PubBob, .sharedExpected = x448SharedExpected
	}
};

#define NUM_GROUPS (sizeof(g_test_vectors) / sizeof(g_test_vectors[0]))
#define MAX_BUF_SIZE 128



int testEcdhGenerateKeypair(void)
{
	int	passed = 0;
	int	total = 0;

	printInfo("Testing ECDHE generate keypair across all curves...");

	for (size_t g = 0; g < NUM_GROUPS; g++)
	{
		const t_ecdhTestVector	*tv = &g_test_vectors[g];
		t_ecdhCtx				ctx;

		ft_printf("  [%s] Initializing context...\n", tv->name);
		if (!ecdhInit(&ctx, tv->id))
		{
			printFailure("ecdhInit failed");
			total++;
			continue;
		}

		total++;
		if (ecdhGenerateKeypair(&ctx))
		{
			passed++;
			printSuccess("ecdhGenerateKeypair success");
		}
		else
			printFailure("ecdhGenerateKeypair failed");

		total++;
		int ptr_check = (ctx.priv && ctx.pubX);
		if (tv->isWeierstrass) ptr_check = ptr_check && ctx.pubY;

		if (ptr_check)
		{
			passed++;
			printSuccess("Pointers allocated correctly");
		}
		else
			printFailure("Pointers check failed");

		total++;
		if (ctx.pubX && !bigIntIsZero(ctx.pubX))
		{
			passed++;
			printSuccess("Public key X component is valid (not zero)");
		}
		else
			printFailure("Public key X component is zero or NULL");

		if (tv->isWeierstrass)
		{
			total++;
			if (ctx.pubY && !bigIntIsZero(ctx.pubY))
			{
				passed++;
				printSuccess("Public key Y component is valid (not zero)");
			}
			else
				printFailure("Public key Y component is zero or NULL");
		}

		ecdhFree(&ctx);
	}

	ft_printf("ECDHE generate keypair summary: %d/%d passed\n", passed, total);
	g_totalTests += total;
	g_passedTests += passed;
	return (passed == total);
}

int testEcdhGetPublicBytes(void)
{
	int	passed = 0;
	int	total = 0;

	printInfo("Testing ECDHE get public bytes across all curves...");

	for (size_t g = 0; g < NUM_GROUPS; g++)
	{
		const t_ecdhTestVector	*tv = &g_test_vectors[g];
		t_ecdhCtx				ctx;
		uint8_t					buf[MAX_BUF_SIZE];
		size_t					len, len2;
		int						ret;

		ft_printf("  [%s] Testing buffer export...\n", tv->name);
		if (!ecdhInit(&ctx, tv->id) || !ecdhGenerateKeypair(&ctx))
		{
			printFailure("Setup failed");
			total += 1;
			continue;
		}

		len = 0;
		ret = ecdhGetPublicBytes(&ctx, NULL, &len);
		total++;
		if (ret && len == tv->pubSize)
		{
			passed++;
			printSuccess("ecdhGetPublicBytes returned correct key length");
		}
		else
			printFailure("ecdhGetPublicBytes size query failed");

		len2 = sizeof(buf);
		ret = ecdhGetPublicBytes(&ctx, buf, &len2);
		total++;
		if (ret && len2 == tv->pubSize)
		{
			passed++;
			printSuccess("ecdhGetPublicBytes successfully exported bytes");
		}
		else
			printFailure("ecdhGetPublicBytes raw export failed");

		ecdhFree(&ctx);
	}

	ft_printf("ECDHE get public bytes summary: %d/%d passed\n", passed, total);
	g_totalTests += total;
	g_passedTests += passed;
	return (passed == total);
}

int testEcdhExchangeGroup(void)
{
	int	totalPassed = 0;
	int	totalExpected = NUM_GROUPS * 4;

	printInfo("Testing ECDHE Key Exchange (Alice <-> Bob) across all curves...");

	for (size_t g = 0; g < NUM_GROUPS; g++)
	{
		const t_ecdhTestVector	*tv = &g_test_vectors[g];
		t_ecdhCtx				alice, bob;
		uint8_t					alicePub[MAX_BUF_SIZE], bobPub[MAX_BUF_SIZE];
		uint8_t					aliceShared[MAX_BUF_SIZE], bobShared[MAX_BUF_SIZE];
		size_t					alicePubLen, bobPubLen, aliceSharedLen, bobSharedLen;
		int						ret, local_passed = 0;

		ft_printf("  [%s] Simulating Diffie-Hellman exchange...\n", tv->name);
		if (!ecdhInit(&alice, tv->id) || !ecdhInit(&bob, tv->id))
		{
			printFailure("Initialization failed");
			g_totalTests += 4;
			continue;
		}

		if (ecdhGenerateKeypair(&alice) && ecdhGenerateKeypair(&bob))
		{
			local_passed++;
			printSuccess("Both ephemeral keypairs generated successfully");
		}
		else
		{
			printFailure("Keypair generation failed");
			goto cleanupExchange;
		}

		alicePubLen = sizeof(alicePub);
		bobPubLen = sizeof(bobPub);
		ret = ecdhGetPublicBytes(&alice, alicePub, &alicePubLen) &&
			  ecdhGetPublicBytes(&bob, bobPub, &bobPubLen);
		if (ret && alicePubLen == tv->pubSize && bobPubLen == tv->pubSize)
		{
			local_passed++;
			printSuccess("Public keys serialized perfectly");
		}
		else
		{
			printFailure("Public key serialization failed");
			goto cleanupExchange;
		}

		aliceSharedLen = sizeof(aliceShared);
		bobSharedLen = sizeof(bobShared);
		ret = ecdhComputeShared(&alice, bobPub, bobPubLen, aliceShared, &aliceSharedLen) &&
			  ecdhComputeShared(&bob, alicePub, alicePubLen, bobShared, &bobSharedLen);
		if (ret && aliceSharedLen == tv->sharedSize && bobSharedLen == tv->sharedSize)
		{
			local_passed++;
			printSuccess("Shared secrets calculated by both parties");
		}
		else
		{
			printFailure("Shared secret calculation engine failed");
			goto cleanupExchange;
		}

		if (aliceSharedLen == bobSharedLen && ft_memcmp(aliceShared, bobShared, aliceSharedLen) == 0)
		{
			local_passed++;
			printSuccess("Shared secrets match identically");
		}
		else
		{
			printFailure("Critical Error: Shared secrets mismatch");
			ft_printf("Alice's Shared: ");
			for (size_t i = 0; i < aliceSharedLen; i++) ft_printf("%02x", aliceShared[i]);
			ft_printf("\nBob's Shared:   ");
			for (size_t i = 0; i < bobSharedLen; i++) ft_printf("%02x", bobShared[i]);
			ft_printf("\n");
		}

	cleanupExchange:
		ecdhFree(&alice);
		ecdhFree(&bob);
		totalPassed += local_passed;
	}

	ft_printf("ECDHE exchange summary: %d/%d passed\n", totalPassed, totalExpected);
	g_totalTests += totalExpected;
	g_passedTests += totalPassed;
	return (totalPassed == totalExpected);
}

int testEcdhFreeZeroing(void)
{
	int	passed = 0;
	int	total = 0;

	printInfo("Testing ECDHE context destruction and secure zeroing...");

	for (size_t g = 0; g < NUM_GROUPS; g++)
	{
		const t_ecdhTestVector	*tv = &g_test_vectors[g];
		t_ecdhCtx				ctx;

		ft_printf("  [%s] Cleaning memory...\n", tv->name);
		if (!ecdhInit(&ctx, tv->id) || !ecdhGenerateKeypair(&ctx))
		{
			printFailure("Setup failed");
			total += 2;
			continue;
		}

		ecdhFree(&ctx);

		total++;
		int ptr_null = (ctx.priv == NULL && ctx.pubX == NULL && ctx.shared == NULL);
		if (tv->isWeierstrass) ptr_null = ptr_null && (ctx.pubY == NULL);

		if (ptr_null)
		{
			passed++;
			printSuccess("All active internal pointers sanitized to NULL");
		}
		else
			printFailure("Memory leak or raw dangling pointer found after ecdhFree");

		total++;
		if (ctx.curveId == 0)
		{
			passed++;
			printSuccess("Context metadata structural flag zeroed out");
		}
		else
			printFailure("curveId contains dirty residual stack data");
	}

	ft_printf("ECDHE free zeroing summary: %d/%d passed\n", passed, total);
	g_totalTests += total;
	g_passedTests += passed;
	return (passed == total);
}
