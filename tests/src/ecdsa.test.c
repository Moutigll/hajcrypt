#include <stdlib.h>

#include "../../hajlib/include/hprintf.h"
#include "../../hajlib/include/hmemory.h"
#include "../../includes/asymmetric/ecdsa.h"

#include "../test.h"

/* Hash SHA-256 "Hello, world!" */
static const uint8_t ecdsaHash[] = {
	0x31, 0x5b, 0xf5, 0xeb, 0xc5, 0x7d, 0x4f, 0xda,
	0xbc, 0xc5, 0xea, 0xba, 0x07, 0xd5, 0x3f, 0x6b,
	0x37, 0x6b, 0x6b, 0x01, 0x7a, 0x14, 0x79, 0x63,
	0x9b, 0xbb, 0x8b, 0x25, 0xe5, 0x54, 0x52, 0x94
};


int testEcdsaGenerateKeypair(void)
{
	int			passed = 0, total = 0;
	t_ecdsaKey	key;
	
	printInfo("Testing ECDSA generate keypair...");
	
	if (!ecdsaGenerateKey(&key, ECDH_GROUP_SECP256R1))
	{
		printFailure("ecdsaGenerateKey failed");
		g_totalTests += 1;
		return (0);
	}
	
	total++;
	if (key.priv && key.pubX && key.pubY)
	{
		passed++;
		printSuccess("priv, pubX, pubY not NULL");
	}
	else
		printFailure("priv, pubX, or pubY is NULL");
	
	total++;
	if (!bigIntIsZero(key.pubX) && !bigIntIsZero(key.pubY))
	{
		passed++;
		printSuccess("public key not zero");
	}
	else
		printFailure("public key is zero");
	
	ecdsaFreeKey(&key);
	
	ft_printf("ECDSA generate keypair: %d/%d passed\n", passed, total);
	g_totalTests += total;
	g_passedTests += passed;
	return (passed == total);
}

int testEcdsaSignAndVerify(void)
{
	int passed = 0, total = 0;
	t_ecdsaKey key;
	uint8_t sig[128];
	size_t sigLen = sizeof(sig);
	
	printInfo("Testing ECDSA sign and verify...");

	if (!ecdsaGenerateKey(&key, ECDH_GROUP_SECP256R1))
	{
		printFailure("ecdsaGenerateKey failed");
		g_totalTests += 1;
		return (0);
	}

	total++;
	if (ecdsaSign(ecdsaHash, sizeof(ecdsaHash), NULL, &key, sig, &sigLen, PKEY_PADDING_NONE))
	{
		passed++;
		printSuccess("ecdsaSign success");
	}
	else
	{
		printFailure("ecdsaSign failed");
		ecdsaFreeKey(&key);
		g_totalTests += total;
		g_passedTests += passed;
		return (passed == total);
	}

	total++;
	if (ecdsaVerify(ecdsaHash, sizeof(ecdsaHash), NULL, &key, sig, sigLen, PKEY_PADDING_NONE))
	{
		passed++;
		printSuccess("ecdsaVerify success");
	}
	else
		printFailure("ecdsaVerify failed");

	if (sigLen > 0)
	{
		uint8_t *tampered = malloc(sigLen);
		if (tampered)
		{
			ft_memcpy(tampered, sig, sigLen);
			tampered[sigLen / 2] ^= 0xFF;
			
			total++;
			if (!ecdsaVerify(ecdsaHash, sizeof(ecdsaHash), NULL, &key, tampered, sigLen, PKEY_PADDING_NONE))
			{
				passed++;
				printSuccess("Tampered signature rejected");
			}
			else
				printFailure("Tampered signature accepted");
			
			free(tampered);
		}
	}
	
	ecdsaFreeKey(&key);
	
	ft_printf("ECDSA sign and verify: %d/%d passed\n", passed, total);
	g_totalTests += total;
	g_passedTests += passed;
	return (passed == total);
}

int testEcdsaRoundtrip(void)
{
	int			passed = 0, total = 0;
	t_ecdsaKey	alice;
	t_ecdsaKey	bob;
	uint8_t		sig[128];
	size_t		sigLen = sizeof(sig);
	uint8_t		pubKeyBytes[65];
	size_t		pubKeyLen = sizeof(pubKeyBytes);

	printInfo("Testing ECDSA roundtrip (generate -> sign -> verify)...");

	if (!ecdsaGenerateKey(&alice, ECDH_GROUP_SECP256R1))
	{
		printFailure("Alice generate key failed");
		g_totalTests += 1;
		return (0);
	}

	if (!ecdhGetPublicBytes(&alice, pubKeyBytes, &pubKeyLen))
	{
		printFailure("Alice get public bytes failed");
		ecdsaFreeKey(&alice);
		g_totalTests += 1;
		return (0);
	}

	if (pubKeyLen < 65 || pubKeyBytes[0] != 0x04)
	{
		printFailure("Unexpected public key format");
		ecdsaFreeKey(&alice);
		g_totalTests += 1;
		return (0);
	}

	const uint8_t *pubX = pubKeyBytes + 1;
	const uint8_t *pubY = pubKeyBytes + 1 + 32;

	ft_memset(&bob, 0, sizeof(bob));
	if (!ecdsaSetPublicKey(&bob, ECDH_GROUP_SECP256R1, pubX, 32, pubY, 32))
	{
		printFailure("Bob set public key failed");
		ecdsaFreeKey(&alice);
		g_totalTests += 1;
		return (0);
	}

	total++;
	if (ecdsaSign(ecdsaHash, sizeof(ecdsaHash), NULL, &alice, sig, &sigLen, PKEY_PADDING_NONE))
	{
		passed++;
		printSuccess("Alice signed the message");
	}
	else
	{
		printFailure("Alice signature failed");
		ecdsaFreeKey(&alice);
		ecdsaFreeKey(&bob);
		g_totalTests += total;
		g_passedTests += passed;
		return (passed == total);
	}

	total++;
	if (ecdsaVerify(ecdsaHash, sizeof(ecdsaHash), NULL, &bob, sig, sigLen, PKEY_PADDING_NONE))
	{
		passed++;
		printSuccess("Bob verified the signature (using extracted public key)");
	}
	else
		printFailure("Bob verification failed");

	ecdsaFreeKey(&alice);
	ecdsaFreeKey(&bob);

	ft_printf("ECDSA roundtrip: %d/%d passed\n", passed, total);
	g_totalTests += total;
	g_passedTests += passed;
	return (passed == total);
}
