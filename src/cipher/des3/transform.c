#include "../../../includes/cipher/des.h"

#include "../../../includes/cipher/des3.h"

void des3GenerateSubkeys(const uint8_t	key24[24],
						 uint64_t		subkeys1[16],
						 uint64_t		subkeys2[16],
						 uint64_t		subkeys3[16])
{
	uint64_t k1 = 0, k2 = 0, k3 = 0;

	for (int i = 0; i < 8; i++) {
		k1 = (k1 << 8) | key24[i];
		k2 = (k2 << 8) | key24[8 + i];
		k3 = (k3 << 8) | key24[16 + i];
	}

	desGenerateSubkeys(k1, subkeys1);
	desGenerateSubkeys(k2, subkeys2);
	desGenerateSubkeys(k3, subkeys3);
}

uint64_t des3EncryptBlock(uint64_t			block,
						  const uint64_t	subkeys1[16],
						  const uint64_t	subkeys2[16],
						  const uint64_t	subkeys3[16])
{
	block = desEncryptBlock(block, subkeys1);   /* E(K1) */
	block = desDecryptBlock(block, subkeys2);   /* D(K2) */
	block = desEncryptBlock(block, subkeys3);   /* E(K3) */

	return (block);
}

uint64_t des3DecryptBlock(uint64_t block,
						  const uint64_t subkeys1[16],
						  const uint64_t subkeys2[16],
						  const uint64_t subkeys3[16])
{
	block = desDecryptBlock(block, subkeys1);   /* D(K1) */
	block = desEncryptBlock(block, subkeys2);   /* E(K2) */
	block = desDecryptBlock(block, subkeys3);   /* D(K3) */
	return (block);
}
