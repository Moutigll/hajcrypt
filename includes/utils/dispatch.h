#ifndef HAJCRYPT_DISPATCH_H
#define HAJCRYPT_DISPATCH_H

#include <stddef.h>
#include <stdint.h>

#include "../hash/hmac.h"
#include "../hash/hash.h"
#include "../cipher/cipher.h"
#include "../asymmetric/pkeyPem.h"

typedef enum e_algo
{
	ALGO_NONE,
	ALGO_GENRSA,
	ALGO_MD5,
	ALGO_SHA256,
	ALGO_WHIRLPOOL,
	ALGO_BLAKE2B,
	ALGO_BASE64,
	ALGO_DES,
	ALGO_DES_ECB,
	ALGO_DES_CBC,
	ALGO_DES_CFB,
	ALGO_DES_CFB1,
	ALGO_DES_CFB8,
	ALGO_DES_OFB,
	ALGO_DES_CTR,
	ALGO_DES_PCBC,
	ALGO_DES3,
	ALGO_DES3_ECB,
	ALGO_DES3_CBC,
	ALGO_DES3_CFB,
	ALGO_DES3_CFB1,
	ALGO_DES3_CFB8,
	ALGO_DES3_OFB,
	ALGO_DES3_CTR,
	ALGO_DES3_PCBC,
	ALGO_AES_128,
	ALGO_AES_192,
	ALGO_AES_256,
	ALGO_AES_128_ECB,
	ALGO_AES_128_CBC,
	ALGO_AES_128_CFB,
	ALGO_AES_128_CFB1,
	ALGO_AES_128_CFB8,
	ALGO_AES_128_OFB,
	ALGO_AES_128_CTR,
	ALGO_AES_128_PCBC,
	ALGO_AES_192_ECB,
	ALGO_AES_192_CBC,
	ALGO_AES_192_CFB,
	ALGO_AES_192_CFB1,
	ALGO_AES_192_CFB8,
	ALGO_AES_192_OFB,
	ALGO_AES_192_CTR,
	ALGO_AES_192_PCBC,
	ALGO_AES_256_ECB,
	ALGO_AES_256_CBC,
	ALGO_AES_256_CFB,
	ALGO_AES_256_CFB1,
	ALGO_AES_256_CFB8,
	ALGO_AES_256_OFB,
	ALGO_AES_256_CTR,
	ALGO_AES_256_PCBC,
	ALGO_BLOWFISH,
	ALGO_BLOWFISH_ECB,
	ALGO_BLOWFISH_CBC,
	ALGO_BLOWFISH_CFB,
	ALGO_BLOWFISH_CFB1,
	ALGO_BLOWFISH_CFB8,
	ALGO_BLOWFISH_OFB,
	ALGO_BLOWFISH_CTR,
	ALGO_BLOWFISH_PCBC,
}	t_algo;

typedef struct s_hashDispatch
{
	t_algo			algo;
	const t_hash	*hash;
}	t_hashDispatch;

typedef struct s_cipherDispatch
{
	t_algo			algo;
	const t_cipher	*cipher;
}	t_cipherDispatch;

typedef struct s_pkeyPemDispatch
{
	t_pkeyType			type;
	const t_pkeyPemDef	*def;
}	t_pkeyPemDispatch;

extern const	t_hashDispatch		g_hashTable[];
extern const	t_cipherDispatch	g_cipherTable[];
extern const	t_pkeyPemDispatch	g_pkeyPemTable[];

/**
 * @brief Retrieves a hash structure based on the specified algorithm.
 * 
 * @param algo The algorithm type to look up the corresponding hash structure.
 * 
 * @return A pointer to a constant t_hash structure matching the given algorithm,
 *         or NULL if the algorithm is not found.
 */
const t_hash	*getHashByAlgo(t_algo algo);

/**
 * @brief Retrieves a cipher structure based on the specified algorithm.
 * 
 * @param algo The algorithm type to look up the corresponding cipher structure.
 * 
 * @return A pointer to a constant t_cipher structure matching the given algorithm,
 *         or NULL if the algorithm is not found.
 */
const t_cipher	*getCipherByAlgo(t_algo algo);

/**
 * @brief Retrieves a hash structure based on the specified name.
 * 
 * @param name The name of the hash to look up (e.g., "sha256").
 * 
 * @return A pointer to a constant t_hash structure matching the given name,
 *         or NULL if the name is not found.
 */
const t_hash *getHashByName(const char *name);

/**
 * @brief Retrieves a cipher structure based on the specified name.
 * 
 * @param name The name of the cipher to look up (e.g., "aes-256-cbc").
 * 
 * @return A pointer to a constant t_cipher structure matching the given name,
 *         or NULL if the name is not found.
 */
const t_cipher *getCipherByName(const char *name);

/**
 * @brief Retrieves the name of the algorithm as a string.
 * 
 * @param algo The algorithm enumeration value.
 * @return const char* A pointer to a null-terminated string containing the name of the algorithm.
 */
const char *getAlgoName(t_algo algo);

/**
 * @brief Retrieves a cipher structure based on the specified OID.
 * 
 * @param oid The OID to look up, represented as a byte array.
 * @param oidLen The length of the OID in bytes.
 * 
 * @return A pointer to a constant t_cipher structure matching the given OID,
 *         or NULL if the OID is not found.
 */
const t_cipher *getCipherByOid(const uint8_t *oid, size_t oidLen);

/**
 * @brief Retrieves a PEM key definition based on the specified key type.
 * 
 * @param type The key type to look up.
 * 
 * @return A pointer to a constant t_pkeyPemDef structure matching the given type,
 *         or NULL if the type is not found.
 */
const t_pkeyPemDef *getPkeyPemDefByPkeyType(t_pkeyType type);

/**
 * @brief Retrieves a PEM key definition based on the specified traditional PEM label.
 * 
 * @param label The traditional PEM label to look up (e.g., "RSA PRIVATE KEY").
 * @param isPrivate Flag indicating if the key is private (1) or public (0).
 * 
 * @return A pointer to a constant t_pkeyPemDef structure matching the given label,
 *         or NULL if the label is not found.
 */
const t_pkeyPemDef *getPkeyPemDefFromPkcs1Label(const char *label, int isPrivate);

/**
 * @brief Retrieves a PEM key definition based on the specified OID.
 * 
 * @param oid The OID to look up, represented as a byte array.
 * @param oidLen The length of the OID in bytes.
 * 
 * @return A pointer to a constant t_pkeyPemDef structure matching the given OID,
 *         or NULL if the OID is not found.
 */
const t_pkeyPemDef *getPkeyPemDefFromOid(const uint8_t *oid, size_t oidLen);

#endif /* HAJCRYPT_DISPATCH_H */
