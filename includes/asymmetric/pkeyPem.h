#ifndef HAJCRYPT_PKEY_PEM_H
# define HAJCRYPT_PKEY_PEM_H

#include "../x509/oid.h"

typedef enum {
	PKEY_TYPE_UNKNOWN = 0,
	PKEY_TYPE_RSA,
	//PKEY_TYPE_DSA,
	PKEY_TYPE_MAX
} t_pkeyType;

/**
 * @struct t_pkeyPemDef
 * @brief Describes algorithm-specific handlers and metadata for PEM key encoding/decoding.
 *
 * This structure groups labels, OID information, and function pointers used to
 * encode/decode public and private keys in traditional PEM formats as well as
 * algorithm parameter encoding for AlgorithmIdentifier.
 *
 * Members:
 * - tradPubLabel: Traditional public key PEM label (e.g., "RSA PUBLIC KEY").
 * - tradPrivLabel: Traditional private key PEM label (e.g., "RSA PRIVATE KEY").
 * - oid: Pointer to the algorithm OID bytes.
 * - oidLen: Length of the OID in bytes.
 * - encodeAlgoParams: Encodes AlgorithmIdentifier parameters for the algorithm.
 *                     For RSA, returns NULL (no parameters).
 *                     For DSA, returns SEQUENCE { p, q, g }.
 * - encodePubKey: Encodes the public key in traditional DER form.
 * - encodePrivKey: Encodes the private key in traditional DER form.
 * - decodePubKey: Parses a traditional DER public key into the key structure.
 * - decodePrivKey: Parses a traditional DER private key into the key structure.
 */
typedef struct s_pkeyPemDef {
	const char		*tradPubLabel;
	const char		*tradPrivLabel;
	const t_algoId	oid;
	size_t			keyLen;
	uint8_t			*(*encodeAlgoParams)(const void *key, size_t *outLen);
	uint8_t			*(*encodePubKey)(const void *key, size_t *outLen);
	uint8_t			*(*encodePrivKey)(const void *key, size_t *outLen);
	int				(*decodePubKey)(const uint8_t *der, size_t len, void *key);
	int				(*decodePrivKey)(const uint8_t *der, size_t len, void *key);
}	t_pkeyPemDef;

typedef struct {
	t_pkeyType			type;	/* algo used */
	void				*key;	/* pointer to the key struct */
	const t_pkeyPemDef	*def;	/* PEM definition */
} t_pkey;

/**
 * @brief Serialize a public or private key to a PEM-encoded string.
 *
 * @param key             Pointer to the key structure.
 * @param isPrivate       Non-zero to output a private key; zero for public key.
 * @param useTraditional  Non-zero to use traditional PEM format when applicable.
 * @param password        Optional password for encrypting the private key (may be nullptr).
 * @param cipher          Optional cipher to use for encryption (may be nullptr).
 * @return Newly allocated C-string containing the PEM data, or nullptr on failure.
 */
char	*pkeyToPem(t_pkey		*key,
				  int			isPrivate,
				  int			useTraditional,
				  const char	*password,
				  const void	*cipher);

/**
 * @brief Parse a PEM-encoded key into a key structure.
 *
 * @param pem       NUL-terminated PEM string.
 * @param key       Output key structure to populate.
 * @param isPrivate Non-zero if PEM contains a private key, zero for public.
 * @param password  Optional password for encrypted PEM (may be NULL).
 *
 * @return 0 on failure, 1 on success and 2 if a password is required but not provided.
 */
int		pkeyFromPem(const char	*pem,
					t_pkey		*key,
					int			isPrivate,
					const char	*password);

#endif
