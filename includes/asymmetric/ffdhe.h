#ifndef HAJCRYPT_FFDHE_H
# define HAJCRYPT_FFDHE_H

# include "bigint.h"

/**
 * @brief Predefined FFDHE group identifiers (RFC 7919)
 *
 * These constants represent the finite field Diffie-Hellman groups
 * defined in RFC 7919. The value corresponds to the prime size in bits.
 */
# define FFDHE_GROUP_2048	2048
# define FFDHE_GROUP_3072	3072
# define FFDHE_GROUP_4096	4096
# define FFDHE_GROUP_6144	6144
# define FFDHE_GROUP_8192	8192


/**
 * @brief FFDHE context structure
 *
 * This structure holds all the parameters and keys for a finite field
 * Diffie-Hellman ephemeral key exchange. It contains the prime modulus p,
 * the generator g, the ephemeral private key, the public key (g^priv mod p),
 * and the computed shared secret. All big integers are stored in the
 * t_bigInt format.
 */
typedef struct s_ffdheCtx {
	int			groupId;	/* Group identifier (2048, 3072, etc.) */
	t_bigInt	*p;			/* Prime modulus of the group */
	t_bigInt	*g;			/* Generator (2 or 5 depending on group) */
	t_bigInt	*priv;		/* Ephemeral private key (random) */
	t_bigInt	*pub;		/* Public key = g^priv mod p */
	t_bigInt	*shared;	/* Computed shared secret */
}	t_ffdheCtx;

/**
 * @brief Initialises an FFDHE context with a predefined group
 *
 * This function loads the prime modulus p and generator g for the given
 * group identifier. The primes and generators are taken from the standard
 * values defined in RFC 7919. After initialisation, the context is ready
 * to generate a key pair.
 *
 * @param ctx		Pointer to the context structure to initialise
 * @param groupId	Group identifier (FFDHE_GROUP_2048, etc.)
 * @return			1 on success, 0 on error (unknown group)
 */
int	ffdheInit(t_ffdheCtx *ctx, int groupId);

/**
 * @brief Generates an ephemeral key pair
 *
 * This function generates a random private key (priv) in the range [2, p-2]
 * and computes the corresponding public key as g^priv mod p. The results
 * are stored inside the context. The random generator must be properly
 * seeded before calling this function.
 *
 * @param ctx	Initialised context
 * @return		1 on success, 0 on error
 */
int	ffdheGenerateKeypair(t_ffdheCtx *ctx);

/**
 * @brief Retrieves the public key in wire format (big‑endian)
 *
 * This function exports the ephemeral public key as a byte string in
 * big‑endian order, without leading zero bytes. The required output
 * buffer size can be obtained by calling with a NULL output pointer;
 * the needed length is then stored in *outLen.
 *
 * @param ctx		Context containing the key pair
 * @param out		Output buffer (may be NULL to query length)
 * @param outLen	Pointer to buffer size; on output, receives the actual length written
 * @return			1 on success, 0 on error
 */
int	ffdheGetPublicBytes(const t_ffdheCtx *ctx, uint8_t *out, size_t *outLen);

/**
 * @brief Computes the shared secret from the peer’s public key
 *
 * This function performs the key agreement: it calculates the shared
 * secret as peer_pub^priv mod p, where priv is our ephemeral private key.
 * The result is stored in big‑endian byte order without leading zeros.
 * On success, the shared secret is also saved inside the context.
 *
 * @param ctx			Context containing our private key
 * @param peerPub		Peer’s public key as a byte string (big‑endian)
 * @param peerPubLen	Length of the peer’s public key in bytes
 * @param sharedSecret	Output buffer for the computed shared secret
 * @param sharedLen		Pointer to buffer size; on output, receives the actual length
 * @return				1 on success, 0 on error
 */
int	ffdheComputeShared(t_ffdheCtx		*ctx,
					   const uint8_t	*peerPub,		size_t	peerPubLen,
					   uint8_t			*sharedSecret,	size_t	*sharedLen);

/**
 * @brief Frees all resources allocated in the context
 *
 * This function securely zeroises and frees all big integers stored
 * in the context (p, g, priv, pub, shared). After this call, the
 * context should not be used again unless reinitialised.
 *
 * @param ctx	Context to free
 */
void	ffdheFree(t_ffdheCtx *ctx);


int	getGroupParams(int groupId, const char **pHex, const char **gHex);

#endif /* HAJCRYPT_FFDHE_H */
