#ifndef HAJCRYPT_KEX_H
# define HAJCRYPT_KEX_H

# include "ffdhe.h"
# include "ecdh.h"

/**
 * @brief Key exchange algorithm types
 *
 * This enumeration lists the supported key exchange algorithms for TLS.
 */
typedef enum e_kexType {
	KEX_TYPE_FFDHE,	/* Finite Field Diffie‑Hellman Ephemeral */
	KEX_TYPE_ECDH,	/* Elliptic Curve Diffie‑Hellman */
	KEX_TYPE_NONE
}	t_kexType;

/**
 * @brief Opaque key exchange context
 *
 * This structure holds the state for a key exchange operation. The internal
 * pointer points to a type‑specific context (e.g., t_ffdheCtx). Users must
 * not access the fields directly; they should use the provided API functions.
 */
typedef struct s_kexCtx {
	t_kexType		type;
	int				groupId;	/* For FFDHE: prime size (2048, 3072, 4096); for ECDH: curve NID */
	void			*internal;	/* Pointer to t_ffdheCtx or t_ecdhCtx */
}	t_kexCtx;

/**
 * @brief Initializes a key exchange context for a given group
 *
 * This function creates and initialises a key exchange context for the
 * specified algorithm type and group identifier. For FFDHE, the group ID
 * indicates the prime size (e.g., 2048, 3072, 4096). For ECDH, it would
 * be a curve NID. After initialisation, the context is ready to generate
 * a key pair.
 *
 * @param ctx		Pointer to the context to initialise
 * @param type		Algorithm type (KEX_TYPE_FFDHE, etc.)
 * @param groupId	Group identifier (e.g., 2048 for FFDHE, curve NID for ECDH)
 * @return			1 on success, 0 on error
 */
int	kexInit(t_kexCtx *ctx, t_kexType type, int groupId);

/**
 * @brief Generates an ephemeral key pair (private + public)
 *
 * This function generates a new ephemeral key pair for the key exchange.
 * The public key is stored internally in the context and can be retrieved
 * using kexGetPublicBytes(). The private key remains hidden inside the
 * internal context. The key pair is automatically destroyed when kexFree()
 * is called.
 *
 * @param ctx	Initialised context
 * @return		1 on success, 0 on error
 */
int	kexGenerateKeypair(t_kexCtx *ctx);

/**
 * @brief Returns the public key in wire format (as bytes)
 *
 * This function copies the ephemeral public key into the provided buffer
 * in the format expected by the TLS key_share extension. The caller must
 * ensure that the output buffer is large enough; the required size can be
 * obtained by calling this function with a NULL output to retrieve the
 * length, or by using the group parameters.
 *
 * @param ctx		Context containing the key pair
 * @param out		Output buffer (allocated by the caller)
 * @param outLen	Pointer to the buffer size; on output, receives the actual length written
 * @return			1 on success, 0 on error
 */
int	kexGetPublicBytes(const t_kexCtx *ctx, uint8_t *out, size_t *outLen);

/**
 * @brief Computes the shared secret from the peer’s public key
 *
 * This function performs the key agreement: it uses the local private key
 * and the peer’s public key to compute the shared secret. The shared secret
 * is a raw byte string that can be used as the pre‑master secret in TLS.
 * The caller must provide a buffer large enough (typically the group size).
 *
 * @param ctx			Context (contains our private key)
 * @param peerPub		Peer’s public key (wire format, as received)
 * @param peerPubLen	Length of the peer’s public key in bytes
 * @param sharedSecret	Output buffer for the computed shared secret
 * @param sharedLen		Pointer to buffer size; on output, receives the actual length
 * @return				1 on success, 0 on error (including integrity failure)
 */
int	kexComputeShared(t_kexCtx		*ctx,
					 const uint8_t	*peer_pub,		size_t	peer_pub_len,
					 uint8_t		*shared_secret,	size_t	*shared_len);

/**
 * @brief Frees all resources associated with the context
 *
 * This function securely erases any sensitive material (private keys,
 * intermediate values) and releases allocated memory. After calling
 * kexFree(), the context must not be used again unless reinitialised.
 *
 * @param ctx	Context to free
 */
void	kexFree(t_kexCtx *ctx);

#endif /* HAJCRYPT_KEX_H */
