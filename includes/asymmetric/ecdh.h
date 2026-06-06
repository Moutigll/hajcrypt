#ifndef HAJCRYPT_ECDH_H
# define HAJCRYPT_ECDH_H

# include "bigint.h"

/**
 * @brief Named curve identifiers for TLS (RFC 8446 NamedGroup values)
 *
 * These constants identify the elliptic curves supported for ECDH key
 * exchange.
 */
#define ECDH_GROUP_SECP256R1	23	/* 0x0017 */
#define ECDH_GROUP_SECP384R1	24	/* 0x0018 */
#define ECDH_GROUP_SECP521R1	25	/* 0x0019 */
#define ECDH_GROUP_X25519		29	/* 0x001D */
#define ECDH_GROUP_X448			30	/* 0x001E */

/**
 * @brief Key sizes in bytes for each curve
 *
 * The size of the X coordinate (and the shared secret) in bytes.
 * For SECP256r1, the prime is 256 bits → 32 bytes.
 * For SECP384r1, the prime is 384 bits → 48 bytes.
 * For SECP521r1, the prime is 521 bits → 66 bytes.
 */
#define SECP256R1_KEY_SIZE		32
#define SECP384R1_KEY_SIZE		48
#define SECP521R1_KEY_SIZE		66
#define X25519_KEY_SIZE			32
#define X448_KEY_SIZE			56

/* Public key size in bytes (uncompressed point format) */
#define SECP256R1_PUB_SIZE		65	/* 0x04 + 32 bytes X + 32 bytes Y */
#define SECP384R1_PUB_SIZE		97	/* 0x04 + 48 bytes X + 48 bytes Y */
#define SECP521R1_PUB_SIZE		133	/* 0x04 + 66 bytes X + 66 bytes Y */
#define X25519_PUB_SIZE			32
#define X448_PUB_SIZE			56

/* Shared secret size in bytes (X coordinate size) */
#define SECP256R1_SHARED_SIZE	32
#define SECP384R1_SHARED_SIZE	48
#define SECP521R1_SHARED_SIZE	66
#define X25519_SHARED_SIZE		32
#define X448_SHARED_SIZE		56

/**
 * @brief Affine point on a Weierstrass curve
 *
 * This structure represents a point on an elliptic curve in affine
 * coordinates (X, Y). It is used internally for Weierstrass curve
 * operations.
 * @note Internal use only
 */
typedef struct s_ecPoint
{
	t_bigInt	*x;		/* X coordinate */
	t_bigInt	*y;		/* Y coordinate */
}	t_ecPoint;

/**
 * @brief Weierstrass curve parameters
 *
 * This structure holds the domain parameters for a Weierstrass elliptic
 * curve: the prime modulus p, the coefficients a and b, the order n of
 * the base point, the base point G itself, and the key sizes. It is
 * used internally to store the parameters of SECP256r1, SECP384r1,
 * and SECP521r1 curves.
 * @note Internal use only
 */
typedef struct s_weierstrassParams {
	t_bigInt	*p;
	t_bigInt	*a;
	t_bigInt	*b;
	t_bigInt	*n;
	t_ecPoint	G;
	size_t		keySize;
	size_t		pubSize;
} t_weierstrassParams;

/**
 * @brief ECDH context structure (generic)
 *
 * This structure holds all the parameters and keys for an elliptic curve
 * Diffie‑Hellman ephemeral key exchange. It stores the curve identifier,
 * the ephemeral private key as a big integer, the public key coordinates
 * (X and Y), and the computed shared secret (the X coordinate of the
 * shared point). The Y coordinate is kept for completeness but is not
 * needed for the shared secret.
 */
typedef struct s_ecdhCtx
{
	int			curveId;	/* Curve identifier (ECDH_GROUP_*) */
	t_bigInt	*priv;		/* Private key (integer in [1, n-1]) */
	t_bigInt	*pubX;		/* X coordinate of the public key */
	t_bigInt	*pubY;		/* Y coordinate (optional, seldom used) */
	t_bigInt	*shared;	/* Shared secret (X coordinate of the shared point) */
}	t_ecdhCtx;

/**
 * @brief Initialises an ECDH context for a given curve
 *
 * This function loads the domain parameters (prime, curve coefficients,
 * base point, order) for the specified curve and initialises the context.
 * The context must be freed with ecdhFree() when no longer needed.
 *
 * @param ctx		Pointer to the context to initialise
 * @param curveId	Curve identifier (ECDH_GROUP_* value)
 * @return			1 on success, 0 on error (unknown curve)
 */
int	ecdhInit(t_ecdhCtx *ctx, int curveId);

/**
 * @brief Generates an ephemeral key pair
 *
 * This function generates a random private key in the range [1, n-1]
 * (where n is the order of the base point) and computes the corresponding
 * public key point by scalar multiplication of the base point with the
 * private key. The results are stored inside the context.
 *
 * @param ctx	Initialised context
 * @return		1 on success, 0 on error
 */
int	ecdhGenerateKeypair(t_ecdhCtx *ctx);

/**
 * @brief Retrieves the public key in wire format
 *
 * This function exports the ephemeral public key in the format expected
 * by the TLS key_share extension. The wire format is the uncompressed
 * point representation: 0x04 followed by the X coordinate (big‑endian)
 * and then the Y coordinate (big‑endian). For X25519 and X448, the format
 * is simply the raw 32 or 56 byte public key. The caller may call with a
 * NULL output to obtain the required buffer size.
 *
 * @param ctx		Context containing the key pair
 * @param out		Output buffer (may be NULL to query length)
 * @param outLen	Pointer to buffer size; on output, receives the actual length written
 * @return			1 on success, 0 on error
 */
int	ecdhGetPublicBytes(const t_ecdhCtx *ctx, uint8_t *out, size_t *outLen);

/**
 * @brief Computes the shared secret from the peer’s public key
 *
 * This function performs the ECDH key agreement: it multiplies the
 * peer’s public key point by our private key to obtain the shared point.
 * The shared secret is the X coordinate of that point, taken as a big‑endian
 * byte string (without leading zeros). For X25519 and X448, the output is
 * the raw shared secret. The result is also stored inside the context.
 *
 * @param ctx			Context containing our private key
 * @param peerPub		Peer’s public key in wire format (uncompressed point or raw)
 * @param peerPubLen	Length of the peer’s public key in bytes
 * @param sharedSecret	Output buffer for the computed shared secret
 * @param sharedLen		Pointer to buffer size; on output, receives the actual length
 * @return				1 on success, 0 on error
 */
int	ecdhComputeShared(t_ecdhCtx *ctx,
					  const uint8_t *peerPub, size_t peerPubLen,
					  uint8_t *sharedSecret, size_t *sharedLen);

/**
 * @brief Frees all resources allocated in the context
 *
 * This function securely zeroises and frees all big integers stored
 * in the context (private key, public coordinates, shared secret).
 * After this call, the context must not be reused unless reinitialised.
 *
 * @param ctx	Context to free
 */
void	ecdhFree(t_ecdhCtx *ctx);

/*
 * ============================================================================
 * INTERNAL USE ONLY - Low-level elliptic curve operations
 * ============================================================================
 *
 * The following functions and declarations are for internal use within the
 * library and should not be called directly by applications.
 */

/**
 * @brief Retrieves the Weierstrass curve parameters for a given curve ID
 *
 * This function returns a pointer to the structure containing the domain
 * parameters for the specified Weierstrass curve. It is used internally
 * to access the parameters when performing operations on SECP256r1,
 * SECP384r1, and SECP521r1 curves.
 *
 * @param curveId	Curve identifier (ECDH_GROUP_SECP256R1, etc.)
 * @return			Pointer to the curve parameters, or NULL if unknown curve
 */
const t_weierstrassParams *ecdhGetCurveParams(int curveId);

/**
 * @brief Scalar multiplication on a Weierstrass curve
 *
 * Computes Q = k * P (mod p) on the curve y^2 = x^3 + a*x + b.
 * This function is used internally for SECP curves.
 *
 * @param Q		Output point (result of multiplication)
 * @param k		Scalar multiplier
 * @param P		Input point
 * @param p		Prime modulus
 * @param a		Curve coefficient a
 * @return		1 on success, 0 on error
 */
int	ecWeierstrassScalarMult(t_ecPoint		*Q,
							const t_bigInt	*k,
							const t_ecPoint	*P,
							const t_bigInt	*p,
							const t_bigInt	*a);

/**
 * @brief Point doubling on a Weierstrass curve
 *
 * Computes R = 2 * P on the curve y^2 = x^3 + a*x + b mod p.
 * Used internally by the scalar multiplication routine.
 *
 * @param R		Output point (doubled result)
 * @param P		Input point
 * @param p		Prime modulus
 * @param a		Curve coefficient a
 * @return		1 on success, 0 on error
 */
int	ecWeierstrassPointDouble(t_ecPoint			*R,
							 const t_ecPoint	*P,
							 const t_bigInt		*p,
							 const t_bigInt		*a);

/**
 * @brief Point addition on a Weierstrass curve
 *
 * Computes R = P + Q on the curve y^2 = x^3 + a*x + b mod p.
 * Used internally by the scalar multiplication routine.
 *
 * @param R		Output point (sum result)
 * @param P		First input point
 * @param Q		Second input point
 * @param p		Prime modulus
 * @param a		Curve coefficient a
 * @return		1 on success, 0 on error
 */
int	ecWeierstrassPointAdd(t_ecPoint			*R,
						 const t_ecPoint	*P,
						 const t_ecPoint	*Q,
						 const t_bigInt		*p,
						 const t_bigInt		*a);

/**
 * @brief X25519 scalar multiplication (RFC 7748)
 *
 * Computes out = scalar * point on the Curve25519 Montgomery curve.
 * This function is used internally for X25519 key exchange.
 *
 * @param out		Output buffer (32 bytes)
 * @param scalar	Scalar multiplier (32 bytes)
 * @param point		Point on the curve (32 bytes)
 */
void	x25519ScalarMult(uint8_t		out[32],
						const uint8_t	scalar[32],
						const uint8_t	point[32]);

/**
 * @brief X448 scalar multiplication (RFC 7748)
 *
 * Computes out = scalar * point on the Curve448 Montgomery curve.
 * This function is used internally for X448 key exchange.
 *
 * @param out		Output buffer (56 bytes)
 * @param scalar	Scalar multiplier (56 bytes)
 * @param point		Point on the curve (56 bytes)
 */
void	x448ScalarMult(uint8_t		out[56],
					 const uint8_t	scalar[56],
					 const uint8_t	point[56]);

/**
 * @brief Clamp X25519 scalar (RFC 7748)
 *
 * Modifies the scalar in place according to RFC 7748 clamping rules:
 * - Clear bits 0, 1, 2
 * - Set bit 254
 * - Clear bit 255
 *
 * @param scalar	Scalar to clamp (32 bytes, modified in place)
 */
void	x25519Clamp(uint8_t scalar[32]);

/**
 * @brief Clamp X448 scalar (RFC 7748)
 *
 * Modifies the scalar in place according to RFC 7748 clamping rules:
 * - Clear bits 0, 1
 * - Set bit 447
 * - Clear bit 448, 449, 450, 451, 452, 453, 454
 *
 * @param scalar	Scalar to clamp (56 bytes, modified in place)
 */
void	x448Clamp(uint8_t scalar[56]);

/**
 * @brief X25519 base point (RFC 7748)
 *
 * The standard base point for Curve25519 (9 followed by zeros).
 */
extern const uint8_t	x25519BasePoint[32];

/**
 * @brief X448 base point (RFC 7748)
 *
 * The standard base point for Curve448 (5 followed by zeros).
 */
extern const uint8_t	x448BasePoint[56];

#endif /* HAJCRYPT_ECDH_H */
