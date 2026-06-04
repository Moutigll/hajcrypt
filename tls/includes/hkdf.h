#ifndef BTLS_HKDF_H
# define BTLS_HKDF_H

# include "../../includes/hash/hash.h"

#define TLS13_PREFIX		"tls13 "
#define TLS13_PREFIX_LEN	6

/**
 * @brief HKDF expand label (TLS 1.3 specific)
 *
 * The expand label function is a variant of HKDF expand used in TLS 1.3.
 * It prepends "tls13 " to the label and encodes lengths as 2-byte integers.
 *
 * @param secret	Pointer to the secret key material
 * @param secretLen	Length of the secret in bytes
 * @param label		Pointer to the label string (without "tls13 " prefix)
 * @param context	Pointer to the context data
 * @param contextLen	Length of the context in bytes
 * @param output	Pointer to output buffer for derived keying material
 * @param outputLen	Desired length of the output in bytes
 * @param hash		Pointer to the hash function to use
 * @return			0 on success, -1 on error
 */
int	tlsHkdfExpandLabel(const uint8_t	*secret,
					   size_t			secretLen,
					   const char		*label,
					   const uint8_t	*context,
					   size_t			contextLen,
					   uint8_t			*output,
					   size_t			outputLen,
					   const t_hashAlgo	*hash);

#endif /* BTLS_HKDF_H */
