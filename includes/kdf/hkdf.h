#ifndef HAJCRYPT_HKDF_H
# define HAJCRYPT_HKDF_H

# include "../hash/hash.h"
# include "../hash/hmac.h"

/**
 * @brief HKDF extract phase
 *
 * The extract function takes a salt and input key material (IKM) and produces
 * a pseudorandom key (PRK). If the salt is not provided (NULL), it defaults
 * to a string of zeros of the hash length.
 *
 * @param salt		Pointer to the optional salt value (can be NULL)
 * @param saltLen	Length of the salt in bytes
 * @param ikm		Pointer to the input key material
 * @param ikmLen	Length of the input key material in bytes
 * @param prk		Pointer to output buffer for the pseudorandom key
 * @param prkLen	Length of the PRK buffer (must be at least hash length)
 * @param hash		Pointer to the hash function to use
 * @return			1 on success, 0 on error
 */
int	hkdfExtract(const uint8_t	*salt,	size_t	saltLen,
				const uint8_t	*ikm,	size_t	ikmLen,
				uint8_t			*prk,	size_t	prkLen,
				const t_hash	*hash);

/**
 * @brief HKDF expand phase
 *
 * The expand function takes the pseudorandom key (PRK), optional context
 * information, and produces output keying material (OKM) of the desired length.
 *
 * @param prk		Pointer to the pseudorandom key from extract phase
 * @param prkLen	Length of the PRK in bytes
 * @param info		Pointer to optional context/application specific info
 * @param infoLen	Length of the info in bytes
 * @param okm		Pointer to output buffer for the output keying material
 * @param okmLen	Desired length of the output keying material in bytes
 * @param hash		Pointer to the hash function to use (must match extract)
 * @return			1 on success, 0 on error
 */
int	hkdfExpand(const uint8_t	*prk,	size_t	prkLen,
			   const uint8_t	*info,	size_t	infoLen,
			   uint8_t			*okm,	size_t	okmLen,
			   const t_hash		*hash);

/**
 * @brief HKDF one‑shot function (extract + expand)
 *
 * Combines the extract and expand phases into a single call.
 * Extracts a pseudorandom key from the salt and IKM, then expands it
 * into output keying material of the desired length.
 *
 * @param salt		Pointer to the optional salt value (can be NULL)
 * @param saltLen	Length of the salt in bytes
 * @param ikm		Pointer to the input key material
 * @param ikmLen	Length of the input key material in bytes
 * @param info		Pointer to optional context/application specific info
 * @param infoLen	Length of the info in bytes
 * @param okm		Pointer to output buffer for the output keying material
 * @param okmLen	Desired length of the output keying material in bytes
 * @param hash		Pointer to the hash function to use
 * @return			1 on success, 0 on error
 */
int	hkdf(const uint8_t	*salt,
		 size_t			saltLen,
		 const uint8_t	*ikm,
		 size_t			ikmLen,
		 const uint8_t	*info,
		 size_t			infoLen,
		 uint8_t		*okm,
		 size_t			okmLen,
		 const t_hash	*hash);

#endif /* HAJCRYPT_HKDF_H */
