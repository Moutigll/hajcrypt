#ifndef HAJCRYPT_TOTP_H
#define HAJCRYPT_TOTP_H

#include <stdint.h>
#include <stddef.h>

#include "cipher/cipher.h"
#include "hash/hmac.h"

typedef struct s_totpEntry {
	char			*label;		/* User identifier (e.g., email) */
	char			*issuer;	/* Issuer name (optional) */
	uint8_t			secret[64];	/* Secret key in binary form */
	size_t			secretLen;	/* Length of the secret key */
	const t_hash	*algo;		/* Hash algorithm (SHA1, SHA256, SHA512) */
	uint8_t			digits;		/* Number of digits in the TOTP code (6 or 8) */
	uint32_t		period;		/* Time step in seconds (default 30) */
	uint32_t		window;		/* Number of time steps to check for verification (optional, default 1) */
} t_totpEntry;

typedef struct s_totpStore {
	t_totpEntry	*entries;
	size_t		count;
} t_totpStore;



/**
 * @brief Initializes a TOTP context with the given secret and configuration.
 *
 * @param ctx Pointer to the TOTP context to initialize.
 * @param secretBase32 The Base32-encoded secret key.
 * @param algo The hash algorithm to use (SHA1, SHA256, SHA512).
 * @param digits The number of digits in the generated TOTP code (6 or 8).
 * @param period The time step in seconds (default is 30).
 *
 * @return 0 on success, non-zero on failure.
 */
int totpInit(t_totpEntry *ctx, const char *secretBase32, const t_hash *algo, uint8_t digits, uint32_t period);

/**
 * @brief Initializes a TOTP context with the given secret and configuration.
 *
 * @param ctx Pointer to the TOTP context to initialize.
 * @param secretBase32 The Base32-encoded secret key.
 * @param config Pointer to a t_totpEntry structure containing the configuration parameters.
 *
 * @return 0 on success, non-zero on failure.
 */
int totpInitWithConfig(t_totpEntry *ctx, const char *secretBase32, const t_totpEntry *config);

/**
 * @brief Generates a TOTP code for the given timestamp.
 *
 * @param ctx Pointer to the initialized TOTP context.
 * @param timestamp The current timestamp in seconds since the epoch.
 * @param code A buffer to store the generated TOTP code (should be at least 9 bytes for 8 digits + null terminator).
 *
 * @return 0 on success, non-zero on failure.
 */
int totpGenerate(t_totpEntry *ctx, uint64_t timestamp, char *code);

/**
 * @brief Verifies a TOTP code against the expected value for the given timestamp.
 *
 * @param ctx Pointer to the initialized TOTP context.
 * @param code The TOTP code to verify (as a null-terminated string).
 * @param timestamp The current timestamp in seconds since the epoch.
 *
 * @return 1 if the code is valid, 0 if invalid, and -1 on error.
 */
int totpVerify(t_totpEntry *ctx, const char *code, uint64_t timestamp);

/**
 * @brief Generates a random Base32-encoded secret key for TOTP.
 *
 * @param output A buffer to store the generated secret (should be at least 33 bytes for 32 characters + null terminator).
 * @param outputSize The size of the output buffer.
 *
 * @return 0 on success, non-zero on failure.
 */
int totpGenerateSecret(const t_hash *algo, char *output, size_t outputSize);

/**
 * @brief Creates a TOTP URI for use with authenticator apps.
 *
 * @param userEmail The user's email address (used as the account name).
 * @param secretBase32 The Base32-encoded secret key.
 * @param issuer The name of the service or application issuing the TOTP.
 * @param config Pointer to a t_totpEntry structure containing the configuration parameters.
 * @param output A buffer to store the generated URI (should be large enough to hold the URI).
 * @param outputSize The size of the output buffer.
 *
 * @return 0 on success, non-zero on failure.
 */
int totpCreateUri(const char		*userEmail,
				  const char		*secretBase32,
				  const char		*issuer,
				  const t_totpEntry	*config,
				  char				*output,	size_t	outputSize);

/**
 * @brief initializes a TOTP context from a TOTP URI.
 *
 * @param ctx Pointer to the TOTP context to initialize.
 * @param uri The TOTP URI to parse (should start with "otpauth://totp/").
 *
 * @return 0 on success, non-zero on failure.
 */
int totpInitFromUri(t_totpEntry *ctx, const char *uri);

/**
 * @brief Generates a TOTP code from a TOTP URI for the given timestamp.
 *
 * @param uri The TOTP URI to parse (should start with "otpauth://totp/").
 * @param timestamp The current timestamp in seconds since the epoch.
 * @param code A buffer to store the generated TOTP code (should be at least 9 bytes for 8 digits + null terminator).
 *
 * @return 0 on success, non-zero on failure.
 */
int totpGenerateFromUri(const char *uri, uint64_t timestamp, char *code);

/**
 * @brief Verifies a TOTP code against a TOTP URI for the given timestamp.
 *
 * @param uri The TOTP URI to parse (should start with "otpauth://totp/").
 * @param code The TOTP code to verify (as a null-terminated string).
 * @param timestamp The current timestamp in seconds since the epoch.
 *
 * @return 1 if the code is valid, 0 if invalid, and -1 on error.
 */
int totpVerifyFromUri(const char *uri, const char *code, uint64_t timestamp);



/* --------------- Encoding / Decoding of TOTP entries and stores --------------- */

/**
 * @brief Encodes a TOTP entry into DER format.
 *
 * @param entry Pointer to the TOTP entry to encode.
 * @param outLen Pointer to a size_t variable to receive the length of the encoded data.
 *
 * @return Pointer to the allocated DER-encoded buffer on success, or NULL on failure.
 *         The caller is responsible for freeing the returned buffer.
 */
uint8_t *totpEntryEncode(const t_totpEntry *entry, size_t *outLen);

/**
 * @brief Decodes a DER-encoded TOTP entry into a t_totpEntry structure.
 *
 * @param der Pointer to the DER-encoded data.
 * @param derLen Length of the DER-encoded data.
 * @param entry Pointer to a t_totpEntry structure to populate with the decoded data.
 *
 * @return 1 on success, 0 on failure.
 */
int totpEntryDecode(const uint8_t *der, size_t derLen, t_totpEntry *entry);


/**
 * @brief Encodes a TOTP store (collection of entries) into DER format.
 *
 * @param store Pointer to the TOTP store to encode.
 * @param outLen Pointer to a size_t variable to receive the length of the encoded data.
 *
 * @return Pointer to the allocated DER-encoded buffer on success, or NULL on failure.
 *         The caller is responsible for freeing the returned buffer.
 */
uint8_t *totpStoreEncode(const t_totpStore *store, size_t *outLen);

/**
 * @brief Decodes a DER-encoded TOTP store into a t_totpStore structure.
 *
 * @param der Pointer to the DER-encoded data.
 * @param derLen Length of the DER-encoded data.
 * @param store Pointer to a t_totpStore structure to populate with the decoded data.
 *
 * @return 1 on success, 0 on failure.
 */
int totpStoreDecode(const uint8_t *der, size_t derLen, t_totpStore *store);


/**
 * @brief Converts a TOTP store into PEM format.
 *
 * @param store Pointer to the TOTP store to convert.
 * @param password The password to use for encryption (can be NULL for no encryption).
 * @param cipher The cipher to use for encryption (can be NULL for no encryption).
 *
 * @return Pointer to the allocated PEM-encoded buffer on success, or NULL on failure.
 *         The caller is responsible for freeing the returned buffer.
 */
char *totpStoreToPem(const t_totpStore *store, const char *password, const t_cipher *cipher);

/**
 * @brief Loads a TOTP store from a PEM-encoded string.
 *
 * @param pem The PEM-encoded string containing the TOTP store.
 * @param password The password to use for decryption (can be NULL if not encrypted).
 * @param store Pointer to a t_totpStore structure to populate with the loaded data.
 *
 * @return 1 on success, 0 on failure, 2 if a password is required but not provided.
 */
int totpStoreFromPem(const char *pem, const char *password, t_totpStore *store);

/**
 * @brief Frees the memory associated with a TOTP store.
 *
 * @param store Pointer to the TOTP store to free.
 */
void totpStoreFree(t_totpStore *store);

#endif /* TOTP_H */
