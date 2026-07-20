#ifndef HAJCRYPT_TOTP_H
#define HAJCRYPT_TOTP_H

#include <stdint.h>
#include <stddef.h>
#include "hash/hmac.h"

typedef struct s_totpConfig {
	const t_hash	*algo;	/* Hash algorithm (SHA1, SHA256, SHA512) */
	uint8_t			digits; /* Number of digits in the TOTP code (6 or 8) */
	uint32_t		period;	/* Time step in seconds (default 30) */
	uint32_t		window;	/* Number of time steps to check for verification (default 1) */
} t_totpConfig;

typedef struct s_totpCtx {
	uint8_t			secret[64];
	size_t			secretLen;
	t_totpConfig	config;
} t_totpCtx;




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
int totpInit(t_totpCtx *ctx, const char *secretBase32, const t_hash *algo, uint8_t digits, uint32_t period);

/**
 * @brief Initializes a TOTP context with the given secret and configuration.
 *
 * @param ctx Pointer to the TOTP context to initialize.
 * @param secretBase32 The Base32-encoded secret key.
 * @param config Pointer to a t_totpConfig structure containing the configuration parameters.
 *
 * @return 0 on success, non-zero on failure.
 */
int totpInitWithConfig(t_totpCtx *ctx, const char *secretBase32, const t_totpConfig *config);

/**
 * @brief Generates a TOTP code for the given timestamp.
 *
 * @param ctx Pointer to the initialized TOTP context.
 * @param timestamp The current timestamp in seconds since the epoch.
 * @param code A buffer to store the generated TOTP code (should be at least 9 bytes for 8 digits + null terminator).
 *
 * @return 0 on success, non-zero on failure.
 */
int totpGenerate(t_totpCtx *ctx, uint64_t timestamp, char *code);

/**
 * @brief Verifies a TOTP code against the expected value for the given timestamp.
 *
 * @param ctx Pointer to the initialized TOTP context.
 * @param code The TOTP code to verify (as a null-terminated string).
 * @param timestamp The current timestamp in seconds since the epoch.
 *
 * @return 1 if the code is valid, 0 if invalid, and -1 on error.
 */
int totpVerify(t_totpCtx *ctx, const char *code, uint64_t timestamp);

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
 * @param config Pointer to a t_totpConfig structure containing the configuration parameters.
 * @param output A buffer to store the generated URI (should be large enough to hold the URI).
 * @param outputSize The size of the output buffer.
 *
 * @return 0 on success, non-zero on failure.
 */
int totpCreateUri(const char			*userEmail,
				  const char			*secretBase32,
				  const char			*issuer,
				  const t_totpConfig	*config,
				  char					*output,	size_t	outputSize);

/**
 * @brief Initializes a TOTP context from a TOTP URI.
 *
 * @param ctx Pointer to the TOTP context to initialize.
 * @param uri The TOTP URI to parse (should start with "otpauth://totp/").
 *
 * @return 0 on success, non-zero on failure.
 */
int totpInitFromUri(t_totpCtx *ctx, const char *uri);

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

#endif /* TOTP_H */
