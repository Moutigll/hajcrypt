#ifndef HAJCRYPT_PEM_H
#define HAJCRYPT_PEM_H

#include "../cipher/cipher.h"
#include "pemCipher.h"

typedef struct {
	char	*header;	/* Ex: "RSA PRIVATE KEY" */
	uint8_t	*der;		/* DER-encoded data */
	size_t	derLen;
} t_pemBlock;

/* ---------- Encode ---------- */

/**
 * @brief Encodes DER-formatted data into PEM format.
 * 
 * @param der Pointer to the DER-encoded data buffer.
 * @param derLen Length of the DER data in bytes.
 * @param type Pointer to a null-terminated string specifying the PEM type
 *             (e.g., "CERTIFICATE", "PRIVATE KEY", "PUBLIC KEY").
 * 
 * @return Pointer to a dynamically allocated null-terminated string containing
 *         the PEM-encoded data, or NULL on failure.
 */
char	*pemEncode(const uint8_t *der, size_t derLen, const char *type);

/**
 * @brief Encrypts DER-formatted data and encodes it into PEM format using a specified cipher and password.
 * 
 * @param keyType The PEM header type to use (e.g., "RSA PRIVATE KEY").
 * @param der Pointer to the DER-encoded data buffer to be encrypted.
 * @param derLen Length of the DER data in bytes.
 * @param cipher Pointer to the cipher structure specifying the encryption algorithm and parameters.
 * @param password The password to use for encryption.
 * @return Pointer to a dynamically allocated null-terminated string containing the PEM-encoded encrypted data,
 *		 or NULL on failure.
 */
char *pkcs1EncryptPem(const char		*keyType,
					  const uint8_t		*der,
					  size_t			derLen,
					  const t_cipher	*cipher,
					  const char		*password);

/**
 * @brief Encrypts DER-formatted data using PKCS#8 encryption and encodes it into PEM format.
 * 
 * @param pkcs8Der Pointer to the DER-encoded private key data to be encrypted.
 * @param derLen Length of the DER data in bytes.
 * @param cipher Pointer to the cipher structure specifying the encryption algorithm and parameters.
 * @param password The password to use for encryption.
 * @param params Optional pointer to a t_pkcs8Params structure specifying additional parameters for key derivation and encryption. If NULL, default parameters will be used.
 * @return Pointer to a dynamically allocated null-terminated string containing the PEM-encoded encrypted private key,
 *		 or NULL on failure.
 */
char *pkcs8EncryptPem(const uint8_t			*pkcs8Der,
					  size_t				derLen,
					  const t_cipher		*cipher,
					  const char			*password,
					  const t_pkcs8Params	*params);

/* ---------- Decode ---------- */

/**
 * @brief Decodes PEM-formatted data into DER format.
 * 
 * @param pem Pointer to a null-terminated string containing the PEM data.
 * @param block Pointer to a t_pemBlock structure that will be filled with the
 *              decoded header and DER data. The caller is responsible for
 *              freeing the allocated memory in block->header and block->der
 *              using pemFreeBlock().
 * 
 * @return 1 on success, 0 on failure (e.g., invalid PEM format).
 */
int		pemDecode(const char *pem, t_pemBlock *block);

/**
 * @brief Decrypts a PEM-encoded private key using PKCS#1 legacy decryption.
 * 
 * @param pem Pointer to a null-terminated string containing the PEM-encoded encrypted private key.
 * @param password The password to use for decryption.
 * @param outLen Pointer to a size_t variable where the length of the decrypted DER data will be stored.
 * @return Pointer to a dynamically allocated buffer containing the decrypted DER data, or NULL on failure.
 */
uint8_t *pkcs1DecryptedDer(const char *pem, const char *password, size_t *outLen);

/**
 * @brief Decrypts a PEM-encoded private key using PKCS#8 decryption.
 * 
 * @param pem Pointer to a null-terminated string containing the PEM-encoded encrypted private key.
 * @param password The password to use for decryption.
 * @param outLen Pointer to a size_t variable where the length of the decrypted DER data will be stored.
 * @return Pointer to a dynamically allocated buffer containing the decrypted DER data, or NULL on failure.
 */
uint8_t *pkcs8DecryptedDer(const char *pem, const char *password, size_t *outLen);

/**
 * @brief Frees the memory allocated for a t_pemBlock structure.
 * 
 * @param block Pointer to the t_pemBlock structure to free. After calling this
 *              function, the block's header and der pointers will be set to
 *              NULL and derLen will be set to 0.
 */
void	pemFreeBlock(t_pemBlock *block);

#endif
