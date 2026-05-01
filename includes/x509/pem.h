#ifndef HAJCRYPT_PEM_H
#define HAJCRYPT_PEM_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
	char	*header;	/* Ex: "RSA PRIVATE KEY" */
	uint8_t	*der;		/* DER-encoded data */
	size_t	derLen;
} t_pem_block;

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

/* ---------- Decode ---------- */

/**
 * @brief Decodes PEM-formatted data into DER format.
 * 
 * @param pem Pointer to a null-terminated string containing the PEM data.
 * @param block Pointer to a t_pem_block structure that will be filled with the
 *              decoded header and DER data. The caller is responsible for
 *              freeing the allocated memory in block->header and block->der
 *              using pemFreeBlock().
 * 
 * @return 1 on success, 0 on failure (e.g., invalid PEM format).
 */
int		pemDecode(const char *pem, t_pem_block *block);

/**
 * @brief Frees the memory allocated for a t_pem_block structure.
 * 
 * @param block Pointer to the t_pem_block structure to free. After calling this
 *              function, the block's header and der pointers will be set to
 *              NULL and derLen will be set to 0.
 */
void	pemFreeBlock(t_pem_block *block);

#endif
