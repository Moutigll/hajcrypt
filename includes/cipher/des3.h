#ifndef HAJCRYPT_DES3_H
#define HAJCRYPT_DES3_H

#include "cipher.h"
#include "modes.h"

/**
 * @brief Triple DES ECB context structure.
 */
typedef struct s_des3EcbCtx {
    uint64_t            subkeys1[16];   /* subkeys for K1 */
    uint64_t            subkeys2[16];   /* subkeys for K2 */
    uint64_t            subkeys3[16];   /* subkeys for K3 */
    uint8_t             buffer[8];
    size_t              bufferLen;
    t_cipherDirection   dir;
} t_des3EcbCtx;

/**
 * @brief Triple DES CBC context structure.
 */
typedef struct s_des3CbcCtx {
    t_cbcGenCtx         cbcCtx;
    uint64_t            subkeys1[16];
    uint64_t            subkeys2[16];
    uint64_t            subkeys3[16];
} t_des3CbcCtx;

/**
 * @brief Triple DES CFB context structure.
 */
typedef struct s_des3CfbCtx {
    t_cfbGenCtx         cfbCtx;
    uint64_t            subkeys1[16];
    uint64_t            subkeys2[16];
    uint64_t            subkeys3[16];
} t_des3CfbCtx;

/**
 * @brief Triple DES OFB context structure.
 */
typedef struct s_des3OfbCtx {
    t_ofbGenCtx         ofbCtx;
    uint64_t            subkeys1[16];
    uint64_t            subkeys2[16];
    uint64_t            subkeys3[16];
} t_des3OfbCtx;

/**
 * @brief Triple DES CTR context structure.
 */
typedef struct s_des3CtrCtx {
    t_ctrGenCtx         ctrCtx;
    uint64_t            subkeys1[16];
    uint64_t            subkeys2[16];
    uint64_t            subkeys3[16];
} t_des3CtrCtx;

/**
 * @brief Triple DES PCBC context structure.
 */
typedef struct s_des3PcbcCtx {
    t_pcbcGenCtx        pcbcCtx;
    uint64_t            subkeys1[16];
    uint64_t            subkeys2[16];
    uint64_t            subkeys3[16];
} t_des3PcbcCtx;

/* ---------- Core 3DES operations ---------- */

/**
 * @brief Generates subkeys for all three DES keys from a 24‑byte key.
 *
 * @param key24  24‑byte key (K1, K2, K3)
 * @param subkeys1, subkeys2, subkeys3 output arrays of 16 subkeys each
 */
void    des3GenerateSubkeys(const uint8_t	key24[24],
                            uint64_t		subkeys1[16],
                            uint64_t		subkeys2[16],
                            uint64_t		subkeys3[16]);

/**
 * @brief Encrypts a single 64‑bit block using 3‑key Triple DES (EDE).
 *
 * @param block      plaintext block
 * @param subkeys1, subkeys2, subkeys3 subkey arrays for K1, K2, K3
 * @return encrypted block
 */
uint64_t des3EncryptBlock(uint64_t			block,
                          const uint64_t	subkeys1[16],
                          const uint64_t	subkeys2[16],
                          const uint64_t	subkeys3[16]);

/**
 * @brief Decrypts a single 64‑bit block using 3‑key Triple DES (EDE).
 *
 * @param block      ciphertext block
 * @param subkeys1, subkeys2, subkeys3 subkey arrays for K1, K2, K3
 * @return decrypted block
 */
uint64_t des3DecryptBlock(uint64_t			block,
                          const uint64_t	subkeys1[16],
                          const uint64_t	subkeys2[16],
                          const uint64_t	subkeys3[16]);

/* ---------- Mode-specific functions ---------- */

/* ECB */

/**
 * @brief Initializes Triple DES ECB context with key and direction.
 *
 * @param ctx Pointer to Triple DES ECB context
 * @param key 24-byte key (K1, K2, K3)
 * @param keyLen Length of key (must be 24)
 * @param iv Ignored for ECB mode (can be NULL)
 * @param dir Encryption or decryption direction
 * @return 0 on success, -1 on invalid parameters
 */
int     des3EcbInit(void				*vctx,
					const uint8_t		*key,
					size_t				keyLen,
                    const uint8_t		*iv,
					t_cipherDirection	dir);

/**
 * @brief Updates the Triple DES ECB context with input data.
 *
 * @param ctx Pointer to Triple DES ECB context
 * @param in Input data
 * @param inLen Length of input data
 * @param out Output data
 * @param outLen Length of output data
 */
void    des3EcbUpdate(void			*vctx,
					  const uint8_t	*in,
					  size_t		inLen,
                      uint8_t		*out,
					  size_t		*outLen);

/**
 * @brief Finalizes Triple DES ECB operation, handling padding.
 *
 * For encryption: applies PKCS#7 padding to the last block.
 * For decryption: verifies and removes padding (padding check done separately).
 *
 * @param ctx Pointer to Triple DES ECB context
 * @param out Output buffer for final data
 * @param outLen Number of bytes written to output
 */
void    des3EcbFinal(void *vctx, uint8_t *out, size_t *outLen);

/**
 * @brief Frees Triple DES ECB context resources.
 *
 * @param ctx Pointer to Triple DES ECB context
 */
void    des3EcbFree(void *vctx);



/* CBC */

/**
 * @brief Initializes Triple DES CBC context with key, IV, and direction.
 *
 * @param ctx Pointer to Triple DES CBC context
 * @param key 24-byte key (K1, K2, K3)
 * @param keyLen Length of key (must be 24)
 * @param iv Initialization vector (8 bytes, NULL for zeros)
 * @param dir Encryption or decryption direction
 * @return 0 on success, -1 on invalid parameters
 */
int     des3CbcInit(void				*vctx,
					const uint8_t		*key,
					size_t				keyLen,
                    const uint8_t		*iv,
					t_cipherDirection	dir);

/**
 * @brief Updates the Triple DES CBC context with input data.
 *
 * @param ctx Pointer to Triple DES CBC context
 * @param in Input data
 * @param inLen Length of input data
 * @param out Output data
 * @param outLen Length of output data
 */
void    des3CbcUpdate(void				*vctx,
					  const uint8_t		*in,
					  size_t			inLen,
                      uint8_t			*out,
					  size_t			*outLen);

/**
 * @brief Finalizes Triple DES CBC operation, handling padding.
 *
 * For encryption: applies PKCS#7 padding to the last block.
 * For decryption: verifies and removes padding (padding check done separately).
 *
 * @param ctx Pointer to Triple DES CBC context
 * @param out Output buffer for final data
 * @param outLen Number of bytes written to output
 */
void    des3CbcFinal(void *vctx, uint8_t *out, size_t *outLen);

/**
 * @brief Frees Triple DES CBC context resources.
 *
 * @param ctx Pointer to Triple DES CBC context
 */
void    des3CbcFree(void *vctx);



/* CFB (full‑block, 8‑byte unit) */

/**
 * @brief Initializes Triple DES CFB context with key, IV, and direction.
 *
 * CFB mode operates on blocks, so this function sets up the necessary state.
 *
 * @param ctx Pointer to Triple DES CFB context
 * @param key 24-byte key (K1, K2, K3)
 * @param keyLen Length of key (must be 24)
 * @param iv Initialization vector (8 bytes, NULL for zeros)
 * @param dir Encryption or decryption direction
 * @return 0 on success, -1 on invalid parameters
 */
int     des3CfbInit(void				*vctx,
					const uint8_t		*key,
					size_t				keyLen,
                    const uint8_t		*iv,
					t_cipherDirection	dir);

/**
 * @brief Initializes Triple DES CFB8 context with key, IV, and direction.
 *
 * CFB8 mode operates on 8-bit units, so this function sets up the necessary state.
 *
 * @param ctx Pointer to Triple DES CFB8 context
 * @param key 24-byte key (K1, K2, K3)
 * @param keyLen Length of key (must be 24)
 * @param iv Initialization vector (8 bytes, NULL for zeros)
 * @param dir Encryption or decryption direction
 * @return 0 on success, -1 on invalid parameters
 */
int	 des3Cfb1Init(void					*vctx,
					 const uint8_t		*key,
					 size_t				keyLen,
					 const uint8_t		*iv,
					 t_cipherDirection	dir);

/**
 * @brief Initializes Triple DES CFB8 context with key, IV, and direction.
 *
 * CFB8 mode operates on 8-bit units, so this function sets up the necessary state.
 *
 * @param ctx Pointer to Triple DES CFB8 context
 * @param key 24-byte key (K1, K2, K3)
 * @param keyLen Length of key (must be 24)
 * @param iv Initialization vector (8 bytes, NULL for zeros)
 * @param dir Encryption or decryption direction
 * @return 0 on success, -1 on invalid parameters
 */
int	 des3Cfb8Init(void					*vctx,
					 const uint8_t		*key,
					 size_t				keyLen,
					 const uint8_t		*iv,
					 t_cipherDirection	dir);

/**
 * @brief Updates the Triple DES CFB context with input data.
 *
 * CFB mode can operate on partial blocks, so this function handles buffering.
 *
 * @param ctx Pointer to Triple DES CFB context
 * @param in Input data
 * @param inLen Length of input data
 * @param out Output data
 * @param outLen Length of output data
 */
void    des3CfbUpdate(void			*vctx,
					  const uint8_t	*in,
					  size_t		inLen,
                      uint8_t		*out,
					  size_t		*outLen);

/**
 * @brief Updates the Triple DES CFB1 context with input data (bit-oriented).
 *
 * CFB1 mode operates on individual bits, so this function handles bit-level processing.
 *
 * @param ctx Pointer to Triple DES CFB context
 * @param in Input data
 * @param inLen Length of input data in bytes (will be treated as bits)
 * @param out Output data
 * @param outBits Number of bits written to output
 */
void	des3Cfb1Update(void				*vctx,
					   const uint8_t	*in,
					   size_t			inLen,
					   uint8_t			*out,
					   size_t			*outLen);

/**
 * @brief Finalizes Triple DES CFB operation.
 *
 * CFB mode does not require special finalization, but this function can be used to flush any remaining data.
 * @param ctx Pointer to Triple DES CFB context
 * @param out Output buffer for final data
 * @param outLen Number of bytes written to output
 */
void    des3CfbFinal(void *vctx, uint8_t *out, size_t *outLen);

/**
 * @brief Finalizes Triple DES CFB1 operation.
 *
 * CFB mode does not require special finalization, but this function can be used to flush any remaining data.
 * @param ctx Pointer to Triple DES CFB context
 * @param out Output buffer for final data
 * @param outBits Number of bits written to output (for CFB1)
 */
void	des3Cfb1Final(void *vctx, uint8_t *out, size_t *outBits);

/**
 * @brief Frees Triple DES CFB context resources.
 *
 * @param ctx Pointer to Triple DES CFB context
 */
void    des3CfbFree(void *vctx);



/* OFB */

/**
 * @brief Initializes Triple DES OFB context with key, IV, and direction.
 *
 * @param ctx Pointer to Triple DES OFB context
 * @param key 24-byte key (K1, K2, K3)
 * @param keyLen Length of key (must be 24)
 * @param iv Initialization vector (8 bytes, NULL for zeros)
 * @param dir Encryption or decryption direction
 * @return 0 on success, -1 on invalid parameters
 */
int     des3OfbInit(void				*vctx,
					const uint8_t		*key,
					size_t				keyLen,
                    const uint8_t		*iv,
					t_cipherDirection	dir);

/**
 * @brief Updates the Triple DES OFB context with input data.
 *
 * @param ctx Pointer to Triple DES OFB context
 * @param in Input data
 * @param inLen Length of input data
 * @param out Output data
 * @param outLen Length of output data
 */
void    des3OfbUpdate(void			*vctx,
					  const uint8_t	*in,
					  size_t		inLen,
                      uint8_t		*out,
					  size_t		*outLen);

/**
 * @brief Finalizes Triple DES OFB operation.
 *
 * @param ctx Pointer to Triple DES OFB context
 * @param out Output buffer for final data
 * @param outLen Number of bytes written to output
 */
void    des3OfbFinal(void *vctx, uint8_t *out, size_t *outLen);

/**
 * @brief Frees Triple DES OFB context resources.
 *
 * @param ctx Pointer to Triple DES OFB context
 */
void    des3OfbFree(void *vctx);



/* CTR */

/**
 * @brief Initializes Triple DES CTR context with key, IV, and direction.
 *
 * @param ctx Pointer to Triple DES CTR context
 * @param key 24-byte key (K1, K2, K3)
 * @param keyLen Length of key (must be 24)
 * @param iv Initialization vector (8 bytes, NULL for zeros)
 * @param dir Encryption or decryption direction
 * @return 0 on success, -1 on invalid parameters
 */
int     des3CtrInit(void				*vctx,
					const uint8_t		*key,
					size_t				keyLen,
                    const uint8_t		*iv,
					t_cipherDirection	dir);

/**
 * @brief Updates the Triple DES CTR context with input data.
 *
 * @param ctx Pointer to Triple DES CTR context
 * @param in Input data
 * @param inLen Length of input data
 * @param out Output data
 * @param outLen Length of output data
 */
void    des3CtrUpdate(void			*vctx,
					  const uint8_t	*in,
					  size_t		inLen,
                      uint8_t		*out,
					  size_t		*outLen);

/**
 * @brief Finalizes Triple DES CTR operation.
 *
 * @param ctx Pointer to Triple DES CTR context
 * @param out Output buffer for final data
 * @param outLen Number of bytes written to output
 */
void    des3CtrFinal(void *vctx, uint8_t *out, size_t *outLen);

/**
 * @brief Frees Triple DES CTR context resources.
 *
 * @param ctx Pointer to Triple DES CTR context
 */
void    des3CtrFree(void *vctx);



/* PCBC */

/**
 * @brief Initializes Triple DES PCBC context with key, IV, and direction.
 *
 * @param ctx Pointer to Triple DES PCBC context
 * @param key 24-byte key (K1, K2, K3)
 * @param keyLen Length of key (must be 24)
 * @param iv Initialization vector (8 bytes, NULL for zeros)
 * @param dir Encryption or decryption direction
 * @return 0 on success, -1 on invalid parameters
 */
int     des3PcbcInit(void				*vctx,
					 const uint8_t		*key,
					 size_t				keyLen,
                     const uint8_t		*iv,
					 t_cipherDirection	dir);

/**
 * @brief Updates the Triple DES PCBC context with input data.
 *
 * @param ctx Pointer to Triple DES PCBC context
 * @param in Input data
 * @param inLen Length of input data
 * @param out Output data
 * @param outLen Length of output data
 */
void    des3PcbcUpdate(void				*vctx,
					   const uint8_t	*in,
					   size_t			inLen,
					   uint8_t			*out,
					   size_t			*outLen);

/**
 * @brief Finalizes Triple DES PCBC operation, handling padding.
 *
 * For encryption: applies PKCS#7 padding to the last block.
 * For decryption: verifies and removes padding (padding check done separately).
 *
 * @param ctx Pointer to Triple DES PCBC context
 * @param out Output buffer for final data
 * @param outLen Number of bytes written to output
 */
void    des3PcbcFinal(void *vctx, uint8_t *out, size_t *outLen);

/**
 * @brief Frees Triple DES PCBC context resources.
 *
 * @param ctx Pointer to Triple DES PCBC context
 */
void    des3PcbcFree(void *vctx);

/* ---------- Global cipher structures ---------- */

extern const t_cipher   g_des3Cipher;
extern const t_cipher   g_des3EcbCipher;
extern const t_cipher   g_des3CbcCipher;
extern const t_cipher   g_des3CfbCipher;
extern const t_cipher   g_des3Cfb1Cipher;
extern const t_cipher   g_des3Cfb8Cipher;
extern const t_cipher   g_des3OfbCipher;
extern const t_cipher   g_des3CtrCipher;
extern const t_cipher   g_des3PcbcCipher;

#endif /* HAJCRYPT_DES3_H */
