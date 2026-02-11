#ifndef HAJCRYPT_HASH_H
#define HAJCRYPT_HASH_H

#include <stddef.h>
#include <stdint.h>

typedef struct s_hash
{
    void	(*init)(void *ctx);
    void	(*update)(void *ctx, const uint8_t *data, size_t len);
    void	(*final)(uint8_t *digest, void *ctx);
    size_t	ctxSize;
    size_t	digestSize;
}   t_hash;

#endif	/* HAJCRYPT_HASH_H */
