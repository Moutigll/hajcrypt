#ifndef MD5_H
#define MD5_H

#include <stdint.h>
#include <stddef.h>

typedef struct s_md5Ctx
{
    uint32_t	state[4];
    uint64_t	bitlen;
    uint8_t		buffer[64];
}   t_md5Ctx;

void	md5Init(void *ctx);

void	md5Update(	void			*ctx,
					const uint8_t	*data,
					size_t			len);

void	md5Final(uint8_t *digest, void *ctx);

#endif
