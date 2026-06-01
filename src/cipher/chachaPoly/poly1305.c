#include "../../../hajlib/include/hmemory.h"
#include "../../../includes/utils/bitopts.h"

#include "../../../includes/cipher/chacha20Poly1305.h"

static void poly1305Clamp(uint8_t r[16])
{
	r[3] &= 0x0F;
	r[7] &= 0x0F;
	r[11] &= 0x0F;
	r[15] &= 0x0F;
	r[4] &= 0xFC;
	r[8] &= 0xFC;
	r[12] &= 0xFC;
}

/**
 * @brief Adds a 16-byte block to the Poly1305 accumulator and multiplies by r.
 *
 * Parses the input block into 26-bit limbs, conditionally appends the
 * Poly1305 "1" bit for non-final blocks, accumulates into h, performs
 * multiplication by r with reduction modulo 2^130-5, and keeps h in
 * reduced limb form. Final reduction is completed in poly1305Final().
 *
 * @param ctx   Pointer to the Poly1305 context containing h and r.
 * @param block Pointer to the 16-byte input block.
 * @param final Non-zero if this is the final (possibly partial) block.
 */
static void poly1305AddBlock(t_poly1305Ctx *ctx, const uint8_t *block, int final)
{
	uint32_t	t[5];
	uint64_t	d[5];
	uint32_t	carry;
	uint32_t	b0, b1, b2, b3;

	b0 = load32(block + 0);
	b1 = load32(block + 4);
	b2 = load32(block + 8);
	b3 = load32(block + 12);


	t[0] = b0 & 0x3FFFFFF;
	t[1] = ((b0 >> 26) | (b1 <<  6)) & 0x3FFFFFF;
	t[2] = ((b1 >> 20) | (b2 << 12)) & 0x3FFFFFF;
	t[3] = ((b2 >> 14) | (b3 << 18)) & 0x3FFFFFF;
	t[4] = (b3 >>  8) & 0x3FFFFFF;
	if (!final)
		t[4] |= (1UL << 24);

	carry = 0;
	for (int i = 0; i < 5; i++) {
		uint64_t sum = (uint64_t)ctx->h[i] + t[i] + carry;
		ctx->h[i] = sum & 0x3FFFFFF;
		carry = sum >> 26;
	}

	ctx->h[0] += carry * 5;
	carry = ctx->h[0] >> 26; ctx->h[0] &= 0x3FFFFFF;
	ctx->h[1] += carry; carry = ctx->h[1] >> 26; ctx->h[1] &= 0x3FFFFFF;
	ctx->h[2] += carry; carry = ctx->h[2] >> 26; ctx->h[2] &= 0x3FFFFFF;
	ctx->h[3] += carry; carry = ctx->h[3] >> 26; ctx->h[3] &= 0x3FFFFFF;
	ctx->h[4] += carry;

	uint32_t	r0 = ctx->r[0], r1 = ctx->r[1], r2 = ctx->r[2], r3 = ctx->r[3], r4 = ctx->r[4];
	uint32_t	s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;

	d[0] = (uint64_t)ctx->h[0] * r0 + (uint64_t)ctx->h[1] * s4 + (uint64_t)ctx->h[2] * s3 + (uint64_t)ctx->h[3] * s2 + (uint64_t)ctx->h[4] * s1;
	d[1] = (uint64_t)ctx->h[0] * r1 + (uint64_t)ctx->h[1] * r0 + (uint64_t)ctx->h[2] * s4 + (uint64_t)ctx->h[3] * s3 + (uint64_t)ctx->h[4] * s2;
	d[2] = (uint64_t)ctx->h[0] * r2 + (uint64_t)ctx->h[1] * r1 + (uint64_t)ctx->h[2] * r0 + (uint64_t)ctx->h[3] * s4 + (uint64_t)ctx->h[4] * s3;
	d[3] = (uint64_t)ctx->h[0] * r3 + (uint64_t)ctx->h[1] * r2 + (uint64_t)ctx->h[2] * r1 + (uint64_t)ctx->h[3] * r0 + (uint64_t)ctx->h[4] * s4;
	d[4] = (uint64_t)ctx->h[0] * r4 + (uint64_t)ctx->h[1] * r3 + (uint64_t)ctx->h[2] * r2 + (uint64_t)ctx->h[3] * r1 + (uint64_t)ctx->h[4] * r0;

	carry = d[0] >> 26; ctx->h[0] = d[0] & 0x3FFFFFF;
	carry = (d[1] += carry) >> 26; ctx->h[1] = d[1] & 0x3FFFFFF;
	carry = (d[2] += carry) >> 26; ctx->h[2] = d[2] & 0x3FFFFFF;
	carry = (d[3] += carry) >> 26; ctx->h[3] = d[3] & 0x3FFFFFF;
	carry = (d[4] += carry) >> 26; ctx->h[4] = d[4] & 0x3FFFFFF;

	ctx->h[0] += carry * 5;
	carry = ctx->h[0] >> 26; ctx->h[0] &= 0x3FFFFFF;
	ctx->h[1] += carry; carry = ctx->h[1] >> 26; ctx->h[1] &= 0x3FFFFFF;
	ctx->h[2] += carry; carry = ctx->h[2] >> 26; ctx->h[2] &= 0x3FFFFFF;
	ctx->h[3] += carry; carry = ctx->h[3] >> 26; ctx->h[3] &= 0x3FFFFFF;
	ctx->h[4] += carry;
}



void poly1305Init(t_poly1305Ctx *ctx, const uint8_t key[POLY1305_KEY_SIZE])
{
	uint8_t r_bytes[16];
	ft_memcpy(r_bytes, key, 16);
	poly1305Clamp(r_bytes);

	uint32_t r0 = load32(r_bytes + 0);
	uint32_t r1 = load32(r_bytes + 4);
	uint32_t r2 = load32(r_bytes + 8);
	uint32_t r3 = load32(r_bytes + 12);

	ctx->r[0] = r0 & 0x3FFFFFF;
	ctx->r[1] = ((r0 >> 26) | (r1 <<  6)) & 0x3FFFFFF;
	ctx->r[2] = ((r1 >> 20) | (r2 << 12)) & 0x3FFFFFF;
	ctx->r[3] = ((r2 >> 14) | (r3 << 18)) & 0x3FFFFFF;
	ctx->r[4] = (r3 >>  8) & 0x3FFFFFF;

	ctx->s[0] = load32(key + 16);
	ctx->s[1] = load32(key + 20);
	ctx->s[2] = load32(key + 24);
	ctx->s[3] = load32(key + 28);

	ft_memset(ctx->h, 0, sizeof(ctx->h));
	ctx->bufferLen = 0;
	ctx->totalLen = 0;
}

void poly1305Update(t_poly1305Ctx *ctx, const uint8_t *data, size_t len)
{
	if (!ctx || !len) return;
	ctx->totalLen += len;

	if (ctx->bufferLen) {
		size_t avail = 16 - ctx->bufferLen;
		if (len < avail) {
			ft_memcpy(ctx->buffer + ctx->bufferLen, data, len);
			ctx->bufferLen += len;
			return;
		}
		ft_memcpy(ctx->buffer + ctx->bufferLen, data, avail);
		poly1305AddBlock(ctx, ctx->buffer, 0);
		data += avail;
		len -= avail;
		ctx->bufferLen = 0;
	}

	while (len >= 16) {
		poly1305AddBlock(ctx, data, 0);
		data += 16;
		len -= 16;
	}

	if (len) {
		ft_memcpy(ctx->buffer, data, len);
		ctx->bufferLen = len;
	}
}

void poly1305Final(t_poly1305Ctx *ctx, uint8_t tag[POLY1305_TAG_SIZE])
{
	/* Process the last (possibly incomplete) block, adding the 0x01 byte */
	if (ctx->bufferLen) {
		ctx->buffer[ctx->bufferLen] = 0x01;
		ft_memset(ctx->buffer + ctx->bufferLen + 1, 0,
			16 - ctx->bufferLen - 1);
		poly1305AddBlock(ctx, ctx->buffer, 1);
	}

	/* Fully reduce h modulo 2^130-5 */
	uint32_t carry = 0;
	for (int i = 0; i < 5; i++) {
		uint64_t sum = (uint64_t)ctx->h[i] + carry;
		ctx->h[i] = sum & 0x3FFFFFF;
		carry = sum >> 26;
	}
	/* carry can be 0 or 1 (since h < 2^131) */
	ctx->h[0] += carry * 5;
	/* Propagate the possible new carry */
	carry = ctx->h[0] >> 26;
	ctx->h[0] &= 0x3FFFFFF;
	for (int i = 1; i < 5; i++) {
		ctx->h[i] += carry;
		carry = ctx->h[i] >> 26;
		ctx->h[i] &= 0x3FFFFFF;
	}
	/* now ctx->h[4] < 2^26 + 5, still need final reduction */

	/* Constant‑time subtraction of p = 2^130-5 */
	uint32_t g[5];
	carry = 5;
	for (int i = 0; i < 5; i++) {
		uint64_t sum = (uint64_t)ctx->h[i] + carry;
		g[i] = sum & 0x3FFFFFF;
		carry = sum >> 26;
	}
	/* If carry == 1, then h >= p, use g (the subtracted value) */
	uint32_t mask = 0 - carry;  /* all ones if carry == 1, else zero */
	for (int i = 0; i < 5; i++)
		ctx->h[i] = (ctx->h[i] & ~mask) | (g[i] & mask);

	/* Reconstruct 128‑bit little‑endian integer from the 5 limbs */
	uint32_t w0 = ctx->h[0] | ((ctx->h[1] & 0x3F) << 26);
	uint32_t w1 = (ctx->h[1] >> 6) | ((ctx->h[2] & 0xFFF) << 20);
	uint32_t w2 = (ctx->h[2] >> 12) | ((ctx->h[3] & 0x3FFFF) << 14);
	uint32_t w3 = (ctx->h[3] >> 18) | (ctx->h[4] << 8);

	/* Add the secret s (mod 2^128) */
	uint64_t sum;
	sum = (uint64_t)w0 + ctx->s[0];
	store32(tag +  0, (uint32_t)sum);
	sum = (uint64_t)w1 + ctx->s[1] + (sum >> 32);
	store32(tag +  4, (uint32_t)sum);
	sum = (uint64_t)w2 + ctx->s[2] + (sum >> 32);
	store32(tag +  8, (uint32_t)sum);
	sum = (uint64_t)w3 + ctx->s[3] + (sum >> 32);
	store32(tag + 12, (uint32_t)sum);
}
