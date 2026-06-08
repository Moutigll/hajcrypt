#ifndef HAJCRYPT_BITOPTS_H
# define HAJCRYPT_BITOPTS_H

#include <stdint.h>

#include "../../hajlib/include/hmemory.h"

/**
 * @brief Performs a circular left rotation (ROL) on a 32-bit integer.
 *
 * This function shifts the bits of x to the left by n positions.
 * Bits that overflow on the left are wrapped around to the right.
 *
 * @param x The 32-bit integer to rotate.
 * @param n The number of bits to rotate.
 * @return The rotated 32-bit integer.
 */
static inline uint32_t rotateLeft(uint32_t x, uint32_t n)
{
	/**
	 * 1. shift left of n bits; ex: 0b011010 << 2 = 0b101000
	 * 2. shift right of (32 - n) bits; ex: 0b011010 >> (32 - 30) = 0b000110
	 * 3. bitwise OR of the two results; here 0b101000 | 0b000110 = 0b101110
	 */
	return (x << n) | (x >> (32 - n));
}

#if defined(__aarch64__) && defined(__ARM_FEATURE_CRYPTO)

#include <arm_neon.h>

static inline uint32x4_t neonRol(uint32x4_t v, const int n)
{
	int32x4_t shift_left  = vdupq_n_s32(n);
	int32x4_t shift_right = vdupq_n_s32(n - 32);
	return vorrq_u32(vshlq_u32(v, shift_left), vshlq_u32(v, shift_right));
}

#endif /* NEON */

/**
 * @brief Performs a circular right rotation (ROR) on a 32-bit integer.
 *
 * This function shifts the bits of x to the right by n positions.
 * Bits that underflow on the right are wrapped around to the left.
 * 
 * @param x The 32-bit integer to rotate.
 * @param n The number of bits to rotate.
 * @return The rotated 32-bit integer.
 */
static inline uint32_t rotateRight(uint32_t x, uint32_t n)
{
	return (x >> n) | (x << (32 - n));
}

/**
 * @brief Performs a circular right rotation (ROR) on a 64-bit integer.
 *
 * This function shifts the bits of x to the right by n positions.
 * Bits that underflow on the right are wrapped around to the left.
 * 
 * @param x The 64-bit integer to rotate.
 * @param n The number of bits to rotate.
 * @return The rotated 64-bit integer.
 */
static inline uint64_t rotr64(uint64_t x, uint64_t n)
{
	return (x >> n) | (x << (64 - n));
}

/* Store a 32-bit integer in little-endian format */
static inline void store32(void *dst, uint32_t w) {
#if defined(NATIVE_LITTLE_ENDIAN)
	ft_memcpy(dst, &w, sizeof w);
#else
	uint8_t *p = (uint8_t *)dst;
	*p++ = (uint8_t)w;
	w >>= 8;
	*p++ = (uint8_t)w;
	w >>= 8;
	*p++ = (uint8_t)w;
	w >>= 8;
	*p++ = (uint8_t)w;
#endif
}

static inline uint32_t load32(const uint8_t *src) {
#if defined(NATIVE_LITTLE_ENDIAN)
	uint32_t w;
	ft_memcpy(&w, src, sizeof w);
	return w;
#else
	return ((uint32_t)src[0]) |
	       ((uint32_t)src[1] << 8) |
	       ((uint32_t)src[2] << 16) |
	       ((uint32_t)src[3] << 24);
#endif
}

static inline void store32Be(void *dst, uint32_t w) {
#if defined(NATIVE_BIG_ENDIAN)
	ft_memcpy(dst, &w, sizeof w);
#else
	uint8_t *p = (uint8_t *)dst;
	*p++ = (uint8_t)(w >> 24);
	*p++ = (uint8_t)(w >> 16);
	*p++ = (uint8_t)(w >> 8);
	*p++ = (uint8_t)w;
#endif
}

static inline uint32_t load32Be(const uint8_t *src) {
#if defined(NATIVE_BIG_ENDIAN)
	uint32_t w;
	ft_memcpy(&w, src, sizeof w);
	return (w);
#else
	return ((uint32_t)src[0] << 24) |
	       ((uint32_t)src[1] << 16) |
	       ((uint32_t)src[2] << 8) |
	       ((uint32_t)src[3]);
#endif
}

/* Store a 64-bit integer in little-endian format */
static inline void store64(void *dst, uint64_t w) {
#if defined(NATIVE_LITTLE_ENDIAN)
	ft_memcpy(dst, &w, sizeof w);
#else
	uint8_t *p = (uint8_t *)dst;
	*p++ = (uint8_t)w;
	w >>= 8;
	*p++ = (uint8_t)w;
	w >>= 8;
	*p++ = (uint8_t)w;
	w >>= 8;
	*p++ = (uint8_t)w;
	w >>= 8;
	*p++ = (uint8_t)w;
	w >>= 8;
	*p++ = (uint8_t)w;
	w >>= 8;
	*p++ = (uint8_t)w;
	w >>= 8;
	*p++ = (uint8_t)w;
#endif
}

/* Load a 64-bit integer in big-endian format */
static inline uint64_t load64Be(const uint8_t *src)
{
	return ((uint64_t)src[0] << 56) |
		   ((uint64_t)src[1] << 48) |
		   ((uint64_t)src[2] << 40) |
		   ((uint64_t)src[3] << 32) |
		   ((uint64_t)src[4] << 24) |
		   ((uint64_t)src[5] << 16) |
		   ((uint64_t)src[6] << 8)  |
		   ((uint64_t)src[7]);
}

/* Store a 64-bit integer in big-endian format */
static inline void store64Be(void *dst, uint64_t w)
{
	uint8_t *p = (uint8_t *)dst;
	p[0] = (w >> 56) & 0xFF;
	p[1] = (w >> 48) & 0xFF;
	p[2] = (w >> 40) & 0xFF;
	p[3] = (w >> 32) & 0xFF;
	p[4] = (w >> 24) & 0xFF;
	p[5] = (w >> 16) & 0xFF;
	p[6] = (w >> 8)  & 0xFF;
	p[7] = w & 0xFF;
}

static inline void writeUint16(uint8_t *out, uint16_t value)
{
	out[0] = (value >> 8) & 0xFF;
	out[1] = value & 0xFF;
}

static inline uint16_t readUint16(const uint8_t *data)
{
	return ((uint16_t)data[0] << 8) | data[1];
}

static inline uint32_t readUint24(const uint8_t *data)
{
	return ((uint32_t)data[0] << 16) | ((uint32_t)data[1] << 8) | data[2];
}

static inline uint32_t readUint32(const uint8_t *data)
{
	return ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
		   ((uint32_t)data[2] << 8) | data[3];
}

#endif /* HAJCRYPT_BITOPTS_H */
