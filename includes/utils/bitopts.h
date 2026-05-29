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

#endif /* HAJCRYPT_BITOPTS_H */
