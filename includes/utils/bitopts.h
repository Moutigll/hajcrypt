#ifndef HAJCRYPT_BITOPTS_H
# define HAJCRYPT_BITOPTS_H

#include <stdint.h>


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

#endif /* HAJCRYPT_BITOPTS_H */
