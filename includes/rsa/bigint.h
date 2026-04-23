#ifndef HAJCRYPT_BIGINT_H
#define HAJCRYPT_BIGINT_H

#include <stdint.h>
#include <stddef.h>

typedef struct s_bigInt {
	uint64_t	*words;
	size_t		numWords;
	size_t		used;
	int			sign;
} t_bigInt;

/* ---------- Allocation and basic operations ---------- */


/**
 * @brief Allocates and initializes a new big integer structure.
 * 
 * Creates a dynamically allocated big integer capable of storing the specified
 * number of words. The allocated memory is initialized and ready for use.
 * 
 * @param numWords The number of words to allocate for the big integer.
 * @return A pointer to the newly allocated t_bigInt structure,
 *         or NULL if memory allocation fails.
 */
t_bigInt	*bigIntNew(size_t numWords);

/**
 * @brief Converts a 64-bit unsigned integer to a big integer.
 * 
 * Allocates and initializes a new big integer structure from the given
 * unsigned 64-bit integer value.
 * 
 * @param val The 64-bit unsigned integer value to convert.
 * @return A pointer to a newly allocated t_bigInt structure containing
 *         the value, or NULL if memory allocation fails.
 */
t_bigInt	*bigIntFromUint64(uint64_t val);

/**
 * @brief Converts a hexadecimal string to a big integer.
 * 
 * Allocates and initializes a new big integer structure from the given
 * hexadecimal string representation.
 * 
 * @param hexStr The hexadecimal string to convert.
 * @param hexStrLen The length of the hexadecimal string.
 * @return A pointer to a newly allocated t_bigInt structure containing
 *         the value, or NULL if memory allocation fails or if the string is
 *         invalid.
 */
t_bigInt	*bigIntFromHex(const char *hexStr, size_t hexStrLen);

/**
 * @brief Frees the memory allocated for a big integer structure.
 * 
 * Deallocates all dynamically allocated memory associated with the given
 * big integer structure and sets the pointer to NULL.
 * 
 * @param n Pointer to the t_bigInt structure to be freed.
 */
void		bigIntFree(t_bigInt *n);

/**
 * @brief Sets a big integer to zero.
 * 
 * Resets the given big integer structure to represent the value zero by
 * clearing all words and resetting the used count and sign.
 * 
 * @param n Pointer to the t_bigInt structure to be zeroed.
 */
void		bigIntZero(t_bigInt *n);

/**
 * @brief Creates a duplicate of a big integer structure.
 * 
 * Allocates and initializes a new big integer structure that is an exact
 * copy of the given source big integer.
 * 
 * @param src Pointer to the t_bigInt structure to be duplicated.
 * @return A pointer to the newly allocated t_bigInt structure containing
 *         the same value as src, or NULL if memory allocation fails.
 */
t_bigInt	*bigIntDup(const t_bigInt *src);

/**
 * @brief Copies the value of one big integer to another.
 * 
 * Copies the value from the source big integer structure to the destination
 * big integer structure. The destination must have enough allocated space to
 * hold the value of the source.
 * 
 * @param dst Pointer to the t_bigInt structure where the value will be copied.
 * @param src Pointer to the t_bigInt structure containing the value to copy.
 * @return A pointer to dst if the copy is successful, or NULL if dst is
 *         NULL, src is NULL, or dst does not have enough space to hold src.
 */
t_bigInt	*bigIntCopy(t_bigInt *dst, const t_bigInt *src);





/* ---------- Comparisons ---------- */

/**
 * @brief Compares two big integer structures.
 * 
 * Compares the values of two big integer structures and determines their
 * relative order.
 * 
 * @param a Pointer to the first t_bigInt structure to compare.
 * @param b Pointer to the second t_bigInt structure to compare.
 * @return 1 if a is greater than b, -1 if a is less than b, or 0 if they
 *         are equal.
 */
int	bigIntCmp(const t_bigInt *a, const t_bigInt *b);

/**
 * @brief Checks if a big integer is zero.
 * 
 * Determines whether the given big integer structure represents the value zero.
 * 
 * @param n Pointer to the t_bigInt structure to check.
 * @return 1 if n is zero, or 0 otherwise.
 */
int	bigIntIsZero(const t_bigInt *n);

/**
 * @brief Checks if a big integer is odd.
 * 
 * Determines whether the given big integer structure represents an odd number.
 * 
 * @param n Pointer to the t_bigInt structure to check.
 * @return 1 if n is odd, or 0 otherwise.
 */
int	bigIntIsOdd(const t_bigInt *n);

/**
 * @brief Checks if a big integer is even.
 * 
 * Determines whether the given big integer structure represents an even number.
 * 
 * @param n Pointer to the t_bigInt structure to check.
 * @return 1 if n is even, or 0 otherwise.
 */
int	bigIntIsEven(const t_bigInt *n);

/* ---------- Arithmetic Operations ---------- */

/**
 * @brief Adds two big integers.
 * 
 * Adds the values of two big integer structures and stores the result in the third.
 * 
 * @param result Pointer to the t_bigInt structure where the result will be stored.
 * @param a Pointer to the first t_bigInt structure to add.
 * @param b Pointer to the second t_bigInt structure to add.
 * @return A pointer to result if the addition is successful, or NULL if an error occurs.
 */
t_bigInt	*bigIntAdd(t_bigInt *result, const t_bigInt *a, const t_bigInt *b);

/**
 * @brief Subtracts one big integer from another.
 * 
 * Subtracts the value of the second big integer structure from the first and
 * stores the result in the third. The function assumes that a >= b.
 * 
 * @param result Pointer to the t_bigInt structure where the result will be stored.
 * @param a Pointer to the t_bigInt structure to subtract from.
 * @param b Pointer to the t_bigInt structure to subtract.
 * @return A pointer to result if the subtraction is successful, or NULL if an error occurs.
 */
t_bigInt	*bigIntSub(t_bigInt *result, const t_bigInt *a, const t_bigInt *b);

/**
 * @brief Multiplies two big integers.
 * 
 * Multiplies the values of two big integer structures and stores the result in the third.
 * 
 * @param result Pointer to the t_bigInt structure where the result will be stored.
 * @param a Pointer to the first t_bigInt structure to multiply.
 * @param b Pointer to the second t_bigInt structure to multiply.
 * @return A pointer to result if the multiplication is successful, or NULL if an error occurs.
 */
t_bigInt	*bigIntMul(t_bigInt *result, const t_bigInt *a, const t_bigInt *b);

/**
 * @brief Divides one big integer by another and computes the modulus.
 * 
 * Performs division of the first big integer structure by the second, storing
 * the quotient and remainder in the provided result structures.
 * 
 * @param quot Pointer to the t_bigInt structure where the quotient will be stored.
 * @param rem Pointer to the t_bigInt structure where the remainder will be stored.
 * @param a Pointer to the t_bigInt structure representing the dividend.
 * @param b Pointer to the t_bigInt structure representing the divisor.
 * @return A pointer to quot if the division is successful, or NULL if an error occurs (e.g., division by zero).
 */
t_bigInt	*bigIntDiv(t_bigInt *quot, t_bigInt *rem, const t_bigInt *a, const t_bigInt *b);

/**
 * @brief Computes the modulus of one big integer by another.
 * 
 * Computes the modulus of the first big integer structure by the second and
 * stores the result in the provided result structure.
 * 
 * @param result Pointer to the t_bigInt structure where the modulus will be stored.
 * @param a Pointer to the t_bigInt structure representing the value to be reduced.
 * @param m Pointer to the t_bigInt structure representing the modulus.
 * @return A pointer to result if the modulus operation is successful, or NULL if an error occurs (e.g., modulus by zero).
 */
t_bigInt	*bigIntMod(t_bigInt *result, const t_bigInt *a, const t_bigInt *m);

/* ---------- Modular arithmetic ---------- */

/**
 * @brief Multiplies two big integers and reduces the result modulo a third.
 * 
 * Multiplies the values of two big integer structures, reduces the result
 * modulo a third big integer structure, and stores the final result in the
 * provided result structure.
 * 
 * @param result Pointer to the t_bigInt structure where the final result will be stored.
 * @param a Pointer to the first t_bigInt structure to multiply.
 * @param b Pointer to the second t_bigInt structure to multiply.
 * @param m Pointer to the t_bigInt structure representing the modulus for reduction.
 * @return A pointer to result if the operation is successful, or NULL if an error occurs (e.g., modulus by zero).
 */
t_bigInt	*bigIntMulMod(t_bigInt *result, const t_bigInt *a, const t_bigInt *b, const t_bigInt *m);

/**
 * @brief Computes the modular exponentiation of a big integer.
 * 
 * Raises the base big integer to the power of the exponent big integer,
 * reduces the result modulo a third big integer, and stores the final result
 * in the provided result structure.
 * 
 * @param result Pointer to the t_bigInt structure where the final result will be stored.
 * @param base Pointer to the t_bigInt structure representing the base value.
 * @param exp Pointer to the t_bigInt structure representing the exponent value.
 * @param mod Pointer to the t_bigInt structure representing the modulus for reduction.
 * @return A pointer to result if the operation is successful, or NULL if an error occurs (e.g., modulus by zero).
 */
t_bigInt	*bigIntModExp(t_bigInt *result, const t_bigInt *base, const t_bigInt *exp, const t_bigInt *mod);

/**
 * @brief Computes the modular inverse of a big integer.
 * 
 * Computes the modular inverse of the given big integer a modulo m, which is
 * the value x such that (a * x) mod m = 1. The result is stored in the
 * provided result structure.
 * 
 * @param result Pointer to the t_bigInt structure where the modular inverse will be stored.
 * @param a Pointer to the t_bigInt structure representing the value for which to compute the inverse.
 * @param m Pointer to the t_bigInt structure representing the modulus for the inverse operation.
 * @return A pointer to result if the operation is successful, or NULL if an error occurs (e.g., if a and m are not coprime).
 */
t_bigInt	*bigIntModInverse(t_bigInt *result, const t_bigInt *a, const t_bigInt *m);

/**
 * @brief Computes the greatest common divisor (GCD) of two big integers.
 * 
 * Computes the greatest common divisor of the two given big integer structures
 * and stores the result in the provided result structure.
 * 
 * @param result Pointer to the t_bigInt structure where the GCD will be stored.
 * @param a Pointer to the first t_bigInt structure for GCD computation.
 * @param b Pointer to the second t_bigInt structure for GCD computation.
 * @return A pointer to result if the operation is successful, or NULL if an error occurs.
 */
t_bigInt	*bigIntGcd(t_bigInt *result, const t_bigInt *a, const t_bigInt *b);

/* ---------- Random generation ---------- */

/**
 * @brief Generates a random big integer with a specified number of bits.
 * 
 * Fills the provided big integer structure with a random value that has the
 * specified number of bits. The function ensures that the generated value is
 * properly randomized and fits within the allocated space of the big integer.
 * 
 * @param n Pointer to the t_bigInt structure where the random value will be stored.
 * @param bits The number of bits for the random big integer to generate.
 */
void		bigIntRandom(t_bigInt *n, size_t bits);

/* --------- Conversions ---------- */

/**
 * @brief Converts a big integer to a byte array.
 * 
 * Serializes the value of the given big integer structure into a byte array
 * representation. The function writes the bytes into the provided buffer and
 * returns the number of bytes written.
 * 
 * @param n Pointer to the t_bigInt structure to convert.
 * @param buf Pointer to the buffer where the byte array will be stored.
 * @param bufSize The size of the provided buffer in bytes.
 * @return The number of bytes written to the buffer, or 0 if an error occurs (e.g., if bufSize is too small).
 */
size_t		bigIntToBytes(const t_bigInt *n, uint8_t *buf, size_t bufSize);

/**
 * @brief Converts a big integer to a hexadecimal string.
 * 
 * Serializes the value of the given big integer structure into a hexadecimal
 * string representation. The function allocates memory for the string, which
 * must be freed by the caller.
 * 
 * @param n Pointer to the t_bigInt structure to convert.
 * @return A pointer to a newly allocated null-terminated string containing the
 *         hexadecimal representation of the big integer, or NULL if memory
 *         allocation fails.
 */
char		*bigIntToHex(const t_bigInt *n);

/**
 * @brief Converts a big integer to a decimal string.
 * 
 * Serializes the value of the given big integer structure into a decimal
 * string representation. The function allocates memory for the string, which
 * must be freed by the caller.
 * 
 * @param n Pointer to the t_bigInt structure to convert.
 * @return A pointer to a newly allocated null-terminated string containing the
 *         decimal representation of the big integer, or NULL if memory
 *         allocation fails.
 */
char		*bigIntToDec(const t_bigInt *n);

/* --------- Utility functions ---------- */

/**
 * @brief Gets the number of bits required to represent a big integer.
 * 
 * Returns the number of bits needed to represent the value of the given big integer structure.
 * 
 * @param n Pointer to the t_bigInt structure for which to get the bit length.
 * @return The number of bits required to represent the big integer.
 */
size_t		bigIntBitLength(const t_bigInt *n);

/**
 * @brief Sets a specific bit in a big integer.
 * 
 * Sets the bit at the specified position in the given big integer structure to 1.
 * 
 * @param n Pointer to the t_bigInt structure in which to set the bit.
 * @param bit The position of the bit to set.
 */
void		bigIntSetBit(t_bigInt *n, size_t bit);

/**
 * @brief Gets the value of a specific bit in a big integer.
 * 
 * Retrieves the value of the bit at the specified position in the given big integer structure.
 * 
 * @param n Pointer to the t_bigInt structure from which to get the bit.
 * @param bit The position of the bit to retrieve.
 * @return 1 if the bit is set, or 0 if it is not set.
 */
int			bigIntGetBit(const t_bigInt *n, size_t bit);

/* ---------- Bitwise shifts ---------- */

/**
 * @brief Shifts a big integer left by a specified number of bits.
 * 
 * Performs a left bitwise shift operation on the given big integer, effectively multiplying it by 2^shift.
 * 
 * @param n Pointer to the t_bigInt structure to be shifted. The value is modified in place.
 * @param shift The number of bits to shift left.
 * @return void
 */
void		bigIntShl(t_bigInt *n);

/**
 * @brief Shifts a big integer right by a specified number of bits.
 * 
 * Performs a right bitwise shift operation on the given big integer, effectively dividing it by 2^shift.
 * 
 * @param n Pointer to the t_bigInt structure to be shifted. The value is modified in place.
 * @param shift The number of bits to shift right.
 * @return void
 */
void		bigIntShr(t_bigInt *n);

#endif
