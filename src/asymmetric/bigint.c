#include "../../hajlib/include/hmemory.h"
#include "../../hajlib/include/hstring.h"
#include "../../includes/utils/random.h"
#include "../../includes/utils/utils.h"
#include "../../includes/x509/asn1.h"

#include "../../includes/asymmetric/bigint.h"

/**
 * @brief Shifts a big integer left by a specified number of bits.
 * 
 * Performs a left bitwise shift operation on the given big integer,
 * effectively multiplying it by 2^shift.
 * 
 * @param n Pointer to the t_bigInt structure to be shifted. The value is modified in place.
 * @param shift The number of bits to shift left.
 */
static void bigIntShiftLeft(t_bigInt *n, unsigned shift)
{
	if (shift == 0 || n->used == 0)
		return;

	size_t		wordShift = shift / 64;
	unsigned	bitShift = shift % 64;
	size_t		oldUsed = n->used;
	size_t		newUsed = oldUsed + wordShift + (bitShift ? 1 : 0);

	if (newUsed > n->numWords)
		return; 

	if (newUsed > oldUsed) {
		for (size_t i = oldUsed; i < newUsed; i++)
			n->words[i] = 0;
	}

	if (bitShift == 0) {
		for (size_t i = oldUsed; i-- > 0; )
			n->words[i + wordShift] = n->words[i];
	} else {
		for (size_t i = oldUsed; i-- > 0; ) {
			uint64_t val = n->words[i];
			n->words[i + wordShift + 1] |= (val >> (64 - bitShift));
			n->words[i + wordShift] = (val << bitShift);
		}
	}

	if (wordShift > 0)
		ft_bzero(n->words, wordShift * sizeof(uint64_t));

	n->used = newUsed;
	while (n->used > 0 && n->words[n->used - 1] == 0)
		n->used--;
}



/* ---------- Allocation and basic operations ---------- */

t_bigInt *bigIntNew(size_t numWords)
{
	t_bigInt	*n = malloc(sizeof(t_bigInt));
	if (!n)
		return (NULL);
	n->words = calloc(numWords, sizeof(uint64_t));
	if (!n->words) {
		free(n);
		return (NULL);
	}
	n->numWords = numWords;
	n->used = 0;
	n->sign = 0;
	return (n);
}

t_bigInt *bigIntFromUint64(uint64_t val)
{
	t_bigInt	*n = bigIntNew(1);
	if (!n)
		return (NULL);
	n->words[0] = val;
	n->used = (val != 0) ? 1 : 0;
	return (n);
}

t_bigInt *bigIntFromHex(const char *hex, size_t numWords)
{
	size_t		len = ft_strlen(hex);
	size_t		bytes = (len + 1) / 2;
	size_t		words = (bytes + 7) / 8;
	t_bigInt	*n = bigIntNew(numWords ? numWords : words);
	uint8_t		*byteArray;

	if (!n)
		return (NULL);
	
	byteArray = calloc(bytes, 1);
	if (!byteArray) {
		bigIntFree(n);
		return (NULL);
	}

	for (size_t i = 0; i < len; i++)
	{
		char	c = hex[len - 1 - i];
		uint8_t	nibble;

		if	  (c >= '0' && c <= '9') nibble = c - '0';
		else if (c >= 'a' && c <= 'f') nibble = c - 'a' + 10;
		else if (c >= 'A' && c <= 'F') nibble = c - 'A' + 10;
		else						   nibble = 0;

		if (i % 2 == 0)
			byteArray[i / 2]  = nibble;		/* low nibble   */
		else
			byteArray[i / 2] |= (nibble << 4); /* high nibble  */
	}

	for (size_t i = 0; i < bytes; i++) {
		size_t	wordIdx = i / 8;
		size_t	byteIdx = i % 8;
		n->words[wordIdx] |= ((uint64_t)byteArray[i]) << (byteIdx * 8);
	}

	n->used = words;
	while (n->used > 0 && n->words[n->used - 1] == 0)
		n->used--;

	free(byteArray);
	return (n);
}

t_bigInt	*bigIntFromBytes(const uint8_t *bytes, size_t len)
{
	size_t		words = (len + 7) / 8;
	t_bigInt	*n = bigIntNew(words);
	if (!n)
		return (NULL);

	for (size_t i = 0; i < len; i++) {
		size_t	wordIdx = i / 8;
		size_t	byteIdx = i % 8;
		n->words[wordIdx] |= ((uint64_t)bytes[len - 1 - i]) << (byteIdx * 8);
	}

	n->used = words;
	while (n->used > 0 && n->words[n->used - 1] == 0)
		n->used--;

	return (n);
}

void bigIntFree(t_bigInt *n)
{
	if (!n)
		return;
	if (n->words) {
		secureZeroMemory(n->words, n->numWords * sizeof(uint64_t));
		free(n->words);
	}
	free(n);
}

void bigIntZero(t_bigInt *n)
{
	ft_bzero(n->words, n->numWords * sizeof(uint64_t));
	n->used = 0;
	n->sign = 0;
}

t_bigInt *bigIntDup(const t_bigInt *src)
{
	t_bigInt *dst = bigIntNew(src->numWords);
	if (!dst)
		return (NULL);
	ft_memcpy(dst->words, src->words, src->numWords * sizeof(uint64_t));
	dst->used = src->used;
	dst->sign = src->sign;
	return (dst);
}

t_bigInt *bigIntCopy(t_bigInt *dst, const t_bigInt *src)
{
	if (!dst || !src || dst->numWords < src->used)
		return (NULL);
	if (dst == src)
		return (dst);

	ft_bzero(dst->words, dst->numWords * sizeof(uint64_t));
	ft_memcpy(dst->words, src->words, src->used * sizeof(uint64_t));
	dst->used = src->used;
	dst->sign = src->sign;
	return (dst);
}

int	bigIntSetUint64(t_bigInt *n, uint64_t val)
{
	if (!n)
		return (0);
	
	/* Clear all words */
	ft_bzero(n->words, n->numWords * sizeof(uint64_t));
	
	/* Set the first word */
	n->words[0] = val;
	n->used = (val != 0) ? 1 : 0;
	n->sign = 0;
	
	return (1);
}

/* ---------- Comparisons ---------- */

int bigIntCmp(const t_bigInt *a, const t_bigInt *b)
{
	if (a->used != b->used)
		return ((a->used > b->used) ? 1 : -1);
	for (size_t i = a->used; i-- > 0;)
		if (a->words[i] != b->words[i])
			return ((a->words[i] > b->words[i]) ? 1 : -1);
	return (0);
}

int bigIntIsZero(const t_bigInt *n)
{
	if (!n)
		return (1);
	return (n->used == 0);
}

int bigIntIsOdd(const t_bigInt *n)
{
	if (!n)
		return (0);
	return (n->used > 0 && (n->words[0] & 1)); /* Check if the least significant bit is 1 */
}

int bigIntIsEven(const t_bigInt *n)
{
	if (!n)
		return (0);
	return (!bigIntIsOdd(n));
}



/* ---------- Arithmetic Operations ---------- */

t_bigInt *bigIntAdd(t_bigInt *result, const t_bigInt *a, const t_bigInt *b)
{
	size_t	maxWords = (a->used > b->used) ? a->used : b->used;
	
	if (maxWords > result->numWords)
		return (NULL);
		
	uint64_t carry = 0;
	for (size_t i = 0; i < maxWords; i++) {
		__uint128_t sum = (__uint128_t)(i < a->used ? a->words[i] : 0) +
						  (__uint128_t)(i < b->used ? b->words[i] : 0) + carry;
		result->words[i] = (uint64_t)sum;
		carry = (uint64_t)(sum >> 64);
	}
	result->used = maxWords;
	
	/* Handle the carry if one exists */
	if (carry) {
		if (result->used >= result->numWords)
			return (NULL); /* Fail only when capacity is genuinely exceeded by a carry */
		result->words[result->used++] = carry;
	}
	
	/* Trim any potential leading zeros */
	while (result->used > 0 && result->words[result->used - 1] == 0)
		result->used--;
		
	result->sign = 0;
	return (result);
}

t_bigInt *bigIntSub(t_bigInt *result, const t_bigInt *a, const t_bigInt *b)
{
	if (bigIntCmp(a, b) < 0)
		return (NULL);
	if (result->numWords < a->used)
		return (NULL);

	uint64_t borrow = 0;
	for (size_t i = 0; i < a->used; i++) {
		__int128_t diff = (__int128_t)(i < a->used ? a->words[i] : 0) -
						  (__int128_t)(i < b->used ? b->words[i] : 0) - borrow;
		if (diff < 0) {
			diff += (__int128_t)1 << 64;
			borrow = 1;
		} else
			borrow = 0;
		result->words[i] = (uint64_t)diff;
	}
	result->used = a->used;
	while (result->used > 0 && result->words[result->used - 1] == 0)
		result->used--;
	result->sign = 0;
	return (result);
}

t_bigInt *bigIntMul(t_bigInt *result, const t_bigInt *a, const t_bigInt *b)
{
	if (result->numWords < a->used + b->used)
		return (NULL);

	t_bigInt *tmpA = NULL, *tmpB = NULL;
	const t_bigInt *safeA = a, *safeB = b;
	
	if (result == a) safeA = tmpA = bigIntDup(a);
	if (result == b) safeB = tmpB = bigIntDup(b);
	
	ft_bzero(result->words, result->numWords * sizeof(uint64_t));

	for (size_t i = 0; i < safeA->used; i++) {
		if (safeA->words[i] == 0) continue;
		uint64_t carry = 0;
		for (size_t j = 0; j < safeB->used; j++) {
			__uint128_t prod = (__uint128_t)safeA->words[i] * safeB->words[j] + 
							   result->words[i + j] + carry;
			result->words[i + j] = (uint64_t)prod;
			carry = (uint64_t)(prod >> 64);
		}
		result->words[i + safeB->used] = carry;
	}

	result->used = safeA->used + safeB->used;
	while (result->used > 0 && result->words[result->used - 1] == 0)
		result->used--;
	
	bigIntFree(tmpA); bigIntFree(tmpB);
	return (result);
}

/* ---------- Fast division and modulus (Knuth's Algorithm D) ---------- */

/**
 * @brief Normalizes two big integers for arithmetic operations.
 * 
 * Adjusts the precision and alignment of two big integer operands
 * to ensure they can be operated on together.
 * 
 * @param a Pointer to the first big integer to normalize.
 * @param b Pointer to the second big integer to normalize.
 * 
 * @return The normalized size or status code indicating the result
 *		 of the normalization operation.
 */
static unsigned bigIntNormalize(t_bigInt *a, t_bigInt *b) {
	if (b->used == 0) return (0); /* Avoid division by zero in normalization */
	
	/* Count leading zeros in the most significant word */
	uint64_t	top = b->words[b->used - 1];
	unsigned	shift = 0;

	if (top != 0)
		shift = __builtin_clzll(top); 

	if (shift > 0) {
		bigIntShiftLeft(a, shift);
		bigIntShiftLeft(b, shift);
	}

	if (a->used <= b->used && a->used < a->numWords) { /* Ensure a has enough space for the division algorithm */
		a->words[a->used] = 0;
		a->used++;
	}
	return (shift);
}

/**
 * @brief Denormalizes a big integer by shifting it right.
 *
 * Reverses the normalization process applied to a big integer by performing
 * a right shift operation. This is typically used after modular arithmetic
 * operations to restore the big integer to its original representation.
 *
 * @param a Pointer to the big integer to be denormalized. Must not be NULL.
 * @param shift The number of bit positions to shift right. Should be less than
 *			  the bit width of the big integer elements.
 *
 * @return void
 */
static void bigIntUnnormalize(t_bigInt *a, unsigned shift) {
	if (a->used == 0) return;
	
	if (shift > 0) {
		unsigned bitShift = shift;
		uint64_t carry = 0;
		for (size_t i = a->used; i-- > 0; ) {
			uint64_t next_carry = a->words[i] << (64 - bitShift);
			a->words[i] = (a->words[i] >> bitShift) | carry;
			carry = next_carry;
		}
	}

	while (a->used > 0 && a->words[a->used - 1] == 0)
		a->used--;
}

/**
 * @brief Performs division and modulus of big integers using Knuth's Algorithm D.
 *
 * This function computes the quotient and remainder of two big integers using
 * Knuth's Algorithm D, which is an efficient method for large integer division.
 *
 * @param quot Pointer to a big integer where the quotient will be stored. Can be NULL if only the remainder is needed.
 * @param rem Pointer to a big integer where the remainder will be stored. Can be NULL if only the quotient is needed.
 * @param a Pointer to the dividend big integer. Must not be NULL.
 * @param b Pointer to the divisor big integer. Must not be NULL and should not be zero.
 */
static void bigIntDivModKnuth(t_bigInt *quot, t_bigInt *rem, const t_bigInt *a, const t_bigInt *b)
{
	/* Simple case for single-word divisor */
	if (b->used == 1) {
		uint64_t divisor = b->words[0];
		uint64_t remainder = 0;
		if (quot && quot->numWords < a->used)
			return; /* Insufficient space for quotient */

		for (size_t i = a->used; i-- > 0; ) {
			__uint128_t num = ((__uint128_t)remainder << 64) | a->words[i];
			if (quot)
				quot->words[i] = (uint64_t)(num / divisor);
			remainder = (uint64_t)(num % divisor);
		}
		if (quot) {
			quot->used = a->used;
			while (quot->used > 0 && quot->words[quot->used - 1] == 0)
				quot->used--;
		}
		if (rem) {
			rem->words[0] = remainder;
			rem->used = (remainder != 0) ? 1 : 0;
		}
		return;
	}

	/* Allocation and normalization */
	t_bigInt *A = bigIntNew(a->used + 2);
	t_bigInt *B = bigIntNew(b->used + 1);
	if (!A || !B) {
		bigIntFree(A);
		bigIntFree(B);
		return;
	}
	bigIntCopy(A, a);
	bigIntCopy(B, b);

	unsigned shift = bigIntNormalize(A, B);
	size_t n = B->used;
	
	if (A->used < n) { /* Dividend is smaller than divisor */
		if (quot)
			bigIntZero(quot);
		if (rem)
			bigIntCopy(rem, a);
		return;
	}

	size_t m = A->used - n;

	if (quot) {
		if (quot->numWords < m + 1) {
			bigIntFree(A);
			bigIntFree(B);
			return;
		}
		bigIntZero(quot);
		quot->used = m + 1;
	}

	/* Main loop of Knuth's Algorithm D */
	for (size_t j = m; j != (size_t)-1; j--) {
		
		/* Precise estimation of q_hat (Step D3 of Knuth) */
		uint64_t uJn   = (j + n < A->used) ? A->words[j + n] : 0;
		uint64_t uJn1  = (j + n - 1 < A->used) ? A->words[j + n - 1] : 0;
		uint64_t uJn2  = (j + n - 2 < A->used) ? A->words[j + n - 2] : 0;
		uint64_t vN1   = B->words[n - 1];
		uint64_t vN2   = (n >= 2) ? B->words[n - 2] : 0;

		__uint128_t qHat;
		__uint128_t rHat;

		if (uJn == vN1) {
			qHat = (uint64_t)-1;
			rHat = (__uint128_t)uJn1 + vN1;
		} else {
			__uint128_t num = ((__uint128_t)uJn << 64) | uJn1;
			qHat = num / vN1;
			rHat = num % vN1;
		}

		/* Stric refinement of q_hat (Step D4 of Knuth) */
		while (rHat < ((__uint128_t)1 << 64)) {
			__uint128_t lhs = qHat * vN2;
			__uint128_t rhs = (rHat << 64) | uJn2;
			if (lhs > rhs) {
				qHat--;
				rHat += vN1;
			} else break;
		}

		/* Multiplication and subtraction: A = A - q_hat * B * b^j (Step D4 of Knuth) */
		uint64_t borrow = 0;
		for (size_t i = 0; i < n; i++) {
			__uint128_t prod = (__uint128_t)qHat * B->words[i] + borrow;
			uint64_t pLo = (uint64_t)prod;
			uint64_t pHi = (uint64_t)(prod >> 64);

			if (A->words[j + i] < pLo) {
				A->words[j + i] = A->words[j + i] - pLo;
				borrow = pHi + 1;
			} else {
				A->words[j + i] -= pLo;
				borrow = pHi;
			}
		}

		int is_negative = 0;
		if (A->words[j + n] < borrow) {
			is_negative = 1;
		}
		A->words[j + n] -= borrow;

		if (is_negative) {
			qHat--;
			uint64_t carry = 0;
			for (size_t i = 0; i < n; i++) {
				__uint128_t sum = (__uint128_t)A->words[j + i] + B->words[i] + carry;
				A->words[j + i] = (uint64_t)sum;
				carry = (uint64_t)(sum >> 64);
			}
			A->words[j + n] += carry;
		}

		if (quot)
			quot->words[j] = (uint64_t)qHat;
	}

	if (quot) {
		while (quot->used > 0 && quot->words[quot->used - 1] == 0)
			quot->used--;
	}

	if (rem) {
		bigIntUnnormalize(A, shift);
		bigIntCopy(rem, A);
	}

	bigIntFree(A);
	bigIntFree(B);
}

t_bigInt *bigIntDiv(t_bigInt *quot, t_bigInt *rem, const t_bigInt *a, const t_bigInt *b)
{
	if (bigIntIsZero(b))
		return (NULL);
	if (bigIntCmp(a, b) < 0) {
		if (rem)
			bigIntCopy(rem, a);
		if (quot)
			bigIntZero(quot);
		return (quot);
	}
	bigIntDivModKnuth(quot, rem, a, b);
	return (quot);
}

t_bigInt *bigIntMod(t_bigInt *result, const t_bigInt *a, const t_bigInt *m)
{
	if (bigIntIsZero(m))
		return (NULL);
	bigIntDiv(NULL, result, a, m);
	return (result);
}



/* ---------- Modular arithmetic ---------- */

t_bigInt *bigIntMulMod(t_bigInt *result, const t_bigInt *a, const t_bigInt *b, const t_bigInt *m)
{
	t_bigInt *tmp = bigIntNew(a->used + b->used);
	if (!tmp)
		return (NULL);
	if (!bigIntMul(tmp, a, b) || !bigIntMod(result, tmp, m)) {
		bigIntFree(tmp);
		return (NULL);
	}
	bigIntFree(tmp);
	return (result);
}

/**
 * @brief Computes the Montgomery parameter m0_prime = -m[0]^(-1) mod 2^64.
 * @param m0 The modulus m0 for which we want to compute the Montgomery parameter. Must be odd.
 * @return The Montgomery parameter m0_prime, which is used in Montgomery reduction. Returns 0 if m0 is even.
 */
static uint64_t montgomeryM0Prime(uint64_t m0)
{
	uint64_t inv = m0;
	inv *= 2ULL - m0 * inv;
	inv *= 2ULL - m0 * inv;
	inv *= 2ULL - m0 * inv;
	inv *= 2ULL - m0 * inv;
	inv *= 2ULL - m0 * inv;
	return ~inv + 1ULL;
}

/**
 * @brief Performs Montgomery multiplication: res = (a * b * R^-1) mod m
 * This function computes the Montgomery multiplication of two big integers a and b modulo m,
 * where R is typically 2^(64 * n) for some n.
 * The modulus m must be odd for Montgomery multiplication to work correctly.
 * @param res The result of the Montgomery multiplication
 * @param a The first operand
 * @param b The second operand
 * @param m The modulus
 * @param m0Prime The Montgomery parameter
 */
static void bigIntMontMul(t_bigInt *res, const t_bigInt *a, const t_bigInt *b, const t_bigInt *m, uint64_t m0Prime)
{
	size_t n = m->used;
	uint64_t T[n + 2];
	ft_bzero(T, (n + 2) * sizeof(uint64_t));

	for (size_t i = 0; i < n; i++) {
		uint64_t carry = 0;
		uint64_t ai = (i < a->used) ? a->words[i] : 0;
		
		/* Step 1: Compute T = T + ai * b */
		for (size_t j = 0; j < n; j++) {
			uint64_t bj = (j < b->used) ? b->words[j] : 0;
			__uint128_t sum = (__uint128_t)T[j] + ((__uint128_t)ai * bj) + carry;
			T[j] = (uint64_t)sum;
			carry = (uint64_t)(sum >> 64);
		}
		__uint128_t sum_carry = (__uint128_t)T[n] + carry;
		T[n] = (uint64_t)sum_carry;
		T[n+1] = (uint64_t)(sum_carry >> 64);

		/* Step 2: Compute q = (T[0] * m0Prime) mod 2^64 */
		uint64_t q = T[0] * m0Prime;
		carry = 0;
		__uint128_t sum_red = (__uint128_t)T[0] + ((__uint128_t)q * m->words[0]);
		carry = (uint64_t)(sum_red >> 64);
		
		for (size_t j = 1; j < n; j++) {
			__uint128_t sum = (__uint128_t)T[j] + ((__uint128_t)q * m->words[j]) + carry;
			T[j-1] = (uint64_t)sum;
			carry = (uint64_t)(sum >> 64);
		}
		
		sum_red = (__uint128_t)T[n] + carry;
		T[n-1] = (uint64_t)sum_red;
		carry = (uint64_t)(sum_red >> 64);
		T[n] = T[n+1] + carry;
	}

	ft_bzero(res->words, res->numWords * sizeof(uint64_t));
	for(size_t i = 0; i <= n && i < res->numWords; i++) {
		res->words[i] = T[i];
	}
	
	res->used = n + 1;
	if (res->used > res->numWords) res->used = res->numWords;
	while(res->used > 0 && res->words[res->used - 1] == 0) res->used--;

	/* Final reduction if res >= m */
	if (bigIntCmp(res, m) >= 0) {
		uint64_t borrow = 0;
		for (size_t i = 0; i < n; i++) {
			__int128_t diff = (__int128_t)res->words[i] - m->words[i] - borrow;
			if (diff < 0) {
				diff += (__int128_t)1 << 64;
				borrow = 1;
			} else {
				borrow = 0;
			}
			res->words[i] = (uint64_t)diff;
		}
		for (size_t i = n; i < res->used; i++) res->words[i] = 0; // Nettoyer les restes
		res->used = n;
		while(res->used > 0 && res->words[res->used - 1] == 0) res->used--;
	}
}

/**
 * @brief Computes modular exponentiation using the classic algorithm.
 * @param result The result of the modular exponentiation
 * @param base The base
 * @param exp The exponent
 * @param mod The modulus
 * @return The result of the modular exponentiation, or NULL if an error occurred.
 */
static t_bigInt *bigIntModExpClassic(t_bigInt *result, const t_bigInt *base, const t_bigInt *exp, const t_bigInt *mod)
{
	size_t bit_len = bigIntBitLength(exp);
	t_bigInt *tmp = bigIntNew(mod->numWords * 2 + 2);
	t_bigInt *b = bigIntNew(mod->numWords);
	
	if (!b || !tmp) goto cleanup;

	if (bigIntCmp(base, mod) >= 0) bigIntMod(b, base, mod);
	else bigIntCopy(b, base);

	bigIntZero(result);
	result->words[0] = 1;
	result->used = 1;

	for (size_t i = bit_len; i-- > 0; ) {
		if (!bigIntMulMod(tmp, result, result, mod)) goto cleanup;
		bigIntCopy(result, tmp);
		if (bigIntGetBit(exp, i)) {
			if (!bigIntMulMod(tmp, result, b, mod)) goto cleanup;
			bigIntCopy(result, tmp);
		}
	}
	
	bigIntFree(b); bigIntFree(tmp);
	return (result);

cleanup:
	bigIntFree(b); bigIntFree(tmp);
	return (NULL);
}

t_bigInt *bigIntModExp(t_bigInt *result, const t_bigInt *base, const t_bigInt *exp, const t_bigInt *mod)
{
	if (bigIntIsZero(mod)) return (NULL);
	if (mod->used == 1 && mod->words[0] == 1) {
		bigIntZero(result);
		return (result);
	}
	
	/* Montgomery multiplication is only efficient for odd moduli, so we fall back to the classic method for even moduli. */
	if (bigIntIsEven(mod))
		return bigIntModExpClassic(result, base, exp, mod);

	size_t n = mod->used;
	uint64_t m0Prime = montgomeryM0Prime(mod->words[0]);

	/* Compute R^2 mod M for Montgomery reduction */
	t_bigInt *R2 = bigIntNew(n * 2 + 1);
	t_bigInt *R2Mod = bigIntNew(n + 1);
	if (!R2 || !R2Mod) { bigIntFree(R2); bigIntFree(R2Mod); return NULL; }
	
	bigIntSetBit(R2, n * 128);
	bigIntMod(R2Mod, R2, mod);
	bigIntFree(R2);

	/* Initial reduction of the base : baseMod = base mod M */
	t_bigInt *baseMod = bigIntNew(n + 1);
	if (bigIntCmp(base, mod) >= 0) bigIntMod(baseMod, base, mod);
	else bigIntCopy(baseMod, base);

	t_bigInt *baseBar = bigIntNew(mod->numWords + 1);
	t_bigInt *xBar = bigIntNew(mod->numWords + 1);
	t_bigInt *one = bigIntFromUint64(1);
	t_bigInt *tmp = bigIntNew(mod->numWords + 1);

	/* Convert base to Montgomery form: baseBar = (baseMod * R^2) mod M */
	bigIntMontMul(baseBar, baseMod, R2Mod, mod, m0Prime);
	bigIntMontMul(xBar, one, R2Mod, mod, m0Prime);

	size_t bit_len = bigIntBitLength(exp);
	for (size_t i = bit_len; i-- > 0; ) {
		bigIntMontMul(tmp, xBar, xBar, mod, m0Prime);
		bigIntCopy(xBar, tmp);
		
		if (bigIntGetBit(exp, i)) {
			bigIntMontMul(tmp, xBar, baseBar, mod, m0Prime); // x_bar * base_bar
			bigIntCopy(xBar, tmp);
		}
	}

	/* Convert result back from Montgomery form: result = (xBar * 1) mod M */
	bigIntMontMul(result, xBar, one, mod, m0Prime);

	bigIntFree(R2Mod); bigIntFree(baseMod);
	bigIntFree(baseBar); bigIntFree(xBar);
	bigIntFree(one); bigIntFree(tmp);
	
	return (result);
}


t_bigInt *bigIntModInverse(t_bigInt *result, const t_bigInt *a, const t_bigInt *m)
{
	if (!result || !a || !m || bigIntIsZero(m) || bigIntIsZero(a))
		return (NULL);

	t_bigInt *t0   = bigIntNew(m->numWords);
	t_bigInt *t1   = bigIntNew(m->numWords);
	t_bigInt *r0   = bigIntNew(m->numWords);
	t_bigInt *r1   = bigIntNew(m->numWords);
	t_bigInt *q	= bigIntNew(m->numWords);

	t_bigInt *tmp  = bigIntNew(m->numWords * 2 + 1);
	t_bigInt *tmp2 = bigIntNew(m->numWords * 2 + 1);

	if (!t0 || !t1 || !r0 || !r1 || !q || !tmp || !tmp2)
		goto cleanup;

	bigIntZero(t0);
	t1->words[0] = 1;
	t1->used = 1;
	
	bigIntCopy(r0, m);
	bigIntCopy(r1, a);

	while (!bigIntIsZero(r1))
	{
		/* q = r0 / r1  and  tmp2 = r0 % r1 */
		if (!bigIntDiv(q, tmp2, r0, r1))
			goto cleanup;
		bigIntCopy(r0, r1);
		bigIntCopy(r1, tmp2);
		if (!bigIntMul(tmp, q, t1))
			goto cleanup;
		if (!bigIntMod(tmp2, tmp, m))
			goto cleanup;
		bigIntZero(tmp);
		if (bigIntCmp(t0, tmp2) >= 0) {
			if (!bigIntSub(tmp, t0, tmp2))
				goto cleanup;
		} else {
			if (!bigIntAdd(tmp, t0, m))
				goto cleanup;
			if (!bigIntSub(tmp, tmp, tmp2))
				goto cleanup;
		}
		bigIntCopy(t0, t1);
		bigIntCopy(t1, tmp);
	}
	if (r0->used > 1 || (r0->used == 1 && r0->words[0] > 1) || r0->used == 0)
		goto cleanup;
	bigIntCopy(result, t0);

	bigIntFree(t0); bigIntFree(t1);
	bigIntFree(r0); bigIntFree(r1);
	bigIntFree(q);  bigIntFree(tmp); bigIntFree(tmp2);
	
	return (result);

cleanup:
	bigIntFree(t0); bigIntFree(t1);
	bigIntFree(r0); bigIntFree(r1);
	bigIntFree(q);  bigIntFree(tmp); bigIntFree(tmp2);
	return (NULL);
}

/* ---------- PGCD ---------- */

t_bigInt *bigIntGcd(t_bigInt *result, const t_bigInt *a, const t_bigInt *b)
{
	t_bigInt *newA = bigIntDup(a);
	t_bigInt *newB = bigIntDup(b);
	size_t maxWords = (a->numWords > b->numWords) ? a->numWords : b->numWords;
	t_bigInt *tmp = bigIntNew(maxWords);
	if (!newA || !newB || !tmp)
		goto cleanup;
	while (!bigIntIsZero(newB)) {
		bigIntMod(tmp, newA, newB);
		bigIntCopy(newA, newB);
		bigIntCopy(newB, tmp);
	}
	bigIntCopy(result, newA);
cleanup:
	bigIntFree(newA); bigIntFree(newB); bigIntFree(tmp);
	return (result);
}

/* ---------- Utilities ---------- */

size_t bigIntBitLength(const t_bigInt *n)
{
	if (n->used == 0) return (0);
	size_t bits = (n->used - 1) * 64;
	uint64_t word = n->words[n->used - 1];
	while (word) {
		bits++;
		word >>= 1;
	}
	return (bits);
}

void bigIntSetBit(t_bigInt *n, size_t bit)
{
	size_t wordIdx = bit / 64;
	size_t bitIdx = bit % 64;
	if (wordIdx >= n->numWords)
		return;
	if (wordIdx >= n->used)
		n->used = wordIdx + 1;
	n->words[wordIdx] |= (1ULL << bitIdx);
}

int bigIntGetBit(const t_bigInt *n, size_t bit)
{
	size_t wordIdx = bit / 64;
	if (wordIdx >= n->used)
		return (0);
	return ((n->words[wordIdx] >> (bit % 64)) & 1);
}

void bigIntRandom(t_bigInt *n, size_t bits)
{
	if (!n || bits == 0) return;
	
	size_t wordsNeeded = (bits + 63) / 64;
	if (wordsNeeded > n->numWords) return;

	bigIntZero(n);
	
	for (size_t i = 0; i < wordsNeeded; i++)
		n->words[i] = hajRandomUint64();

	if (bits % 64 != 0)
		n->words[wordsNeeded - 1] &= ((1ULL << (bits % 64)) - 1);

	n->words[wordsNeeded - 1] |= (1ULL << ((bits - 1) % 64));

	if (bits > 1)
		n->words[wordsNeeded - 1] |= (1ULL << ((bits - 2) % 64));

	n->words[0] |= 1ULL;

	n->used = wordsNeeded;
}

size_t bigIntToBytes(const t_bigInt *num, uint8_t *buf, size_t bufSize)
{
	size_t	numBits;
	size_t	numBytes;
	size_t	pad;
	size_t	i, j;
	int		started;

	if (!num || !buf || bufSize == 0)
		return (0);

	numBits = bigIntBitLength(num);
	numBytes = (numBits + 7) / 8;
	if (numBytes > bufSize)
		return (0);

	ft_bzero(buf, bufSize);
	pad = bufSize - numBytes;
	i = pad;
	started = 0;

	for (j = num->numWords; j > 0; j--)
	{
		uint64_t	word = num->words[j - 1];
		int			byteShift;

		for (byteShift = 56; byteShift >= 0; byteShift -= 8)
		{
			uint8_t byte = (uint8_t)(word >> byteShift);
			if (!started)
			{
				if (byte == 0 && i < bufSize - 1)
					continue;
				started = 1;
			}
			if (i < bufSize)
				buf[i++] = byte;
		}
	}
	if (!started && pad < bufSize)
		buf[pad] = 0;

	return (bufSize);
}

char *bigIntToHex(const t_bigInt *n)
{
	size_t bits = bigIntBitLength(n);
	size_t hexDigits = (bits + 3) / 4;
	char *hex = malloc(hexDigits + 1);
	if (!hex)
		return (NULL);
	for (size_t i = 0; i < hexDigits; i++) {
		size_t bitPos = (hexDigits - 1 - i) * 4;
		size_t wordIdx = bitPos / 64;
		size_t bitIdx = bitPos % 64;
		uint8_t nibble = 0;
		if (wordIdx < n->used) {
			nibble = (n->words[wordIdx] >> bitIdx) & 0xF;
		}
		hex[i] = (nibble < 10) ? ('0' + nibble) : ('a' + nibble - 10);
	}
	hex[hexDigits] = '\0';
	return (hex);
}

char *bigIntToDec(const t_bigInt *n)
{
	if (bigIntIsZero(n))
		return (ft_strdup("0"));

	size_t maxDigits = bigIntBitLength(n) * 10 / 33 + 1;
	char *dec = malloc(maxDigits + 1);
	if (!dec)
		return (NULL);
	size_t idx = maxDigits;
	t_bigInt *tmp = bigIntDup(n);
	t_bigInt *quot = bigIntNew(tmp->numWords);
	t_bigInt *rem = bigIntNew(1);
	t_bigInt *ten = bigIntFromUint64(10);
	if (!tmp || !quot || !rem || !ten) {
		free(dec);
		bigIntFree(tmp); bigIntFree(quot); bigIntFree(rem); bigIntFree(ten);
		return (NULL);
	}
	while (!bigIntIsZero(tmp)) {
		bigIntDiv(quot, rem, tmp, ten);
		dec[--idx] = '0' + rem->words[0];
		bigIntCopy(tmp, quot);
	}
	dec[maxDigits] = '\0';
	char *result = ft_strdup(dec + idx);
	free(dec);
	bigIntFree(tmp); bigIntFree(quot); bigIntFree(rem); bigIntFree(ten);
	return (result);
}

void bigIntShr(t_bigInt *n)
{
	uint64_t carry = 0;
	for (size_t i = n->used; i-- > 0;) {
		uint64_t newCarry = (n->words[i] & 1) << 63;
		n->words[i] = (n->words[i] >> 1) | carry;
		carry = newCarry;
	}
	if (n->used > 0 && n->words[n->used - 1] == 0)
		n->used--;
}

int	bigIntAbs(t_bigInt *n)
{
	if (!n) return (0);
	if (n->sign == 1) return (1);
	n->sign = 1;
	return (1);
}

int	bigIntSqrtNewton(t_bigInt *result, const t_bigInt *n)
{
	t_bigInt	*x0;
	t_bigInt	*x1;
	t_bigInt	*quot;
	t_bigInt	*sum;
	t_bigInt	*two;
	t_bigInt	*one;
	t_bigInt	*temp;
	int			bits;
	int			cmp;
	
	if (!result || !n)
		return (0);
	if (bigIntIsZero(n)) {
		bigIntZero(result);
		return (1);
	}
	if (n->sign < 0)
		return (0);
	
	one = bigIntFromUint64(1);
	if (!one)
		return (0);
	if (bigIntCmp(n, one) == 0) {
		bigIntSetUint64(result, 1);
		bigIntFree(one);
		return (1);
	}
	
	bits = bigIntBitLength(n);
	x0 = bigIntFromUint64(1);
	if (!x0) {
		bigIntFree(one);
		return (0);
	}
	/* Correction : bigIntShiftLeft prend 2 arguments, pas 3 */
	bigIntShiftLeft(x0, (bits + 1) / 2);
	
	x1 = bigIntNew(x0->numWords + 2);
	quot = bigIntNew(n->numWords + 2);
	sum = bigIntNew(x0->numWords + n->numWords + 4);
	two = bigIntFromUint64(2);
	temp = bigIntNew(x0->numWords + 2);
	
	if (!x1 || !quot || !sum || !two || !temp) {
		bigIntFree(one);
		bigIntFree(two);
		bigIntFree(x0);
		bigIntFree(x1);
		bigIntFree(quot);
		bigIntFree(sum);
		bigIntFree(temp);
		return (0);
	}
	
	while (1) {
		/* Correction : appel correct à bigIntDiv (dividende en 3ème, diviseur en 4ème) */
		bigIntDiv(quot, NULL, n, x0);
		
		bigIntAdd(sum, x0, quot);
		bigIntDiv(x1, NULL, sum, two);
		
		cmp = bigIntCmp(x1, x0);
		if (cmp >= 0)
			break;
		
		bigIntCopy(x0, x1);
	}
	
	bigIntMul(temp, x0, x0);
	if (bigIntCmp(temp, n) > 0)
		bigIntSub(x0, x0, one);
	
	bigIntCopy(result, x0);
	
	bigIntFree(one);
	bigIntFree(two);
	bigIntFree(x0);
	bigIntFree(x1);
	bigIntFree(quot);
	bigIntFree(sum);
	bigIntFree(temp);
	
	return (1);
}

uint8_t	*bigIntToDerInteger(const t_bigInt *n, size_t *outLen)
{
	size_t	len = (bigIntBitLength(n) + 7) / 8;

	if (len == 0) len = 1;
	uint8_t *data = malloc(len);
	if (!data) return (NULL);
	bigIntToBytes(n, data, len);
	uint8_t *der = asn1EncodeInteger(data, len, outLen);
	free(data);
	return (der);
}
