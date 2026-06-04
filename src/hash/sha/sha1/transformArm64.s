// ARMv8 SHA-1 implementation using crypto extensions
// void sha1TransformArm64(uint32_t *state, const uint8_t *data)

.text
.align 5

// SHA-1 constants K[0..3]
.type k_sha1, @object
.size k_sha1, 16
k_sha1:
.word 0x5A827999	  // K0..19: 0x5A827999
.word 0x6ED9EBA1	  // K20..39: 0x6ED9EBA1
.word 0x8F1BBCDC	  // K40..59: 0x8F1BBCDC
.word 0xCA62C1D6	  // K60..79: 0xCA62C1D6

.globl sha1TransformArm64
.type sha1TransformArm64, @function
sha1TransformArm64:
	// Save frame pointer and link register
	stp x29, x30, [sp, #-16]!
	mov x29, sp

	// Load state (5 words) into SIMD registers
	// v0.4s = [A, B, C, D]
	// v1.s[0] = E
	ld1 {v0.4s}, [x0], #16
	ld1 {v1.s}[0], [x0]
	sub x0, x0, #16

	// Save original state for final addition
	mov v16.16b, v0.16b
	mov v17.16b, v1.16b

	// Load ALL SHA-1 constants into v20
	adrp x2, k_sha1
	add x2, x2, :lo12:k_sha1
	ld1 {v20.4s}, [x2]

	// Load message (64 bytes) into v2, v3, v4, v5
	ld1 {v2.16b-v5.16b}, [x1]

	// Convert to big-endian (SHA-1 uses big-endian words)
	rev32 v2.16b, v2.16b
	rev32 v3.16b, v3.16b
	rev32 v4.16b, v4.16b
	rev32 v5.16b, v5.16b

	// ------------------------------------------------------------
	// Round groups of 4 rounds each, total 20 groups (80 rounds)
	// Rotating buffer: v2, v3, v4, v5 hold the next 4 words.
	// After each group (except the last 4) the used vector is updated
	// with the next 4 words of the message schedule.
	// ------------------------------------------------------------

	// Group 0: rounds 0..3, K0, use v2 (W[0..3])
	dup v6.4s, v20.s[0]
	add v6.4s, v6.4s, v2.4s
	mov v7.16b, v0.16b
	sha1c q0, s1, v6.4s
	sha1h s1, s7
	sha1su0 v2.4s, v3.4s, v4.4s
	sha1su1 v2.4s, v5.4s

	// Group 1: rounds 4..7, K0, use v3 (W[4..7])
	dup v6.4s, v20.s[0]
	add v6.4s, v6.4s, v3.4s
	mov v7.16b, v0.16b
	sha1c q0, s1, v6.4s
	sha1h s1, s7
	sha1su0 v3.4s, v4.4s, v5.4s
	sha1su1 v3.4s, v2.4s

	// Group 2: rounds 8..11, K0, use v4 (W[8..11])
	dup v6.4s, v20.s[0]
	add v6.4s, v6.4s, v4.4s
	mov v7.16b, v0.16b
	sha1c q0, s1, v6.4s
	sha1h s1, s7
	sha1su0 v4.4s, v5.4s, v2.4s
	sha1su1 v4.4s, v3.4s

	// Group 3: rounds 12..15, K0, use v5 (W[12..15])
	dup v6.4s, v20.s[0]
	add v6.4s, v6.4s, v5.4s
	mov v7.16b, v0.16b
	sha1c q0, s1, v6.4s
	sha1h s1, s7
	sha1su0 v5.4s, v2.4s, v3.4s
	sha1su1 v5.4s, v4.4s

	// Group 4: rounds 16..19, K0, use v2 (now W[16..19])
	dup v6.4s, v20.s[0]
	add v6.4s, v6.4s, v2.4s
	mov v7.16b, v0.16b
	sha1c q0, s1, v6.4s
	sha1h s1, s7
	sha1su0 v2.4s, v3.4s, v4.4s
	sha1su1 v2.4s, v5.4s

	// Group 5: rounds 20..23, K1, use v3 (W[20..23])
	dup v6.4s, v20.s[1]
	add v6.4s, v6.4s, v3.4s
	mov v7.16b, v0.16b
	sha1p q0, s1, v6.4s
	sha1h s1, s7
	sha1su0 v3.4s, v4.4s, v5.4s
	sha1su1 v3.4s, v2.4s

	// Group 6: rounds 24..27, K1, use v4 (W[24..27])
	dup v6.4s, v20.s[1]
	add v6.4s, v6.4s, v4.4s
	mov v7.16b, v0.16b
	sha1p q0, s1, v6.4s
	sha1h s1, s7
	sha1su0 v4.4s, v5.4s, v2.4s
	sha1su1 v4.4s, v3.4s

	// Group 7: rounds 28..31, K1, use v5 (W[28..31])
	dup v6.4s, v20.s[1]
	add v6.4s, v6.4s, v5.4s
	mov v7.16b, v0.16b
	sha1p q0, s1, v6.4s
	sha1h s1, s7
	sha1su0 v5.4s, v2.4s, v3.4s
	sha1su1 v5.4s, v4.4s

	// Group 8: rounds 32..35, K1, use v2 (W[32..35])
	dup v6.4s, v20.s[1]
	add v6.4s, v6.4s, v2.4s
	mov v7.16b, v0.16b
	sha1p q0, s1, v6.4s
	sha1h s1, s7
	sha1su0 v2.4s, v3.4s, v4.4s
	sha1su1 v2.4s, v5.4s

	// Group 9: rounds 36..39, K1, use v3 (W[36..39])
	dup v6.4s, v20.s[1]
	add v6.4s, v6.4s, v3.4s
	mov v7.16b, v0.16b
	sha1p q0, s1, v6.4s
	sha1h s1, s7
	sha1su0 v3.4s, v4.4s, v5.4s
	sha1su1 v3.4s, v2.4s

	// Group 10: rounds 40..43, K2, use v4 (W[40..43])
	dup v6.4s, v20.s[2]
	add v6.4s, v6.4s, v4.4s
	mov v7.16b, v0.16b
	sha1m q0, s1, v6.4s
	sha1h s1, s7
	sha1su0 v4.4s, v5.4s, v2.4s
	sha1su1 v4.4s, v3.4s

	// Group 11: rounds 44..47, K2, use v5 (W[44..47])
	dup v6.4s, v20.s[2]
	add v6.4s, v6.4s, v5.4s
	mov v7.16b, v0.16b
	sha1m q0, s1, v6.4s
	sha1h s1, s7
	sha1su0 v5.4s, v2.4s, v3.4s
	sha1su1 v5.4s, v4.4s

	// Group 12: rounds 48..51, K2, use v2 (W[48..51])
	dup v6.4s, v20.s[2]
	add v6.4s, v6.4s, v2.4s
	mov v7.16b, v0.16b
	sha1m q0, s1, v6.4s
	sha1h s1, s7
	sha1su0 v2.4s, v3.4s, v4.4s
	sha1su1 v2.4s, v5.4s

	// Group 13: rounds 52..55, K2, use v3 (W[52..55])
	dup v6.4s, v20.s[2]
	add v6.4s, v6.4s, v3.4s
	mov v7.16b, v0.16b
	sha1m q0, s1, v6.4s
	sha1h s1, s7
	sha1su0 v3.4s, v4.4s, v5.4s
	sha1su1 v3.4s, v2.4s

	// Group 14: rounds 56..59, K2, use v4 (W[56..59])
	dup v6.4s, v20.s[2]
	add v6.4s, v6.4s, v4.4s
	mov v7.16b, v0.16b
	sha1m q0, s1, v6.4s
	sha1h s1, s7
	sha1su0 v4.4s, v5.4s, v2.4s
	sha1su1 v4.4s, v3.4s

	// Group 15: rounds 60..63, K3, use v5 (W[60..63])
	dup v6.4s, v20.s[3]
	add v6.4s, v6.4s, v5.4s
	mov v7.16b, v0.16b
	sha1p q0, s1, v6.4s
	sha1h s1, s7
	sha1su0 v5.4s, v2.4s, v3.4s
	sha1su1 v5.4s, v4.4s

	// Group 16: rounds 64..67, K3, use v2 (W[64..67])
	dup v6.4s, v20.s[3]
	add v6.4s, v6.4s, v2.4s
	mov v7.16b, v0.16b
	sha1p q0, s1, v6.4s
	sha1h s1, s7

	// Group 17: rounds 68..71, K3, use v3 (W[68..71])
	dup v6.4s, v20.s[3]
	add v6.4s, v6.4s, v3.4s
	mov v7.16b, v0.16b
	sha1p q0, s1, v6.4s
	sha1h s1, s7

	// Group 18: rounds 72..75, K3, use v4 (W[72..75])
	dup v6.4s, v20.s[3]
	add v6.4s, v6.4s, v4.4s
	mov v7.16b, v0.16b
	sha1p q0, s1, v6.4s
	sha1h s1, s7

	// Group 19: rounds 76..79, K3, use v5 (W[76..79])
	dup v6.4s, v20.s[3]
	add v6.4s, v6.4s, v5.4s
	mov v7.16b, v0.16b
	sha1p q0, s1, v6.4s
	sha1h s1, s7

	// Add original state
	add v0.4s, v0.4s, v16.4s
	add v1.4s, v1.4s, v17.4s

	// Store result back to state
	st1 {v0.4s}, [x0], #16
	st1 {v1.s}[0], [x0]

	// Restore and return
	ldp x29, x30, [sp], #16
	ret

.size sha1TransformArm64, .-sha1TransformArm64
