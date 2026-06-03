// ARMv8 SHA256 implementation using crypto extensions
// void sha256Transform_arm64(uint32_t *state, const uint8_t *data)

.text
.align 5

// K256 constants
.type k256, @object
.size k256, 256
k256:
.word 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5
.word 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5
.word 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3
.word 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174
.word 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc
.word 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da
.word 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7
.word 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967
.word 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13
.word 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85
.word 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3
.word 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070
.word 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5
.word 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3
.word 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208
.word 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2

.globl sha256TransformArm64
.type sha256TransformArm64, @function
sha256TransformArm64:
	// Save frame pointer and link register
	stp x29, x30, [sp, #-16]!
	mov x29, sp

	// Load state (8 words) into v0 (ABCD) and v1 (EFGH)
	ld1 {v0.4s}, [x0], #16
	ld1 {v1.4s}, [x0]
	sub x0, x0, #16		  // restore original pointer

	// Save original state for final addition
	mov v16.16b, v0.16b
	mov v17.16b, v1.16b

	// Load K256 table address
	adrp x2, k256
	add x2, x2, :lo12:k256

	// Load message (64 bytes) into v2, v3, v4, v5
	ld1 {v2.16b-v5.16b}, [x1]

	// Convert to big-endian
	rev32 v2.16b, v2.16b
	rev32 v3.16b, v3.16b
	rev32 v4.16b, v4.16b
	rev32 v5.16b, v5.16b


    // ------------------------------------------------------------
    // Process 4 SHA-256 rounds (round group i .. i+3)
    // Registers convention in this implementation:
    //   q0 (v0) = ABCD state words
    //   q1 (v1) = EFGH state words
    //   v2      = current message schedule words W[i..i+3]
    //   x2      = pointer to round constants K[]
    // ------------------------------------------------------------

    ld1 {v6.4s}, [x2], #16
    // Load 4 consecutive 32-bit round constants K[i..i+3]
    // from memory into vector register v6.
    // Post-increment the constant pointer (x2) by 16 bytes.

    add v6.4s, v6.4s, v2.4s
    // Add the corresponding message schedule words W[i..i+3]
    // to the constants.
    // Each lane performs:
    //     v6[j] = K[i+j] + W[i+j]
    // This prepares the input required for the 4 rounds.

    mov v7.16b, v0.16b
    // Preserve the current ABCD state.
    // sha256h2 requires the original ABCD values,
    // so we keep a copy before modifying q0.

    sha256h q0, q1, v6.4s
    // Execute 4 SHA-256 rounds updating the ABCD state.
    //
    // Inputs:
    //   q0 = ABCD
    //   q1 = EFGH
    //   v6 = W + K values
    //
    // This instruction performs:
    //   T1 = H + Σ1(E) + Ch(E,F,G) + W + K
    //   T2 = Σ0(A) + Maj(A,B,C)
    //
    // and updates the ABCD lanes accordingly for 4 rounds.

    sha256h2 q1, q7, v6.4s
    // Execute the complementary part of the same 4 rounds,
    // updating the EFGH state.
    //
    // Inputs:
    //   q1 = EFGH
    //   q7 = preserved ABCD (original values)
    //   v6 = W + K values
    //
    // This completes the state transition for the 4 rounds.

    // ------------------------------------------------------------
    // Update the message schedule (W array expansion)
    // Prepare the next 4 message words for future rounds
    // ------------------------------------------------------------

    sha256su0 v2.4s, v3.4s
    // Perform the first stage of message schedule update.
    // Applies the σ0 function and partial accumulation:
    //     W[i] += σ0(W[i-15])
    // Vectorized across 4 lanes.

    sha256su1 v2.4s, v4.4s, v5.4s
    // Complete the message schedule update.
    // Applies σ1 and final additions:
    //     W[i] += W[i-7] + σ1(W[i-2])
    //
    // After this instruction, v2 contains
    // the next 4 expanded message words.

	// Continue for following rounds...

	// Round group 4..7
	ld1 {v6.4s}, [x2], #16
	add v6.4s, v6.4s, v3.4s
	mov v7.16b, v0.16b
	sha256h q0, q1, v6.4s
	sha256h2 q1, q7, v6.4s

	sha256su0 v3.4s, v4.4s
	sha256su1 v3.4s, v5.4s, v2.4s

	// Round group 8..11
	ld1 {v6.4s}, [x2], #16
	add v6.4s, v6.4s, v4.4s
	mov v7.16b, v0.16b
	sha256h q0, q1, v6.4s
	sha256h2 q1, q7, v6.4s

	sha256su0 v4.4s, v5.4s
	sha256su1 v4.4s, v2.4s, v3.4s

	// Round group 12..15
	ld1 {v6.4s}, [x2], #16
	add v6.4s, v6.4s, v5.4s
	mov v7.16b, v0.16b
	sha256h q0, q1, v6.4s
	sha256h2 q1, q7, v6.4s

	sha256su0 v5.4s, v2.4s
	sha256su1 v5.4s, v3.4s, v4.4s

	// Round group 16..19
	ld1 {v6.4s}, [x2], #16
	add v6.4s, v6.4s, v2.4s
	mov v7.16b, v0.16b
	sha256h q0, q1, v6.4s
	sha256h2 q1, q7, v6.4s

	sha256su0 v2.4s, v3.4s
	sha256su1 v2.4s, v4.4s, v5.4s

	// Round group 20..23
	ld1 {v6.4s}, [x2], #16
	add v6.4s, v6.4s, v3.4s
	mov v7.16b, v0.16b
	sha256h q0, q1, v6.4s
	sha256h2 q1, q7, v6.4s

	sha256su0 v3.4s, v4.4s
	sha256su1 v3.4s, v5.4s, v2.4s

	// Round group 24..27
	ld1 {v6.4s}, [x2], #16
	add v6.4s, v6.4s, v4.4s
	mov v7.16b, v0.16b
	sha256h q0, q1, v6.4s
	sha256h2 q1, q7, v6.4s

	sha256su0 v4.4s, v5.4s
	sha256su1 v4.4s, v2.4s, v3.4s

	// Round group 28..31
	ld1 {v6.4s}, [x2], #16
	add v6.4s, v6.4s, v5.4s
	mov v7.16b, v0.16b
	sha256h q0, q1, v6.4s
	sha256h2 q1, q7, v6.4s

	sha256su0 v5.4s, v2.4s
	sha256su1 v5.4s, v3.4s, v4.4s

	// Round group 32..35
	ld1 {v6.4s}, [x2], #16
	add v6.4s, v6.4s, v2.4s
	mov v7.16b, v0.16b
	sha256h q0, q1, v6.4s
	sha256h2 q1, q7, v6.4s

	sha256su0 v2.4s, v3.4s
	sha256su1 v2.4s, v4.4s, v5.4s

	// Round group 36..39
	ld1 {v6.4s}, [x2], #16
	add v6.4s, v6.4s, v3.4s
	mov v7.16b, v0.16b
	sha256h q0, q1, v6.4s
	sha256h2 q1, q7, v6.4s

	sha256su0 v3.4s, v4.4s
	sha256su1 v3.4s, v5.4s, v2.4s

	// Round group 40..43
	ld1 {v6.4s}, [x2], #16
	add v6.4s, v6.4s, v4.4s
	mov v7.16b, v0.16b
	sha256h q0, q1, v6.4s
	sha256h2 q1, q7, v6.4s

	sha256su0 v4.4s, v5.4s
	sha256su1 v4.4s, v2.4s, v3.4s

	// Round group 44..47
	ld1 {v6.4s}, [x2], #16
	add v6.4s, v6.4s, v5.4s
	mov v7.16b, v0.16b
	sha256h q0, q1, v6.4s
	sha256h2 q1, q7, v6.4s

	sha256su0 v5.4s, v2.4s
	sha256su1 v5.4s, v3.4s, v4.4s

	// Round group 48..51
	ld1 {v6.4s}, [x2], #16
	add v6.4s, v6.4s, v2.4s
	mov v7.16b, v0.16b
	sha256h q0, q1, v6.4s
	sha256h2 q1, q7, v6.4s

	sha256su0 v2.4s, v3.4s
	sha256su1 v2.4s, v4.4s, v5.4s

	// Round group 52..55
	ld1 {v6.4s}, [x2], #16
	add v6.4s, v6.4s, v3.4s
	mov v7.16b, v0.16b
	sha256h q0, q1, v6.4s
	sha256h2 q1, q7, v6.4s

	sha256su0 v3.4s, v4.4s
	sha256su1 v3.4s, v5.4s, v2.4s

	// Round group 56..59
	ld1 {v6.4s}, [x2], #16
	add v6.4s, v6.4s, v4.4s
	mov v7.16b, v0.16b
	sha256h q0, q1, v6.4s
	sha256h2 q1, q7, v6.4s

	sha256su0 v4.4s, v5.4s
	sha256su1 v4.4s, v2.4s, v3.4s

	// Round group 60..63
	ld1 {v6.4s}, [x2], #16
	add v6.4s, v6.4s, v5.4s
	mov v7.16b, v0.16b
	sha256h q0, q1, v6.4s
	sha256h2 q1, q7, v6.4s

	sha256su0 v5.4s, v2.4s
	sha256su1 v5.4s, v3.4s, v4.4s

	// Add original state
	add v0.4s, v0.4s, v16.4s
	add v1.4s, v1.4s, v17.4s

	// Store result back to state
	st1 {v0.4s}, [x0], #16
	st1 {v1.4s}, [x0]

	// Restore and return
	ldp x29, x30, [sp], #16
	ret

.size sha256TransformArm64, .-sha256TransformArm64
