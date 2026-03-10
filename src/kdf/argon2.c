#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../includes/kdf/argon2.h"
#include "../../includes/hash/blake2b.h"
#include "../../hajlib/include/hmemory.h"
#include "../../includes/utils/bitopts.h"



static void xorBlock(t_argon2Block *dst, const t_argon2Block *src)
{
	for (int i = 0; i < ARGON2_QWORDS_PER_BLOCK; ++i)
		dst->v[i] ^= src->v[i];
}

/**
 * @brief Fills a memory block using the previous block and a reference block.
 * @param prevBlock The previous block in the lane (or the last block of the previous segment)
 * @param refBlock The reference block determined by the pseudo-random value
 * @param nextBlock The block to be filled (current block)
 * @param withXor If true, the final output will be XORed with the existing content of nextBlock (used in subsequent passes)
 */
static void fillBlock(const t_argon2Block	*prevBlock,
					  const t_argon2Block	*refBlock,
					  t_argon2Block			*nextBlock,
					  int					withXor)
{
	t_argon2Block	blockR, blockTmp;

	ft_memcpy(blockR.v, refBlock->v, sizeof(uint64_t) * ARGON2_QWORDS_PER_BLOCK);
	xorBlock(&blockR, prevBlock);
	ft_memcpy(blockTmp.v, &blockR.v, sizeof(uint64_t) * ARGON2_QWORDS_PER_BLOCK);
	if (withXor)
		xorBlock(&blockTmp, nextBlock);

	/* Apply Blake2 on columns */
	for (unsigned i = 0; i < 8; ++i) {
		BLAKE2_ROUND_NOMSG(
			blockR.v[16 * i], blockR.v[16 * i + 1], blockR.v[16 * i + 2],
			blockR.v[16 * i + 3], blockR.v[16 * i + 4], blockR.v[16 * i + 5],
			blockR.v[16 * i + 6], blockR.v[16 * i + 7], blockR.v[16 * i + 8],
			blockR.v[16 * i + 9], blockR.v[16 * i + 10], blockR.v[16 * i + 11],
			blockR.v[16 * i + 12], blockR.v[16 * i + 13], blockR.v[16 * i + 14],
			blockR.v[16 * i + 15]);
	}

	/* Apply Blake2 on rows */
	for (unsigned i = 0; i < 8; ++i) {
		BLAKE2_ROUND_NOMSG(
			blockR.v[2 * i], blockR.v[2 * i + 1], blockR.v[2 * i + 16],
			blockR.v[2 * i + 17], blockR.v[2 * i + 32], blockR.v[2 * i + 33],
			blockR.v[2 * i + 48], blockR.v[2 * i + 49], blockR.v[2 * i + 64],
			blockR.v[2 * i + 65], blockR.v[2 * i + 80], blockR.v[2 * i + 81],
			blockR.v[2 * i + 96], blockR.v[2 * i + 97], blockR.v[2 * i + 112],
			blockR.v[2 * i + 113]);
	}

	ft_memcpy(nextBlock->v, blockTmp.v, sizeof(uint64_t) * ARGON2_QWORDS_PER_BLOCK);
	xorBlock(nextBlock, &blockR);
}

/**
 * @brief Generates the next addresses for data-independent addressing.
 *
 * This function is used in the data-independent addressing mode of Argon2 (ARGON2_I and the first pass of ARGON2_ID).
 * It generates the next set of addresses based on the current input block and a zero block,
 * which are used to determine the reference blocks for filling the memory.
 * @param addressBlock The block to store the generated addresses.
 * @param inputBlock The input block used for address generation.
 * @param zeroBlock The zero block used for address generation.
 */
static void nextAddresses(t_argon2Block			*addressBlock,
						  t_argon2Block			*inputBlock,
						  const t_argon2Block	*zeroBlock)
{
	inputBlock->v[6]++;
	fillBlock(zeroBlock, inputBlock, addressBlock, 0);
	fillBlock(zeroBlock, addressBlock, addressBlock, 0);
}

/**
 * @brief Computes the index of the reference block for the current block being filled.
 *
 * This function implements the index computation as specified in the Argon2 specification.
 * It takes into account the current position in the memory (pass, lane, slice, index), the pseudo-random value,
 * and whether the reference block must be in the same lane or can be in any lane.
 * @param ctx The Argon2 context containing parameters and state.
 * @param pos The current position in the memory (pass, lane, slice, index).
 * @param pseudoRand The pseudo-random value used to determine the reference block.
 * @param sameLane Indicates whether the reference block must be in the same lane or can be in any lane.
 * @return The index of the reference block within the lane.
 */
static uint32_t indexAlpha(const t_argon2Ctx	*ctx,
						   const t_argon2Position	*pos,
						   uint32_t				pseudoRand,
						   int					sameLane) {
	uint32_t	refAreaSize;
	uint64_t	relPos;
	uint32_t	startPos, absPos;

	if (pos->pass == 0) {
		if (pos->slice == 0) {
			refAreaSize = pos->index - 1;
		} else {
			if (sameLane)
				refAreaSize = pos->slice * ctx->segmentLength + pos->index - 1;
			else
				refAreaSize = pos->slice * ctx->segmentLength + ((pos->index == 0) ? -1 : 0);
		}
	} else {
		if (sameLane)
			refAreaSize = ctx->blocksPerLane - ctx->segmentLength + pos->index - 1;
		else
			refAreaSize = ctx->blocksPerLane - ctx->segmentLength + ((pos->index == 0) ? -1 : 0);
	}

	if (refAreaSize < 0) refAreaSize = 0;

	relPos = pseudoRand;
	relPos = (relPos * relPos) >> 32;
	if (refAreaSize > 0)
		relPos = refAreaSize - 1 - (refAreaSize * relPos >> 32);
	else
		relPos = 0;

	startPos = 0;
	if (pos->pass != 0) {
		startPos = (pos->slice == ARGON2_SYNC_POINTS - 1)
					   ? 0
					   : (pos->slice + 1) * ctx->segmentLength;
	}

	absPos = (startPos + (uint32_t)relPos) % ctx->blocksPerLane;
	return (absPos);
}

static void fillSegment(t_argon2Ctx *ctx, t_argon2Position pos)
{
	t_argon2Block	addressBlock, inputBlock, zeroBlock;
	uint64_t		pseudoRand, refLane ;
	uint32_t		prevOffset, currOffset;
	uint32_t		startIdx;
	int				dataIndependent;

	if (!ctx) return;

	dataIndependent = (ctx->type == ARGON2_I) ||
					  (ctx->type == ARGON2_ID && pos.pass == 0 &&
					   pos.slice < ARGON2_SYNC_POINTS / 2);

	if (dataIndependent) {
		ft_memset(zeroBlock.v, 0, sizeof(zeroBlock.v));
		ft_memset(inputBlock.v, 0, sizeof(inputBlock.v));
		inputBlock.v[0] = pos.pass;
		inputBlock.v[1] = pos.lane;
		inputBlock.v[2] = pos.slice;
		inputBlock.v[3] = ctx->memory;		   /* total blocks */
		inputBlock.v[4] = ctx->iterations;	   /* passes */
		inputBlock.v[5] = ctx->type;
		/* v[6] is counter, starts at 0 implicitly */
	}

	startIdx = 0;
	if (pos.pass == 0 && pos.slice == 0) {
		startIdx = 2;   /* first two blocks already generated */
		if (dataIndependent)
			nextAddresses(&addressBlock, &inputBlock, &zeroBlock);
	}

	currOffset = pos.lane * ctx->blocksPerLane +
				 pos.slice * ctx->segmentLength + startIdx;

	if (currOffset % ctx->blocksPerLane == 0)
		prevOffset = currOffset + ctx->blocksPerLane - 1;
	else
		prevOffset = currOffset - 1;

	for (uint32_t i = startIdx; i < ctx->segmentLength; ++i, ++currOffset, ++prevOffset) {
		/* Rotate prevOffset if needed */
		if (currOffset % ctx->blocksPerLane == 1)
			prevOffset = currOffset - 1;

		/* Get pseudo-random value */
		if (dataIndependent) {
			if (i % ARGON2_QWORDS_PER_BLOCK == 0)
				nextAddresses(&addressBlock, &inputBlock, &zeroBlock);
			pseudoRand = addressBlock.v[i % ARGON2_QWORDS_PER_BLOCK];
		} else
			pseudoRand = ctx->memoryArray[prevOffset].v[0];

		/* Compute reference lane */
		refLane = (pseudoRand >> 32) % ctx->parallelism;
		if (pos.pass == 0 && pos.slice == 0)
			refLane = pos.lane;

		/* Compute reference index */
		pos.index = i;

		fillBlock(ctx->memoryArray + prevOffset,
				  ctx->memoryArray + refLane * ctx->blocksPerLane
					+ indexAlpha(ctx, &pos, (uint32_t)pseudoRand,
				  (refLane == pos.lane)),
				  ctx->memoryArray + currOffset,
				  (pos.pass != 0));
	}
}

static void fillMemoryBlocks(t_argon2Ctx *ctx)
{
	for (uint32_t pass = 0; pass < ctx->iterations; ++pass) {
		for (uint32_t slice = 0; slice < ARGON2_SYNC_POINTS; ++slice) {
			for (uint32_t lane = 0; lane < ctx->parallelism; ++lane) {
				t_argon2Position pos = {pass, lane, (uint8_t)slice, 0};
				fillSegment(ctx, pos);
			}
		}
	}
}

/**
 * @brief Initializes the first two blocks of each lane using the initial hash (H0) and fills the memory blocks.
 *
 * This function computes the initial hash (H0) based on the input parameters and then fills the first two blocks of each lane
 * using the initial hash as a seed.
 * @param ctx The Argon2 context containing parameters and state.
 * @param hash0 The initial hash generated from the input parameters, used as a seed for filling the memory.
 */
static void initialHash(const t_argon2Ctx *ctx, uint8_t hash0[ARGON2_PREHASH_DIGEST_LENGTH])
{
	t_blake2bCtx	b2;
	uint32_t		tmp;

	blake2bInit(&b2);
	blake2bSetOutlen(&b2, ARGON2_PREHASH_DIGEST_LENGTH);

	tmp = ctx->parallelism;	blake2bUpdate(&b2, (uint8_t*)&tmp, sizeof(tmp));
	tmp = ctx->outputLen;	blake2bUpdate(&b2, (uint8_t*)&tmp, sizeof(tmp));
	tmp = ctx->memory;		blake2bUpdate(&b2, (uint8_t*)&tmp, sizeof(tmp));
	tmp = ctx->iterations;	blake2bUpdate(&b2, (uint8_t*)&tmp, sizeof(tmp));
	tmp = ctx->version;		blake2bUpdate(&b2, (uint8_t*)&tmp, sizeof(tmp));
	tmp = ctx->type;		blake2bUpdate(&b2, (uint8_t*)&tmp, sizeof(tmp));

	tmp = ctx->passwordLen;	blake2bUpdate(&b2, (uint8_t*)&tmp, sizeof(tmp));
	blake2bUpdate(&b2, ctx->password, ctx->passwordLen);

	tmp = ctx->saltLen;		blake2bUpdate(&b2, (uint8_t*)&tmp, sizeof(tmp));
	blake2bUpdate(&b2, ctx->salt, ctx->saltLen);

	tmp = ctx->secretLen;	blake2bUpdate(&b2, (uint8_t*)&tmp, sizeof(tmp));
	if (ctx->secret) blake2bUpdate(&b2, ctx->secret, ctx->secretLen);

	tmp = ctx->adLen;		blake2bUpdate(&b2, (uint8_t*)&tmp, sizeof(tmp));
	if (ctx->ad) blake2bUpdate(&b2, ctx->ad, ctx->adLen);

	blake2bFinal(hash0, &b2);
}

/**
 * @brief Fills the first two blocks of each lane using the initial hash (H0) as a seed.
 *
 * This function takes the initial hash (H0) generated from the input parameters and fills the first two blocks of each lane
 * using a combination of the initial hash and the lane index. It uses the blake2bLong function to generate the block content.
 * @param seed The initial hash (H0) used as a seed for filling the first blocks.
 * @param ctx The Argon2 context containing parameters and state.
 */
static void fillFirstBlocks(uint8_t *seed, const t_argon2Ctx *ctx)
{
	uint8_t	input[ARGON2_PREHASH_SEED_LENGTH];
	ft_memcpy(input, seed, ARGON2_PREHASH_SEED_LENGTH);

	for (uint32_t l = 0; l < ctx->parallelism; ++l) {
		/* Block 0: index 0, lane l */
		store32(input + ARGON2_PREHASH_DIGEST_LENGTH, 0);
		store32(input + ARGON2_PREHASH_DIGEST_LENGTH + 4, l);
		blake2bLong((uint8_t*)&ctx->memoryArray[l * ctx->blocksPerLane + 0],
					ARGON2_BLOCK_SIZE, input, ARGON2_PREHASH_SEED_LENGTH);

		/* Block 1: index 1, lane l */
		store32(input + ARGON2_PREHASH_DIGEST_LENGTH, 1);
		blake2bLong((uint8_t*)&ctx->memoryArray[l * ctx->blocksPerLane + 1],
					ARGON2_BLOCK_SIZE, input, ARGON2_PREHASH_SEED_LENGTH);
	}
}

/* ---------- Public API ---------- */

void argon2InitDefault(t_argon2Ctx *ctx) {
	ft_bzero(ctx, sizeof(t_argon2Ctx));
	ctx->password = NULL;
	ctx->passwordLen = 0;
	ctx->salt = NULL;
	ctx->saltLen = 0;
	ctx->secret = NULL;
	ctx->secretLen = 0;
	ctx->ad = NULL;
	ctx->adLen = 0;
	ctx->memory = ARGON2_DEFAULT_MEMORY;
	ctx->iterations = ARGON2_DEFAULT_ITERATIONS;
	ctx->parallelism = ARGON2_DEFAULT_PARALLELISM;
	ctx->type = ARGON2_DEFAULT_TYPE;
	ctx->version = ARGON2_VERSION;
	ctx->outputLen = 32;
}

void argon2Init(t_argon2Ctx		*ctx,
				const uint8_t	*password,	size_t	passLen,
				const uint8_t	*salt,		size_t	saltLen,
				uint32_t		memory,
				uint32_t		iterations,
				uint32_t		parallelism,
				t_argon2Type type)
{
	ft_bzero(ctx, sizeof(t_argon2Ctx));
	ctx->password = password;
	ctx->passwordLen = (uint32_t)passLen;
	ctx->salt = salt;
	ctx->saltLen = (uint32_t)saltLen;
	ctx->memory = memory;
	ctx->iterations = iterations;
	ctx->parallelism = parallelism;
	ctx->type = type;
	ctx->version = ARGON2_VERSION;
	ctx->secret = NULL;
	ctx->secretLen = 0;
	ctx->ad = NULL;
	ctx->adLen = 0;
	ctx->flags = 0;
	ctx->outputLen = 32;
}

int argon2Hash(const t_argon2Ctx *ctx, uint8_t *output, size_t outputLen)
{
	t_argon2Ctx	local = *ctx;
	uint8_t		h0[ARGON2_PREHASH_DIGEST_LENGTH];
	uint8_t		seed[ARGON2_PREHASH_SEED_LENGTH];

	uint32_t	totalBlocks = local.memory;		  /* memory in KiB = number of blocks */
	uint32_t	lanes = local.parallelism;
	uint32_t	blocksPerLane = totalBlocks / lanes;

	if (outputLen != local.outputLen) return (-1);
	if (lanes == 0 || blocksPerLane < 2) return (-1);
	if (local.iterations == 0) return (-1);

	initialHash(&local, h0);

	ft_memcpy(seed, h0, ARGON2_PREHASH_DIGEST_LENGTH);
	ft_memcpy(seed + ARGON2_PREHASH_DIGEST_LENGTH, h0, 8);

	local.memoryArray = (t_argon2Block*)calloc(totalBlocks, sizeof(t_argon2Block));
	if (!local.memoryArray) return (-1);

	local.blocksPerLane = blocksPerLane;
	local.segmentLength = blocksPerLane / ARGON2_SYNC_POINTS;

	fillFirstBlocks(seed, &local);
	fillMemoryBlocks(&local);

	/* Combine last blocks of each lane */
	t_argon2Block finalBlock;
	ft_bzero(&finalBlock, sizeof(finalBlock));
	for (uint32_t i = 0; i < lanes; ++i) {
		uint32_t last = (i + 1) * blocksPerLane - 1;
		for (uint32_t j = 0; j < ARGON2_QWORDS_PER_BLOCK; ++j)
			finalBlock.v[j] ^= local.memoryArray[last].v[j];
	}

	uint8_t blockBytes[ARGON2_BLOCK_SIZE];
	for (unsigned i = 0; i < ARGON2_QWORDS_PER_BLOCK; ++i)
		store64((uint8_t *)blockBytes + i * sizeof(finalBlock.v[i]), finalBlock.v[i]);
	blake2bLong(output, outputLen, blockBytes, ARGON2_BLOCK_SIZE);

	free(local.memoryArray);
	return (0);
}

int argon2id(const uint8_t	*password,	size_t	passLen,
			 uint8_t		*output,	size_t	outputLen)
{
	t_argon2Ctx ctx;
	argon2InitDefault(&ctx);
	ctx.password = password;
	ctx.passwordLen = (uint32_t)passLen;
	ctx.outputLen = (uint32_t)outputLen;
	static const uint8_t dummySalt[16] = {0};
	ctx.salt = dummySalt;
	ctx.saltLen = 16;
	return argon2Hash(&ctx, output, outputLen);
}
