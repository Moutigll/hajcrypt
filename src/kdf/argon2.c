#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../hajlib/include/hmath.h"
#include "../../hajlib/include/hmemory.h"
#include "../../hajlib/include/hprintf.h"
#include "../../hajlib/include/hstring.h"

#include "../../includes/utils/bitopts.h"
#include "../../includes/utils/random.h"
#include "../../includes/utils/utils.h"

#include "../../includes/hash/blake2b.h"
#include "../../includes/cipher/base64.h"
#include "../../includes/consts/base64.h"

#include "../../includes/kdf/argon2.h"

static size_t base64EncodeNoPad(const uint8_t *input, size_t inputLen, char *output, size_t outputSize)
{
	if (outputSize < ((inputLen + 2) / 3) * 4 + 1)
		return (0);

	t_base64Ctx ctx;
	base64Init(&ctx, NULL, 0, NULL, CIPHER_ENCRYPT);
	
	size_t outLen1 = 0;
	base64Update(&ctx, input, inputLen, (uint8_t*)output, &outLen1);
	
	size_t outLen2 = 0;
	/* Finalize without padding */
	if (ctx.bits > 0) {
		ctx.buffer <<= (6 - ctx.bits);
		output[outLen1 + outLen2++] = g_base64_enc[ctx.buffer & 0x3F];
	}
	
	size_t totalLen = outLen1 + outLen2;
	if (totalLen < outputSize)
		output[totalLen] = '\0';
	return (totalLen);
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
	t_argon2Block	blockR;
	uint64_t		*blockR_v = blockR.v;
	const uint64_t	*prev_v = prevBlock->v;
	const uint64_t	*ref_v = refBlock->v;
	uint64_t		*next_v = nextBlock->v;

	for (int i = 0; i < ARGON2_QWORDS_PER_BLOCK; ++i)
		blockR_v[i] = ref_v[i] ^ prev_v[i];

	uint64_t blockTmp[ARGON2_QWORDS_PER_BLOCK];
	for (int i = 0; i < ARGON2_QWORDS_PER_BLOCK; ++i)
		blockTmp[i] = blockR_v[i];
	
	if (withXor) {
		for (int i = 0; i < ARGON2_QWORDS_PER_BLOCK; ++i)
			blockTmp[i] ^= next_v[i];
	}

	/* Apply Blake2 on columns */
	for (unsigned i = 0; i < 8; ++i) {
		BLAKE2_ROUND_NOMSG(
			blockR_v[16 * i], blockR_v[16 * i + 1], blockR_v[16 * i + 2],
			blockR_v[16 * i + 3], blockR_v[16 * i + 4], blockR_v[16 * i + 5],
			blockR_v[16 * i + 6], blockR_v[16 * i + 7], blockR_v[16 * i + 8],
			blockR_v[16 * i + 9], blockR_v[16 * i + 10], blockR_v[16 * i + 11],
			blockR_v[16 * i + 12], blockR_v[16 * i + 13], blockR_v[16 * i + 14],
			blockR_v[16 * i + 15]);
	}

	/* Apply Blake2 on rows */
	for (unsigned i = 0; i < 8; ++i) {
		BLAKE2_ROUND_NOMSG(
			blockR_v[2 * i], blockR_v[2 * i + 1], blockR_v[2 * i + 16],
			blockR_v[2 * i + 17], blockR_v[2 * i + 32], blockR_v[2 * i + 33],
			blockR_v[2 * i + 48], blockR_v[2 * i + 49], blockR_v[2 * i + 64],
			blockR_v[2 * i + 65], blockR_v[2 * i + 80], blockR_v[2 * i + 81],
			blockR_v[2 * i + 96], blockR_v[2 * i + 97], blockR_v[2 * i + 112],
			blockR_v[2 * i + 113]);
	}

	for (int i = 0; i < ARGON2_QWORDS_PER_BLOCK; ++i)
		next_v[i] = blockTmp[i] ^ blockR_v[i];
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
		ft_bzero(&zeroBlock, sizeof(zeroBlock));
		ft_bzero(&inputBlock, sizeof(inputBlock));
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

#ifdef ARGON2_THREADED

#include <pthread.h>

static void* fillSegmentThread(void *arg) {
	t_argon2ThreadData *data = (t_argon2ThreadData*)arg;
	t_argon2Ctx *ctx = data->ctx;
	
	/* Thread-local sensitive data */
	t_argon2Block addressBlock = {0};
	t_argon2Block inputBlock = {0};
	t_argon2Block zeroBlock = {0};
	
	for (uint32_t lane = data->startLane; lane < data->endLane; ++lane) {
		t_argon2Position pos = {data->pass, lane, (uint8_t)data->slice, 0};
		fillSegment(ctx, pos);
	}
	
	/* Clean thread-local data if secure flag is set */
	if (ctx->flags & ARGON2_FLAG_CLEAR_MEMORY) {
		secureZeroMemory(&addressBlock, sizeof(addressBlock));
		secureZeroMemory(&inputBlock, sizeof(inputBlock));
		secureZeroMemory(&zeroBlock, sizeof(zeroBlock));
	}
	
	return (NULL);
}

static void fillMemoryBlocksThreaded(t_argon2Ctx *ctx)
{
	pthread_t			*threads = NULL;
	t_argon2ThreadData	*threadData = NULL;
	uint32_t			numThreads;
	uint32_t			lanesPerThread;
	
	/* Adapt number of threads based on the workload and memory size */
	numThreads = ctx->parallelism;
	if (numThreads > ARGON2_MAX_THREADS)
		numThreads = ARGON2_MAX_THREADS;
	
	/* Pour les petites charges, réduire le nombre de threads */
	if (ctx->iterations * ARGON2_SYNC_POINTS * ctx->parallelism < 100) {
		numThreads = (numThreads > 2) ? 2 : numThreads;
	}
	
	lanesPerThread = ctx->parallelism / numThreads;

	if (lanesPerThread < 2 && numThreads > 2) {
		numThreads = ctx->parallelism / 2;
		if (numThreads < 1) numThreads = 1;
		lanesPerThread = ctx->parallelism / numThreads;
	}

	threads = malloc(numThreads * sizeof(pthread_t));
	threadData = malloc(numThreads * sizeof(t_argon2ThreadData));
	
	if (!threads || !threadData) {
		free(threads);
		free(threadData);
		fillMemoryBlocks(ctx);
		return;
	}

	pthread_attr_t	attr;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

	for (uint32_t pass = 0; pass < ctx->iterations; ++pass) {
		for (uint32_t slice = 0; slice < ARGON2_SYNC_POINTS; ++slice) {
			uint32_t lane = 0;
			int threadsCreated = 0;
			
			for (uint32_t t = 0; t < numThreads; ++t) {
				if (lane >= ctx->parallelism)
					break;
					
				threadData[t].ctx = ctx;
				threadData[t].startLane = lane;
				threadData[t].endLane = lane + lanesPerThread;
				threadData[t].pass = pass;
				threadData[t].slice = slice;
				
				if (t == numThreads - 1 || 
					threadData[t].endLane > ctx->parallelism) {
					threadData[t].endLane = ctx->parallelism;
				}
				
				if (pthread_create(&threads[t], &attr, 
						fillSegmentThread, &threadData[t]) == 0) {
					threadsCreated++;
				} else {
					break;
				}
				
				lane = threadData[t].endLane;
				if (lane >= ctx->parallelism)
					break;
			}
			for (int t = 0; t < threadsCreated; ++t) {
				pthread_join(threads[t], NULL);
			}
		}
	}
	
	pthread_attr_destroy(&attr);
	free(threads);
	free(threadData);
}
#endif

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

/**
 * @brief Constant-time comparison of two memory buffers
 * @param buf1 First buffer
 * @param len1 Length of first buffer
 * @param buf2 Second buffer
 * @param len2 Length of second buffer
 * @return 0 if buffers are equal, -1 otherwise
 */
static int argon2SecureCompare(const uint8_t *buf1, size_t len1,
							   const uint8_t *buf2, size_t len2)
{
	if (len1 != len2)
		return (-1);
	
	volatile uint8_t result = 0;
	for (size_t i = 0; i < len1; ++i)
		result |= buf1[i] ^ buf2[i];
	
	return (result != 0 ? -1 : 0);
}

/* ---------- Public API ---------- */

int argon2SetPassword(t_argon2Ctx *ctx, const uint8_t *password, size_t len)
{
	if (!ctx || !password || len == 0 || len > ARGON2_MAX_PWD_LENGTH)
		return (-1);

	if (ctx->flags & ARGON2_FLAG_CLEAR_MEMORY) {
		uint8_t *copy = (uint8_t*)malloc(len);
		if (!copy)
			return (-1);
		
		ft_memcpy(copy, password, len);

		if (ctx->password) {
			if (ctx->flags & ARGON2_FLAG_CLEAR_MEMORY)
				secureFree((void*)ctx->password, ctx->passwordLen);
			else
				free((void*)ctx->password);
		}
		
		ctx->password = copy;
		ctx->passwordLen = (uint32_t)len;
	} 
	else {
		ctx->password = password;
		ctx->passwordLen = (uint32_t)len;
	}
	
	return (0);
}

int argon2SetSalt(t_argon2Ctx *ctx, const uint8_t *salt, size_t len)
{
	if (!ctx || !salt || len == 0 || len > ARGON2_MAX_SALT_LEN)
		return (-1);
	
	if (ctx->flags & ARGON2_FLAG_CLEAR_MEMORY) {
		uint8_t *copy = (uint8_t*)malloc(len);
		if (!copy)
			return (-1);
		
		ft_memcpy(copy, salt, len);
		
		if (ctx->salt) {
			if (ctx->flags & ARGON2_FLAG_CLEAR_MEMORY)
				secureFree((void*)ctx->salt, ctx->saltLen);
			else
				free((void*)ctx->salt);
		}
		
		ctx->salt = copy;
		ctx->saltLen = (uint32_t)len;
	}
	else {
		ctx->salt = salt;
		ctx->saltLen = (uint32_t)len;
	}
	
	return (0);
}

void argon2Free(t_argon2Ctx *ctx)
{
	if (!ctx)
		return;
	
	/* Wipe and free password if present */
	if (ctx->password) {
		if (ctx->flags & ARGON2_FLAG_CLEAR_MEMORY)
			secureFree((void*)ctx->password, ctx->passwordLen);
		ctx->password = NULL;
	}
	
	/* Wipe and free salt if present */
	if (ctx->salt) {
		if (ctx->flags & ARGON2_FLAG_CLEAR_MEMORY)
			secureFree((void*)ctx->salt, ctx->saltLen);
		ctx->salt = NULL;
	}
	
	/* Wipe and free secret if present */
	if (ctx->secret) {
		if (ctx->flags & ARGON2_FLAG_CLEAR_MEMORY)
			secureFree((void*)ctx->secret, ctx->secretLen);
		ctx->secret = NULL;
	}
	
	/* Wipe and free associated data if present */
	if (ctx->ad) {
		if (ctx->flags & ARGON2_FLAG_CLEAR_MEMORY)
			secureFree((void*)ctx->ad, ctx->adLen);
		ctx->ad = NULL;
	}
	
	/* Zero out the context structure itself */
	if (ctx->flags & ARGON2_FLAG_CLEAR_MEMORY)
		secureZeroMemory(ctx, sizeof(t_argon2Ctx));
	else
		ft_bzero(ctx, sizeof(t_argon2Ctx));
}


void argon2InitDefault(t_argon2Ctx *ctx) {
	if (!ctx)
		return;
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
	ctx->flags = 0;
#if defined(ARGON2_THREADED)
	ctx->flags |= ARGON2_FLAG_THREADING;
#endif
}

int argon2Init(t_argon2Ctx		*ctx,
				const uint8_t	*password,	size_t	passLen,
				const uint8_t	*salt,		size_t	saltLen,
				uint32_t		memory,
				uint32_t		iterations,
				uint32_t		parallelism,
				t_argon2Type	type)
{
	if (!ctx)
		return (-1);

	if (memory < (8 * parallelism)) return (-1);
	if (iterations < 1) return (-1);
	if (parallelism < 1 || parallelism > 0x00FFFFFF) return (-1);
	if (passLen > ARGON2_MAX_PWD_LENGTH || saltLen < 8) return (-1);
	ft_bzero(ctx, sizeof(t_argon2Ctx));

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
#if defined(ARGON2_THREADED)
	ctx->flags |= ARGON2_FLAG_THREADING;
#endif

	if (password && passLen > 0)
		argon2SetPassword(ctx, password, passLen);
	
	if (salt && saltLen > 0)
		argon2SetSalt(ctx, salt, saltLen);
	return (0);
}

int argon2Hash(const t_argon2Ctx *ctx, uint8_t *output, size_t outputLen)
{
	t_argon2Ctx	local = *ctx;
	uint8_t		h0[ARGON2_PREHASH_DIGEST_LENGTH];
	uint8_t		seed[ARGON2_PREHASH_SEED_LENGTH];

	uint32_t	totalBlocks = local.memory;		  /* memory in KiB = number of blocks */
	uint32_t	lanes = local.parallelism;
	uint32_t	blocksPerLane;

	if (!ctx || !output || outputLen == 0) return (-1);
	if (outputLen != local.outputLen) return (-1);
	if (lanes == 0) return (-1);
	blocksPerLane = totalBlocks / lanes;
	if (local.iterations == 0 || blocksPerLane < 2) return (-1);

	initialHash(&local, h0);

	ft_memcpy(seed, h0, ARGON2_PREHASH_DIGEST_LENGTH);
	ft_memcpy(seed + ARGON2_PREHASH_DIGEST_LENGTH, h0, 8);

	local.memoryArraySize = totalBlocks * sizeof(t_argon2Block);
	local.memoryArray = (t_argon2Block*) malloc(local.memoryArraySize);
	if (!local.memoryArray) return (-1);

	local.blocksPerLane = blocksPerLane;
	local.segmentLength = blocksPerLane / ARGON2_SYNC_POINTS;

	fillFirstBlocks(seed, &local);
#ifdef ARGON2_THREADED
	int use_threading = 0;
	if (local.flags & ARGON2_FLAG_THREADING) {
		if (local.memory >= ARGON2_MIN_MEMORY_FOR_THREADING && 
				local.parallelism > 1 &&
				local.iterations >= 2)
			use_threading = 1;
	}
	if (use_threading)
		fillMemoryBlocksThreaded(&local);
	else
		fillMemoryBlocks(&local);
#else
	fillMemoryBlocks(&local);
#endif

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

	if (local.flags & ARGON2_FLAG_CLEAR_MEMORY)
	{
		/* Securely wipe all sensitive data */
		if (local.memoryArray) {
			secureZeroMemory(local.memoryArray, local.memoryArraySize);
		}
		
		/* Wipe temporary buffers */
		secureZeroMemory(h0, sizeof(h0));
		secureZeroMemory(seed, sizeof(seed));
		secureZeroMemory(blockBytes, sizeof(blockBytes));
		
		/* Wipe the final block structure */
		secureZeroMemory(&finalBlock, sizeof(finalBlock));
	}

	secureFree(local.memoryArray, local.memoryArraySize);
	return (0);
}

int argon2id(const uint8_t	*password,	size_t	passLen,
			 uint8_t		*output,	size_t	outputLen)
{
	t_argon2Ctx	ctx;
	argon2InitDefault(&ctx);

	if (password && passLen > 0)
		argon2SetPassword(&ctx, password, passLen);


	uint8_t	salt[16];
	hajSecRandBytes(salt, sizeof(salt));
	argon2SetSalt(&ctx, salt, 16);
	
	ctx.outputLen = (uint32_t)outputLen;
	
	int ret = argon2Hash(&ctx, output, outputLen);
	argon2Free(&ctx);
	secureZeroMemory(salt, sizeof(salt));
	return (ret);
}

int argon2Encode(const t_argon2Ctx	*ctx,
				 const uint8_t		*hash,
				 size_t				hashLen,
				 char				*output,
				 size_t				outputSize)
{
	const char *type_str;
	char salt_b64[256];
	char hash_b64[256];
	
	if (!ctx || !hash || !output || outputSize == 0)
		return (-1);
	
	/* Get type string */
	switch (ctx->type) {
		case ARGON2_D:  type_str = "argon2d"; break;
		case ARGON2_I:  type_str = "argon2i"; break;
		case ARGON2_ID: type_str = "argon2id"; break;
		default: return (-1);
	}
	
	/* Base64 encode salt */
	if (ctx->salt && ctx->saltLen > 0)
		base64EncodeNoPad(ctx->salt, ctx->saltLen, salt_b64, sizeof(salt_b64));
	else
		salt_b64[0] = '\0';
	
	/* Base64 encode hash */
	base64EncodeNoPad(hash, hashLen, hash_b64, sizeof(hash_b64));
	
	/* Write encoded string */
	if (ft_snprintf(output, outputSize, "$%s$v=%u$m=%u,t=%u,p=%u$%s$%s",
				 type_str, ctx->version, ctx->memory, 
				 ctx->iterations, ctx->parallelism,
				 salt_b64, hash_b64) >= (int)outputSize) {
		return (-1);
	}
	
	return (0);
}


static int parseUint(const char **ptr, unsigned int *result)
{
	char	*endptr;
	
	if (!ptr || !*ptr || !result)
		return (-1);
	
	*result = ft_strtoul(*ptr, &endptr, 10);
	if (endptr == *ptr)  // Pas de chiffres trouvés
		return (-1);
	
	*ptr = endptr;
	return (0);
}

int argon2Decode(const char		*encoded,
				 t_argon2Ctx	*ctx,
				 uint8_t		*hash,
				 size_t			*hashLen)
{
	char			type_str[16];
	char			salt_b64[256];
	char			hash_b64[256];
	uint8_t			salt[64];
	size_t			salt_len;
	unsigned int	v, m, t, p;
	const char		*ptr;
	const char		*next;
	t_argon2Type	type;
	
	if (!encoded || !ctx || !hash || !hashLen)
		return (-1);

	if (encoded[0] != '$')
		return (-1);
	ptr = encoded + 1;
	
	next = ft_strchr(ptr, '$');
	if (!next) return (-1);
	ft_strlcpy(type_str, ptr, next - ptr + 1);
	ptr = next + 1;
	
	/* Convert type string */
	if (ft_strcmp(type_str, "argon2d") == 0)
		type = ARGON2_D;
	else if (ft_strcmp(type_str, "argon2i") == 0)
		type = ARGON2_I;
	else if (ft_strcmp(type_str, "argon2id") == 0)
		type = ARGON2_ID;
	else
		return (-1);
	
	/* Extract v= (version) */
	if (ft_strncmp(ptr, "v=", 2) != 0) return (-1);
	ptr += 2;
	if (parseUint(&ptr, &v) < 0) return (-1);
	if (*ptr != '$') return (-1);
	ptr++;
	
	/* Extract m= (memory) */
	if (ft_strncmp(ptr, "m=", 2) != 0) return (-1);
	ptr += 2;
	if (parseUint(&ptr, &m) < 0) return (-1);
	if (*ptr != ',') return (-1);
	ptr++;
	
	/* Extract t= (iterations) */
	if (ft_strncmp(ptr, "t=", 2) != 0) return (-1);
	ptr += 2;
	if (parseUint(&ptr, &t) < 0) return (-1);
	if (*ptr != ',') return (-1);
	ptr++;
	
	/* Extract p= (parallelism) */
	if (ft_strncmp(ptr, "p=", 2) != 0) return (-1);
	ptr += 2;
	if (parseUint(&ptr, &p) < 0) return (-1);
	if (*ptr != '$') return (-1);
	ptr++;
	
	/* Extract the salt */
	next = ft_strchr(ptr, '$');
	if (!next) return (-1);
	ft_strlcpy(salt_b64, ptr, next - ptr + 1);
	ptr = next + 1;
	
	/* Extract the hash (the rest) */
	ft_strlcpy(hash_b64, ptr, sizeof(hash_b64));
	
	/* Decode salt */
	salt_len = base64Decode(salt_b64, salt);
	if (salt_len < 0)
		return (-1);
	
	/* Decode hash */
	*hashLen = base64Decode(hash_b64, hash);
	if (*hashLen < 0)
		return (-1);
	
	/* Initialize context with parsed parameters */
	ft_bzero(ctx, sizeof(t_argon2Ctx));
	ctx->memory = m;
	ctx->iterations = t;
	ctx->parallelism = p;
	ctx->type = type;
	ctx->version = v;
	ctx->outputLen = 32;
	ctx->flags = ARGON2_FLAG_CLEAR_MEMORY;

	if (argon2SetSalt(ctx, salt, salt_len) != 0)
		return (-1);
	
	return (0);
}

int argon2Verify(const char *encoded, const uint8_t *password, size_t passLen)
{
	t_argon2Ctx	ctx;
	uint8_t		expected_hash[64];
	uint8_t		computed_hash[64];
	size_t		expected_len = sizeof(expected_hash);
	int			ret;
	
	if (!encoded || !password || passLen == 0)
		return (-1);
	
	if (argon2Decode(encoded, &ctx, expected_hash, &expected_len) != 0) {
		return (-1);
	}

	if (argon2SetPassword(&ctx, password, passLen) != 0) {
		argon2Free(&ctx);
		return (-1);
	}

	if (argon2Hash(&ctx, computed_hash, expected_len) != 0) {
		argon2Free(&ctx);
		return (-1);
	}

	ret = argon2SecureCompare(computed_hash, expected_len,
							  expected_hash, expected_len);
	
	argon2Free(&ctx);

	if (ret == 0)
		return (1);
	else if (ret == -1)
		return (0);
	else
		return (-1);
}
