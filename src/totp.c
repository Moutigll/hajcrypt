#include <time.h>

#include "../hajlib/include/hmemory.h"
#include "../hajlib/include/hstring.h"
#include "../hajlib/include/hprintf.h"

#include "../includes/cipher/base32.h"
#include "../includes/utils/random.h"

#include "../includes/totp.h"


/* Default configuration */
static const t_totpConfig TOTP_DEFAULT_CONFIG = {
	.algo = &g_sha1Hash,
	.digits = 6,
	.period = 30,
	.window = 1
};

/* Dynamic truncation as per RFC 4226 */
static uint32_t dynamaicTrunc(const uint8_t *hmac, size_t hmacLen)
{
	if (hmacLen < 20) return 0;
	
	uint8_t offset = hmac[hmacLen - 1] & 0x0F;
	
	uint32_t binary = ((uint32_t)(hmac[offset] & 0x7F) << 24) |
					  ((uint32_t)hmac[offset + 1] << 16) |
					  ((uint32_t)hmac[offset + 2] << 8) |
					  ((uint32_t)hmac[offset + 3]);
	
	return (binary);
}

/* Get time counter */
static uint64_t getTimeCtr(uint64_t timestamp, uint32_t period)
{
	if (timestamp == 0) {
		timestamp = (uint64_t)time(NULL);
	}
	return (timestamp / period);
}



int totpInit(t_totpCtx *ctx, const char *secretBase32, 
			 const t_hash *algo, uint8_t digits, uint32_t period)
			 {
	if (!ctx || !secretBase32 || !algo || digits < 4 || digits > 8 || period == 0) {
		return (-1);
	}
	
	/* Decode Base32 secret */
	ctx->secretLen = base32Decode(secretBase32, ctx->secret, sizeof(ctx->secret));
	if (ctx->secretLen == (size_t)-1 || ctx->secretLen == 0) {
		return (-1);
	}
	
	/* Set configuration */
	ctx->config.algo = algo;
	ctx->config.digits = digits;
	ctx->config.period = period;
	ctx->config.window = 1;
	
	return (0);
}

int totpInitWithConfig(t_totpCtx *ctx, const char *secretBase32, const t_totpConfig *config)
{
	if (!ctx || !secretBase32 || !config || !config->algo) {
		return (-1);
	}
	
	/* Decode Base32 secret */
	ctx->secretLen = base32Decode(secretBase32, ctx->secret, sizeof(ctx->secret));
	if (ctx->secretLen == (size_t)-1 || ctx->secretLen == 0) {
		return (-1);
	}
	
	/* Copy configuration */
	ft_memcpy(&ctx->config, config, sizeof(t_totpConfig));
	
	return (0);
}

int totpGenerate(t_totpCtx *ctx, uint64_t timestamp, char *code)
{
	uint64_t	counter;
	uint8_t		counterBuffer[8];
	uint8_t		hmac[64];
	t_hmacCtx	hmacCtx;
	uint32_t	binary;
	uint32_t	mod;
	size_t		hmacLen;
	
	if (!ctx || !code) {
		return (-1);
	}
	
	/* Get counter */
	counter = getTimeCtr(timestamp, ctx->config.period);
	
	/* Convert counter to 8-byte big-endian buffer */
	for (int i = 7; i >= 0; i--) {
		counterBuffer[i] = (uint8_t)(counter & 0xFF);
		counter >>= 8;
	}
	
	/* Compute HMAC */
	hmacLen = ctx->config.algo->digestSize;
	if (hmacLen > sizeof(hmac)) {
		hmacLen = sizeof(hmac);
	}
	
	/* Use algorithm's HMAC function if available */
	if (ctx->config.algo->hmacInit) {
		ctx->config.algo->hmacInit(&hmacCtx, ctx->secret, ctx->secretLen);
		ctx->config.algo->update(hmacCtx.innerCtx, counterBuffer, 8);
		ctx->config.algo->final(hmac, hmacCtx.innerCtx);
	} else {
		/* Fallback to generic HMAC */
		hmacInit(&hmacCtx, ctx->config.algo, ctx->secret, ctx->secretLen);
		hmacCtx.algo->update(hmacCtx.innerCtx, counterBuffer, 8);
		hmacFinal(&hmacCtx, hmac);
	}
	
	/* Dynamic truncation */
	binary = dynamaicTrunc(hmac, hmacLen);
	
	/* Reduce to required digits */
	mod = 1;
	for (uint8_t i = 0; i < ctx->config.digits; i++) {
		mod *= 10;
	}
	
	uint32_t otp = binary % mod;
	
	/* Format with leading zeros */
	ft_snprintf(code, ctx->config.digits + 1, "%0*u", ctx->config.digits, otp);
	
	return (0);
}

int totpVerify(t_totpCtx *ctx, const char *code, uint64_t timestamp)
{
	uint64_t	counter;
	char		generated[16];
	int64_t		startStep;
	int64_t		endStep;
	
	if (!ctx || !code) {
		return (-1);
	}
	
	counter = getTimeCtr(timestamp, ctx->config.period);
	
	/* Check current time step and surrounding steps */
	startStep = -(int64_t)ctx->config.window;
	endStep = (int64_t)ctx->config.window;
	
	for (int64_t step = startStep; step <= endStep; step++) {
		uint64_t stepTime = (counter + step) * ctx->config.period;
		
		if (totpGenerate(ctx, stepTime, generated) != 0) {
			continue;
		}
		
		/* Constant-time comparison to prevent timing attacks */
		if (ft_strlen(code) == ft_strlen(generated) &&
			ft_memcmp(code, generated, ft_strlen(code)) == 0) {
			return (1);
		}
	}
	
	return (-1);
}

int totpGenerateSecret(const t_hash *algo, char *output, size_t outputSize)
{
	uint8_t secret[64];
	size_t secretLen;
	size_t encodedLen;
	
	if (!algo || !output || outputSize == 0) {
		return (-1);
	}
	
	/* Determine secret length based on algorithm */
	if (algo == &g_sha256Hash) {
		secretLen = 32;
	} else if (algo == &g_sha512Hash || algo == &g_sha384Hash) {
		secretLen = 64;
	} else {
		secretLen = 20; /* SHA1 default */
	}
	
	if (hajSecRandBytes(secret, secretLen) != 0) {
		return (-1);
	}
	
	/* Encode to Base32 */
	encodedLen = base32Encode(secret, secretLen, output, outputSize);
	if (encodedLen == (size_t)-1 || encodedLen == 0) {
		return (-1);
	}
	
	return (0);
}

int totpCreateUri(const char			*userEmail,
				  const char			*secretBase32,
				  const char			*issuer,
				  const t_totpConfig	*config,
				  char					*output,	size_t	outputSize)
{
	const char *algoName;
	int result;
	
	if (!userEmail || !secretBase32 || !config || !output || outputSize == 0)
		return (-1);
	
	/* Determine algorithm name */
	if (config->algo == &g_sha256Hash) {
		algoName = "SHA256";
	} else if (config->algo == &g_sha512Hash) {
		algoName = "SHA512";
	} else {
		algoName = "SHA1";
	}
	
	/* Create URI */
	result = ft_snprintf(output, outputSize,
					  "otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=%s&digits=%d&period=%u",
					  issuer, userEmail, secretBase32,
					  issuer, algoName,
					  config->digits, config->period);
	
	if (result < 0 || (size_t)result >= outputSize)
		return (-1);
	
	return (0);
}
