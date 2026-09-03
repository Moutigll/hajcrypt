#include <time.h>

#include "../../hajlib/include/hmath.h"
#include "../../hajlib/include/hmemory.h"
#include "../../hajlib/include/hstring.h"
#include "../../hajlib/include/hprintf.h"

#include "../../includes/cipher/base32.h"
#include "../../includes/utils/random.h"

#include "../../includes/totp.h"


/* Default configuration */
static const t_totpEntry TOTP_DEFAULT_CONFIG = {
	.label = NULL,
	.issuer = NULL,
	.secret = {0},
	.secretLen = 0,
	.algo = &g_sha1Hash,
	.digits = 6,
	.period = 30,
	.window = 1
};

/* Dynamic truncation as per RFC 4226 */
static uint32_t dynamicTrunc(const uint8_t *hmac, size_t hmacLen)
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



int totpInit(t_totpEntry	*ctx,	const char	*secretBase32,
			 const t_hash	*algo,	uint8_t		digits,
			 uint32_t		period) {
	if (!ctx || !secretBase32)
		return (-1);
	ft_bzero(ctx, sizeof(t_totpEntry));

	if (!algo)
		algo = TOTP_DEFAULT_CONFIG.algo;

	if (digits < 6 || digits > 8)
		digits = TOTP_DEFAULT_CONFIG.digits;

	if (period == 0)
		period = TOTP_DEFAULT_CONFIG.period;

	/* Decode Base32 secret */
	ctx->secretLen = base32Decode(secretBase32, ctx->secret, sizeof(ctx->secret));
	if (ctx->secretLen == (size_t)-1 || ctx->secretLen == 0)
		return (-1);

	/* Set configuration */
	ctx->algo = algo;
	ctx->digits = digits;
	ctx->period = period;
	ctx->window = 1;

	return (0);
}

int totpInitWithConfig(t_totpEntry *ctx, const char *secretBase32, const t_totpEntry *config)
{
	if (!ctx || !secretBase32 || !config || !config->algo)
		return (-1);

	ft_bzero(ctx, sizeof(t_totpEntry));

	/* Decode Base32 secret */
	ctx->secretLen = base32Decode(secretBase32, ctx->secret, sizeof(ctx->secret));
	if (ctx->secretLen == (size_t)-1 || ctx->secretLen == 0)
		return (-1);

	/* Copy configuration */
	ctx->algo = config->algo;
	ctx->digits = config->digits;
	ctx->period = config->period;
	ctx->window = config->window;

	return (0);
}

int totpGenerate(t_totpEntry *ctx, uint64_t timestamp, char *code)
{
	uint64_t	counter;
	uint8_t		counterBuffer[8];
	uint8_t		hmacBuff[64];
	uint32_t	binary;
	uint32_t	mod;
	size_t		hmacLen;

	if (!ctx || !code || !ctx->algo || ctx->secretLen == 0)
		return (-1);

	/* Get counter */
	counter = getTimeCtr(timestamp, ctx->period ? ctx->period : TOTP_DEFAULT_CONFIG.period);

	/* Convert counter to 8-byte big-endian buffer */
	for (int i = 7; i >= 0; i--) {
		counterBuffer[i] = (uint8_t)(counter & 0xFF);
		counter >>= 8;
	}

	hmacLen = ctx->algo->digestSize;
	if (hmacLen > sizeof(hmacBuff)) {
		hmacLen = sizeof(hmacBuff);
	}
	hmac(ctx->algo, ctx->secret, ctx->secretLen, counterBuffer, sizeof(counterBuffer), hmacBuff);

	/* Dynamic truncation */
	binary = dynamicTrunc(hmacBuff, hmacLen);

	/* Reduce to required digits */
	mod = 1;
	for (uint8_t i = 0; i < ctx->digits; i++) {
		mod *= 10;
	}

	uint32_t otp = binary % mod;

	/* Format with leading zeros */
	for (uint8_t i = 0; i < ctx->digits; i++) {
		code[ctx->digits - 1 - i] = '0' + (otp % 10);
		otp /= 10;
	}
	code[ctx->digits] = '\0';
	return (0);
}

int totpVerify(t_totpEntry *ctx, const char *code, uint64_t timestamp)
{
	uint64_t	counter;
	char		generated[16];
	int64_t		startStep;
	int64_t		endStep;

	if (!ctx || !code) {
		return (-1);
	}

	counter = getTimeCtr(timestamp, ctx->period);

	/* Check current time step and surrounding steps */
	startStep = -(int64_t)ctx->window;
	endStep = (int64_t)ctx->window;

	for (int64_t step = startStep; step <= endStep; step++) {
		uint64_t stepTime = (counter + step) * ctx->period;

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
	if (algo == &g_sha256Hash)
		secretLen = 32;
	else if (algo == &g_sha512Hash || algo == &g_sha384Hash)
		secretLen = 64;
	else
		secretLen = 20; /* SHA1 default */

	if (hajSecRandBytes(secret, secretLen) != 0)
		return (-1);

	/* Encode to Base32 */
	encodedLen = base32Encode(secret, secretLen, output, outputSize);
	if (encodedLen == (size_t)-1 || encodedLen == 0) {
		HAJCRYPT_DPRINT("totp: failed to encode secret to Base32\n");
		return (-1);
	}

	return (0);
}

int totpCreateUri(const char			*userEmail,
				  const char			*secretBase32,
				  const char			*issuer,
				  const t_totpEntry	*config,
				  char					*output,	size_t	outputSize)
{
	const char *algoName;
	int result;

	if (!userEmail || !secretBase32 || !config || !output || outputSize == 0)
		return (-1);

	/* Determine algorithm name */
	if (config->algo == &g_sha256Hash)
		algoName = "SHA256";
	else if (config->algo == &g_sha512Hash)
		algoName = "SHA512";
	else
		algoName = "SHA1";

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

static int parseUriParam(const char *query, const char *key, char *out, size_t outSize)
{
	const char *p = ft_strstr(query, key);
	if (!p) return (-1);
	p += ft_strlen(key);
	if (*p != '=') return (-1);
	p++;
	const char *end = ft_strchr(p, '&');
	if (!end) end = p + ft_strlen(p);
	size_t len = (size_t)(end - p);
	if (len >= outSize) len = outSize - 1;
	ft_strlcpy(out, p, len + 1);
	return (0);
}

int totpInitFromUri(t_totpEntry *ctx, const char *uri)
{
	t_totpEntry	config = TOTP_DEFAULT_CONFIG;
	char		secretBuf[128];
	char		algoBuf[16];
	char		digitsBuf[8];
	char		periodBuf[16];
	char		labelBuf[256];
	char		issuerBuf[128];
	const char	*query, *label, *q;

	if (!ctx || !uri)
		return (-1);

	if (ft_strncmp(uri, "otpauth://totp/", 15) != 0)
		return (-1);

	query = ft_strchr(uri, '?');
	if (!query) return (-1);

	label = uri + 15;
	q = ft_strchr(label, '?');
	if (!q) return (-1);
	if ((size_t)(q - label) >= sizeof(labelBuf))
		return (-1);
	ft_strlcpy(labelBuf, label, (size_t)(q - label) + 1);

	char *colon = ft_strchr(labelBuf, ':');
	issuerBuf[0] = '\0';
	if (colon) {
		*colon = '\0';
		ft_strlcpy(issuerBuf, labelBuf, sizeof(issuerBuf));
		ft_strlcpy(labelBuf, colon + 1, sizeof(labelBuf));
	}

	secretBuf[0] = algoBuf[0] = digitsBuf[0] = periodBuf[0] = '\0';
	parseUriParam(query, "secret", secretBuf, sizeof(secretBuf));
	parseUriParam(query, "algorithm", algoBuf, sizeof(algoBuf));
	parseUriParam(query, "digits", digitsBuf, sizeof(digitsBuf));
	parseUriParam(query, "period", periodBuf, sizeof(periodBuf));
	parseUriParam(query, "issuer", issuerBuf, sizeof(issuerBuf));  // L'issuer peut aussi être dans les params

	if (!secretBuf[0]) return (-1);

	if (algoBuf[0]) {
		if (ft_strcmp(algoBuf, "SHA256") == 0)
			config.algo = &g_sha256Hash;
		else if (ft_strcmp(algoBuf, "SHA512") == 0)
			config.algo = &g_sha512Hash;
		else
			config.algo = &g_sha1Hash;
	}
	if (digitsBuf[0]) {
		int d = ft_atoi(digitsBuf);
		if (d == 6 || d == 8)
			config.digits = (uint8_t)d;
	}
	if (periodBuf[0]) {
		int p = ft_atoi(periodBuf);
		if (p > 0)
			config.period = (uint32_t)p;
	}

	ctx->secretLen = base32Decode(secretBuf, ctx->secret, sizeof(ctx->secret));
	if (ctx->secretLen == (size_t)-1 || ctx->secretLen == 0)
		return (-1);

	ctx->algo = config.algo;
	ctx->digits = config.digits;
	ctx->period = config.period;
	ctx->window = config.window;

	ctx->label = ft_strdup(labelBuf[0] ? labelBuf : TOTP_DEFAULT_CONFIG.label ? TOTP_DEFAULT_CONFIG.label : "user");
	if (!ctx->label)
		return (-1);
	ctx->issuer = ft_strdup(issuerBuf[0] ? issuerBuf : TOTP_DEFAULT_CONFIG.issuer ? TOTP_DEFAULT_CONFIG.issuer : "hajcrypt");
	if (!ctx->issuer) {
		free(ctx->label);
		ctx->label = NULL;
		return (-1);
	}

	return (0);
}

int totpGenerateFromUri(const char *uri, uint64_t timestamp, char *code)
{
	t_totpEntry ctx;
	if (totpInitFromUri(&ctx, uri) != 0)
		return (-1);
	return (totpGenerate(&ctx, timestamp, code));
}

int totpVerifyFromUri(const char *uri, const char *code, uint64_t timestamp)
{
	t_totpEntry ctx;
	if (totpInitFromUri(&ctx, uri) != 0)
		return (-1);
	return (totpVerify(&ctx, code, timestamp));
}
