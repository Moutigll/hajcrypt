#include <stdlib.h>

#include "../../hajlib/include/hmemory.h"

#include "../../includes/x509/asn1.h"

int asn1DecodeLength(const uint8_t *data, size_t *len, size_t *bytesRead)
{
	if (data[0] < 0x80) {
		*len = data[0];
		*bytesRead = 1;
		return (1);
	}
	size_t numOctets = data[0] & 0x7F;
	if (numOctets == 0 || numOctets > 4) return (0);
	*len = 0;
	for (size_t i = 0; i < numOctets; i++)
		*len = (*len << 8) | data[1 + i];
	*bytesRead = 1 + numOctets;
	return (1);
}

int asn1ParseTlv(const uint8_t *data, size_t maxLen, t_asn1Tlv *tlv, size_t *consumed)
{
	size_t lenBytes;
	if (maxLen < 2) return (0);
	tlv->tag = data[0];
	if (!asn1DecodeLength(data + 1, &tlv->length, &lenBytes))
		return (0);
	size_t headerLen = 1 + lenBytes;
	if (headerLen + tlv->length > maxLen)
		return (0);
	tlv->value = (uint8_t *)(data + headerLen);
	if (consumed)
		*consumed = headerLen + tlv->length;
	return (1);
}

int asn1ParseInteger(const		uint8_t *data,	size_t	maxLen,
					 uint8_t	**value,		size_t	*valueLen,
					 size_t		*consumed)
{
	t_asn1Tlv tlv;

	if (!asn1ParseTlv(data, maxLen, &tlv, consumed))
		return (0);
	if (tlv.tag != ASN1_INTEGER)
		return (0);

	/* Remove leading zero if present and next byte has high bit set (to ensure positive integer) */
	if (tlv.length > 1 && tlv.value[0] == 0x00 && (tlv.value[1] & 0x80)) {
		*value = tlv.value + 1;
		*valueLen = tlv.length - 1;
	} else {
		*value = tlv.value;
		*valueLen = tlv.length;
	}
	return (1);
}

int asn1ParseSequence(const uint8_t	*data,		size_t	maxLen,
					  uint8_t		**content,	size_t	*contentLen,
					  size_t		*consumed)
{
	t_asn1Tlv tlv;

	if (!asn1ParseTlv(data, maxLen, &tlv, consumed))
		return (0);
	if (tlv.tag != ASN1_SEQUENCE)
		return (0);

	*content = tlv.value;
	*contentLen = tlv.length;
	return (1);
}

int asn1ParseOctetString(const uint8_t	*data,	size_t	maxLen,
						 uint8_t		**out,	size_t	*outLen,
						 size_t			*consumed)
{
	t_asn1Tlv tlv;

	if (!asn1ParseTlv(data, maxLen, &tlv, consumed))
		return (0);
	if (tlv.tag != ASN1_OCTET_STRING)
		return (0);
	*out = tlv.value;
	*outLen = tlv.length;
	return (1);
}

int asn1ParseAny(const uint8_t	*data,	size_t	maxLen,
				 uint8_t		**out,	size_t	*outLen,
				 size_t			*consumed)
{
	t_asn1Tlv tlv;

	if (!asn1ParseTlv(data, maxLen, &tlv, consumed))
		return (0);
	*out = tlv.value;
	*outLen = tlv.length;
	return (1);
}

int asn1ParseOid(const uint8_t	*data, size_t	maxLen,
				 uint8_t		**out, size_t	*outLen,
				 size_t			*consumed)
{
	t_asn1Tlv tlv;

	if (!asn1ParseTlv(data, maxLen, &tlv, consumed))
		return (0);
	if (tlv.tag != ASN1_OID)
		return (0);
	*out = tlv.value;
	*outLen = tlv.length;
	return (1);
}

int asn1ParseBitString(const uint8_t	*data,	size_t	maxLen,
					 uint8_t		**out,	size_t	*outLen,
					 size_t			*consumed)
{
	t_asn1Tlv tlv;

	if (!asn1ParseTlv(data, maxLen, &tlv, consumed))
		return (0);
	if (tlv.tag != ASN1_BIT_STRING)
		return (0);
	if (tlv.length < 1)
		return (0); /* At least one byte for unused bits count */
	uint8_t unusedBits = tlv.value[0];
	if (unusedBits > 7)
		return (0); /* Invalid number of unused bits */
	*out = tlv.value + 1;
	*outLen = tlv.length - 1;
	return (1);
}

int asn1ParseUTF8String(const uint8_t *data, size_t maxLen, char **out, size_t *consumed)
{
	t_asn1Tlv tlv;
	if (!asn1ParseTlv(data, maxLen, &tlv, consumed)) return (0);
	if (tlv.tag != ASN1_UTF8STRING) return (0);
	char *str = malloc(tlv.length + 1);
	if (!str) return (0);
	ft_memcpy(str, tlv.value, tlv.length);
	str[tlv.length] = '\0';
	*out = str;
	return (1);
}

/**
 * @brief Validates that the given data is a valid ASCII time string (UTCTime or GeneralizedTime)
 *
 * This function checks if the provided data conforms to the expected format of an ASN.1 time string,
 * which should consist of digits followed by a 'Z' character. It does not perform full validation of
 * the time format (e.g., checking for valid month/day values), but ensures that the basic structure is correct.
 *
 * @param data Pointer to the input data buffer containing the time string
 * @param len Length of the input data buffer in bytes
 * @return 1 if the data is a valid ASCII time string, 0 otherwise
 */
static int validateAsciiTime(const uint8_t *data, size_t len)
{
	if (len < 2 || data[len - 1] != 'Z')
		return (0);
	for (size_t i = 0; i < len - 1; i++)
		if (data[i] < '0' || data[i] > '9')
			return (0);
	return (1);
}

static inline int twoDigits(const uint8_t *p)
{
	return (p[0] - '0') * 10 + (p[1] - '0');
}

static time_t portableTimegm(struct tm *tm)
{
#ifdef _WIN32
	return (_mkgmtime(tm));
#elif defined(__linux__) || defined(__APPLE__)
	return (timegm(tm));
#else
	/* Fallback: set TZ to UTC, call mktime, restore TZ */
	char *tz = getenv("TZ");
	setenv("TZ", "UTC", 1);
	tzset();
	time_t t = mktime(tm);
	if (tz)
		setenv("TZ", tz, 1);
	else
		unsetenv("TZ");
	tzset();
	return (t);
#endif
}

int asn1DecodeUTCTime(const uint8_t *data, size_t maxLen, time_t *out, size_t *consumed)
{
	t_asn1Tlv	tlv;
	size_t		tlvConsumed;

	if (!asn1ParseTlv(data, maxLen, &tlv, &tlvConsumed))
		return (0);
	if (tlv.tag != 0x17)  /* ASN1_UTC_TIME */
		return (0);
	if (!validateAsciiTime(tlv.value, tlv.length))
		return (0);

	if (tlv.length != 13)
		return (0);

	int yy = twoDigits(tlv.value + 0);
	int mo = twoDigits(tlv.value + 2);
	int dd = twoDigits(tlv.value + 4);
	int hh = twoDigits(tlv.value + 6);
	int mi = twoDigits(tlv.value + 8);
	int ss = twoDigits(tlv.value + 10);

	struct tm tm;
	ft_memset(&tm, 0, sizeof(tm));
	tm.tm_sec	= ss;
	tm.tm_min	= mi;
	tm.tm_hour	= hh;
	tm.tm_mday	= dd;
	tm.tm_mon	= mo - 1;
	tm.tm_year	= (yy >= 50) ? yy : yy + 100;  /* 1950-2049 */
	tm.tm_isdst	= -1;

	*out = portableTimegm(&tm);
	*consumed = tlvConsumed;
	return (1);
}

int asn1DecodeGeneralizedTime(const uint8_t *data, size_t maxLen, time_t *out, size_t *consumed)
{
	t_asn1Tlv tlv;
	size_t tlvConsumed;

	if (!asn1ParseTlv(data, maxLen, &tlv, &tlvConsumed))
		return (0);
	if (tlv.tag != 0x18)  /* ASN1_GENERALIZED_TIME */
		return (0);

	if (tlv.length < 15)
		return (0);
	if (tlv.value[tlv.length - 1] != 'Z')
		return (0);

	for (size_t i = 0; i < tlv.length - 1; i++) {
		if (i < 14) {  /* YYYYMMDDHHMMSS */
			if (tlv.value[i] < '0' || tlv.value[i] > '9')
				return (0);
		} else if (tlv.value[i] == '.') {
			/* No need to handle fractional seconds */
		}
	}

	int yyyy	= twoDigits(tlv.value + 0) * 100 + twoDigits(tlv.value + 2);
	int mo		= twoDigits(tlv.value + 4);
	int dd		= twoDigits(tlv.value + 6);
	int hh		= twoDigits(tlv.value + 8);
	int mi		= twoDigits(tlv.value + 10);
	int ss		= twoDigits(tlv.value + 12);

	if (mo < 1 || mo > 12 || dd < 1 || dd > 31)
		return (0);
	if (hh > 23 || mi > 59 || ss > 60)  /* 60 for leap second */
		return (0);

	struct tm tm;
	ft_memset(&tm, 0, sizeof(tm));
	tm.tm_sec	= ss;
	tm.tm_min	= mi;
	tm.tm_hour	= hh;
	tm.tm_mday	= dd;
	tm.tm_mon	= mo - 1;
	tm.tm_year	= yyyy - 1900;
	tm.tm_isdst	= -1;

	*out = portableTimegm(&tm);
	*consumed = tlvConsumed;
	return (1);
}

int asn1DecodeTime(const uint8_t *data, size_t maxLen, time_t *out, size_t *consumed)
{
	if (maxLen < 2)
		return (0);
	if (data[0] == 0x17)
		return asn1DecodeUTCTime(data, maxLen, out, consumed);
	else if (data[0] == 0x18)
		return asn1DecodeGeneralizedTime(data, maxLen, out, consumed);
	return (0);
}
