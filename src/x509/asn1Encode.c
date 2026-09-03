#include "../../hajlib/include/hmemory.h"
#include "../../hajlib/include/hstring.h"

#include "../../includes/x509/asn1.h"

size_t asn1EncodeLength(uint8_t *buf, size_t len)
{
	if (len < 128) {
		if (buf) buf[0] = (uint8_t)len;
		return (1);
	} else if (len < 256) {
		if (buf) {
			buf[0] = 0x81;
			buf[1] = (uint8_t)len;
		}
		return (2);
	} else {
		if (buf) {
			buf[0] = 0x82;
			buf[1] = (uint8_t)((len >> 8) & 0xFF);
			buf[2] = (uint8_t)(len & 0xFF);
		}
		return (3);
	}
}

uint8_t *asn1EncodeInteger(const uint8_t *value, size_t valueLen, size_t *outLen)
{
	size_t	headerLen;
	size_t	extra;
	uint8_t	*der;

	/* if the most significant bit of the first byte is set, we need to prepend a 0x00 byte
	   to indicate that the integer is positive (ASN.1 INTEGER is signed) */
	if (valueLen > 0 && (value[0] & 0x80))
		extra = 1;
	else
		extra = 0;

	headerLen = 1 + asn1EncodeLength(NULL, valueLen + extra);
	*outLen = headerLen + valueLen + extra;
	der = malloc(*outLen);
	if (!der) return (NULL);

	der[0] = ASN1_INTEGER;
	asn1EncodeLength(der + 1, valueLen + extra);
	if (extra)
		der[headerLen] = 0x00;
	ft_memcpy(der + headerLen + extra, value, valueLen);
	return (der);
}

uint8_t *asn1EncodeSequence(uint8_t **elements, size_t *elemLens,
							size_t count, size_t *outLen)
{
	size_t totalPayload = 0;

	for (size_t i = 0; i < count; i++)
		totalPayload += elemLens[i];

	size_t headerLen = 1 + asn1EncodeLength(NULL, totalPayload);
	*outLen = headerLen + totalPayload;
	uint8_t *seq = malloc(*outLen);
	if (!seq) return (NULL);

	seq[0] = ASN1_SEQUENCE;
	asn1EncodeLength(seq + 1, totalPayload);

	uint8_t *ptr = seq + headerLen;
	for (size_t i = 0; i < count; i++) {
		ft_memcpy(ptr, elements[i], elemLens[i]);
		ptr += elemLens[i];
	}
	return (seq);
}

uint8_t *asn1EncodeOid(const uint8_t *oid, size_t oidLen, size_t *outLen)
{
	size_t headerLen = 1 + asn1EncodeLength(NULL, oidLen);
	*outLen = headerLen + oidLen;
	uint8_t *der = malloc(*outLen);
	if (!der) return (NULL);

	der[0] = ASN1_OID;
	asn1EncodeLength(der + 1, oidLen);
	ft_memcpy(der + headerLen, oid, oidLen);
	return (der);
}

uint8_t *asn1EncodeBitString(const uint8_t *data, size_t dataLen, size_t *outLen)
{
	/* The BIT STRING encoding consists of:
   - Tag (0x03)
   - Length (1 byte for the number of unused bits + data length)
   - Unused bits count (1 byte, set to 0 since we assume all bits are used)
   - Data bytes */
	size_t headerLen = 1 + asn1EncodeLength(NULL, 1 + dataLen);
	*outLen = headerLen + 1 + dataLen;
	uint8_t *bs = malloc(*outLen);
	if (!bs) return (NULL);

	bs[0] = ASN1_BIT_STRING;
	asn1EncodeLength(bs + 1, 1 + dataLen);
	bs[headerLen] = 0x00;
	ft_memcpy(bs + headerLen + 1, data, dataLen);
	return (bs);
}

uint8_t *asn1EncodeOctetString(const uint8_t *data, size_t dataLen, size_t *outLen)
{
	size_t headerLen = 1 + asn1EncodeLength(NULL, dataLen);
	*outLen = headerLen + dataLen;
	uint8_t *os = malloc(*outLen);
	if (!os) return (NULL);

	os[0] = ASN1_OCTET_STRING;
	asn1EncodeLength(os + 1, dataLen);
	ft_memcpy(os + headerLen, data, dataLen);
	return (os);
}

uint8_t *asn1EncodeNull(size_t *outLen)
{
	*outLen = 2;
	uint8_t *der = malloc(*outLen);
	if (!der) return (NULL);

	der[0] = ASN1_NULL;
	der[1] = 0x00;
	return (der);
}

uint8_t	*asn1EncodeUTF8String(const char *str, size_t *outLen)
{
	if (!str) { *outLen = 0; return (NULL); }
	size_t	len = ft_strlen(str);
	uint8_t	*buf = malloc(1 + 4 + len); /* max length encoding 4 bytes */
	if (!buf) return (NULL);
	size_t	pos = 0;
	buf[pos++] = ASN1_UTF8STRING;
	if (len < 128)
		buf[pos++] = (uint8_t)len;
	else { /* long form (simple) */
		size_t	lenBytes = 1;
		size_t	tmp = len;
		while (tmp > 255) { tmp >>= 8; lenBytes++; }
		buf[pos++] = 0x80 | lenBytes;
		for (size_t i = lenBytes; i > 0; i--) {
			buf[pos + i - 1] = (len >> (8 * (i - 1))) & 0xFF;
		}
		pos += lenBytes;
	}
	ft_memcpy(buf + pos, str, len);
	pos += len;
	*outLen = pos;
	return (buf);
}
