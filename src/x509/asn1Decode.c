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
