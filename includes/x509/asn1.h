#ifndef HAJCRYPT_ASN1_H
#define HAJCRYPT_ASN1_H

#include <stdint.h>
#include <stddef.h>

/* Tags ASN.1 */
#define ASN1_INTEGER		0x02
#define ASN1_BIT_STRING		0x03
#define ASN1_OCTET_STRING	0x04
#define ASN1_NULL			0x05
#define ASN1_OID			0x06
#define ASN1_SEQUENCE		0x30
#define ASN1_SET			0x31

typedef struct {
	uint8_t	tag;
	uint8_t	*value;
	size_t	length;
} t_asn1_tlv;

/* ---------- Encode ---------- */

/**
 * @brief Encodes a length value in ASN.1 DER format.
 * 
 * Encodes the given length into ASN.1 Distinguished Encoding Rules (DER) format
 * and writes the encoded bytes to the provided buffer.
 * 
 * @param buf Pointer to the output buffer where the encoded length will be written.
 * @param len The length value to be encoded in ASN.1 DER format.
 * 
 * @return The number of bytes written to the buffer as a result of encoding.
 */
size_t	asn1EncodeLength(uint8_t *buf, size_t len);

/**
 * @brief Encodes an integer value into ASN.1 DER format.
 * 
 * Converts a raw integer value into its ASN.1 Distinguished Encoding Rules (DER)
 * representation, which includes the appropriate tag and length encoding.
 * 
 * @param value Pointer to the buffer containing the raw integer bytes.
 * @param valueLen Length of the input integer buffer in bytes.
 * @param outLen Pointer to a size_t variable where the length of the encoded
 *               output will be stored. Must not be NULL.
 * 
 * @return Pointer to a dynamically allocated buffer containing the ASN.1 DER
 *         encoded integer.
 *         Returns NULL if encoding fails.
 */
uint8_t	*asn1EncodeInteger(const uint8_t *value, size_t valueLen, size_t *outLen);

/**
 * @brief Encodes a sequence of ASN.1 elements into DER format.
 * 
 * @param elements Array of pointers to ASN.1 encoded elements to be sequenced.
 * @param elemLens Array of sizes for each element in bytes.
 * @param count Number of elements in the sequence.
 * @param outLen Pointer to store the size of the encoded sequence in bytes.
 * 
 * @return Pointer to dynamically allocated buffer containing the DER-encoded
 *         ASN.1 sequence, or NULL on failure. Caller is responsible for
 *         freeing the allocated memory.
 */
uint8_t	*asn1EncodeSequence(uint8_t	**elements,	size_t	*elemLens,
							size_t	count,		size_t	*outLen);


/**
 * @brief Encodes an OID (Object Identifier) to ASN.1 DER format
 * 
 * @param oid Pointer to the OID bytes to encode
 * @param oidLen Length of the OID data in bytes
 * @param outLen Pointer to store the length of the encoded output
 * 
 * @return Pointer to the encoded ASN.1 OID data, or NULL on failure
 */
uint8_t	*asn1EncodeOid(const uint8_t *oid, size_t oidLen, size_t *outLen);

/**
 * @brief Encodes data as an ASN.1 BIT STRING.
 *
 * Encodes the provided data buffer into ASN.1 BIT STRING format, which consists
 * of a tag, length, and the bit string value. The function allocates memory for
 * the encoded output.
 *
 * @param data Pointer to the input data to be encoded as a BIT STRING.
 * @param dataLen Length of the input data in bytes.
 * @param outLen Pointer to a size_t variable where the length of the encoded
 *               output will be stored. Must not be NULL.
 *
 * @return Pointer to a newly allocated buffer containing the ASN.1 BIT STRING
 *         encoding, or NULL if encoding fails.
 */
uint8_t	*asn1EncodeBitString(const uint8_t *data, size_t dataLen, size_t *outLen);

/* ---------- Decode ---------- */

/**
 * @brief Decodes an ASN.1 length field from DER format.
 *
 * This function reads the length field from the provided ASN.1 DER encoded data
 * and decodes it according to the ASN.1 length encoding rules. It supports both
 * short form (for lengths < 128) and long form (for lengths >= 128).
 *
 * @param data Pointer to the input buffer containing the ASN.1 DER encoded data.
 * @param len Pointer to a size_t variable where the decoded length will be stored.
 * @param bytesRead Pointer to a size_t variable where the number of bytes read
 *                  from the input buffer for the length field will be stored.
 *
 * @return 1 on successful decoding, or 0 if decoding fails (e.g., invalid format).
 */
int		asn1DecodeLength(const uint8_t *data, size_t *len, size_t *bytesRead);

/**
 * @brief Parses an ASN.1 TLV (Tag-Length-Value) structure from DER encoded data.
 *
 * This function reads an ASN.1 TLV structure from the provided input buffer,
 * extracting the tag, length, and value components. It validates the format and
 * ensures that the length specified in the TLV does not exceed the maximum
 * allowed length.
 *
 * @param data Pointer to the input buffer containing the ASN.1 DER encoded data.
 * @param maxLen Maximum length of the input buffer to prevent overflows.
 * @param tlv Pointer to a t_asn1_tlv structure where the parsed tag, length, and
 *            value will be stored.
 * @param consumed Pointer to a size_t variable where the total number of bytes
 *                 read from the input buffer for this TLV will be stored.
 *
 * @return 1 on successful parsing, or 0 if parsing fails (e.g., invalid format,
 *         insufficient data).
 */
int		asn1ParseTlv(const uint8_t *data, size_t maxLen, t_asn1_tlv *tlv, size_t *consumed);

/**
 * @brief Parses an ASN.1 INTEGER from DER encoded data.
 *
 * This function reads an ASN.1 INTEGER structure from the provided input buffer,
 * extracting the integer value while handling potential leading zero bytes that
 * may be present to ensure the correct sign representation.
 *
 * @param data Pointer to the input buffer containing the ASN.1 DER encoded data.
 * @param maxLen Maximum length of the input buffer to prevent overflows.
 * @param value Pointer to a uint8_t* variable where the pointer to the integer
 *              value will be stored. This will point to the raw bytes of the
 *              integer within the input buffer.
 * @param valueLen Pointer to a size_t variable where the length of the integer
 *                 value in bytes will be stored.
 * @param consumed Pointer to a size_t variable where the total number of bytes
 *                 read from the input buffer for this INTEGER will be stored.
 *
 * @return 1 on successful parsing, or 0 if parsing fails (e.g., invalid format,
 *         insufficient data).
 */
int		asn1ParseInteger(const uint8_t	*data,		size_t	maxLen,
						 uint8_t		**value,	size_t	*valueLen,
						 size_t			*consumed);
/**
 * @brief Parses an ASN.1 SEQUENCE from DER encoded data.
 *
 * This function reads an ASN.1 SEQUENCE structure from the provided input buffer,
 * extracting the content while validating the format.
 *
 * @param data Pointer to the input buffer containing the ASN.1 DER encoded data.
 * @param maxLen Maximum length of the input buffer to prevent overflows.
 * @param content Pointer to a uint8_t* variable where the pointer to the sequence
 *                content will be stored. This will point to the raw bytes of the
 *                sequence within the input buffer.
 * @param contentLen Pointer to a size_t variable where the length of the sequence
 *                   content in bytes will be stored.
 * @param consumed Pointer to a size_t variable where the total number of bytes
 *                 read from the input buffer for this SEQUENCE will be stored.
 *
 * @return 1 on successful parsing, or 0 if parsing fails (e.g., invalid format,
 *         insufficient data).
 */
int		asn1ParseSequence(const uint8_t	*data,		size_t	maxLen,
						  uint8_t		**content,	size_t	*contentLen,
						  size_t		*consumed);

#endif
