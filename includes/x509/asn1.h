#ifndef HAJCRYPT_ASN1_H
#define HAJCRYPT_ASN1_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>

/* Tags ASN.1 */
#define ASN1_INTEGER		0x02
#define ASN1_BIT_STRING		0x03
#define ASN1_OCTET_STRING	0x04
#define ASN1_NULL			0x05
#define ASN1_OID			0x06
#define ASN1_SEQUENCE		0x30
#define ASN1_SET			0x31
#define ASN1_UTF8STRING     0x0C

typedef struct s_asn1Tlv {
	uint8_t	tag;
	uint8_t	*value;
	size_t	length;
} t_asn1Tlv;

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

/**
 * @brief Encodes data as an ASN.1 OCTET STRING.
 *
 * Encodes the provided data buffer into ASN.1 OCTET STRING format, which consists
 * of a tag, length, and the octet string value. The function allocates memory for
 * the encoded output.
 *
 * @param data Pointer to the input data to be encoded as an OCTET STRING.
 * @param dataLen Length of the input data in bytes.
 * @param outLen Pointer to a size_t variable where the length of the encoded
 *               output will be stored. Must not be NULL.
 *
 * @return Pointer to a newly allocated buffer containing the ASN.1 OCTET STRING
 *         encoding, or NULL if encoding fails.
 */
uint8_t	*asn1EncodeOctetString(const uint8_t *data, size_t dataLen, size_t *outLen);

/**
 * @brief Encodes a NULL value in ASN.1 DER format.
 *
 * This function generates the ASN.1 DER encoding for a NULL value, which consists
 * of a tag (0x05) and a length of 0. The resulting byte array is allocated
 * dynamically and should be freed by the caller.
 *
 * @param outLen Pointer to a size_t variable where the length of the encoded
 *               output will be stored. Must not be NULL.
 *
 * @return Pointer to a newly allocated buffer containing the ASN.1 DER encoding
 *         of a NULL value, or NULL if encoding fails (e.g., memory allocation failure).
 */
uint8_t	*asn1EncodeNull(size_t *outLen);

/**
 * @brief Encodes a UTF-8 string in ASN.1 DER format.
 *
 * This function encodes the provided UTF-8 string into ASN.1 DER format, which consists
 * of a tag (0x0C), length, and the string value. The resulting byte array is allocated
 * dynamically and should be freed by the caller.
 *
 * @param str Pointer to the input UTF-8 string to be encoded.
 * @param outLen Pointer to a size_t variable where the length of the encoded
 *               output will be stored. Must not be NULL.
 *
 * @return Pointer to a newly allocated buffer containing the ASN.1 DER encoding
 *         of the UTF-8 string, or NULL if encoding fails (e.g., memory allocation failure).
 */
uint8_t	*asn1EncodeUTF8String(const char *str, size_t *outLen);

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
 * @param tlv Pointer to a t_asn1Tlv structure where the parsed tag, length, and
 *            value will be stored.
 * @param consumed Pointer to a size_t variable where the total number of bytes
 *                 read from the input buffer for this TLV will be stored.
 *
 * @return 1 on successful parsing, or 0 if parsing fails (e.g., invalid format,
 *         insufficient data).
 */
int		asn1ParseTlv(const uint8_t *data, size_t maxLen, t_asn1Tlv *tlv, size_t *consumed);

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

/**
 * @brief Parses an ASN.1 OCTET STRING from DER encoded data.
 *
 * This function reads an ASN.1 OCTET STRING structure from the provided input buffer,
 * extracting the octet string value while validating the format.
 *
 * @param data Pointer to the input buffer containing the ASN.1 DER encoded data.
 * @param maxLen Maximum length of the input buffer to prevent overflows.
 * @param value Pointer to a uint8_t* variable where the pointer to the octet string
 *              value will be stored. This will point to the raw bytes of the
 *              octet string within the input buffer.
 * @param valueLen Pointer to a size_t variable where the length of the octet string
 *                 value in bytes will be stored.
 * @param consumed Pointer to a size_t variable where the total number of bytes
 *                 read from the input buffer for this OCTET STRING will be stored.
 *
 * @return 1 on successful parsing, or 0 if parsing fails (e.g., invalid format,
 *         insufficient data).
 */
int asn1ParseOctetString(const uint8_t	*data,	size_t	maxLen,
						 uint8_t		**out,	size_t	*outLen,
						 size_t			*consumed);

/**
 * @brief Parses any ASN.1 element from DER encoded data.
 *
 * This function reads an ASN.1 element of any type from the provided input buffer,
 * extracting the value while validating the format. It does not enforce any specific
 * tag type, allowing it to be used for generic parsing of ASN.1 structures.
 *
 * @param data Pointer to the input buffer containing the ASN.1 DER encoded data.
 * @param maxLen Maximum length of the input buffer to prevent overflows.
 * @param value Pointer to a uint8_t* variable where the pointer to the element
 *              value will be stored. This will point to the raw bytes of the
 *              element within the input buffer.
 * @param valueLen Pointer to a size_t variable where the length of the element
 *                 value in bytes will be stored.
 * @param consumed Pointer to a size_t variable where the total number of bytes
 *                 read from the input buffer for this element will be stored.
 *
 * @return 1 on successful parsing, or 0 if parsing fails (e.g., invalid format,
 *         insufficient data).
 */
int asn1ParseAny(const uint8_t	*data,	size_t	maxLen,
				 uint8_t		**out,	size_t	*outLen,
				 size_t			*consumed);

/**
 * @brief Parses an ASN.1 OBJECT IDENTIFIER from DER encoded data.
 *
 * This function reads an ASN.1 OBJECT IDENTIFIER structure from the provided input buffer,
 * extracting the OID value while validating the format.
 *
 * @param data Pointer to the input buffer containing the ASN.1 DER encoded data.
 * @param maxLen Maximum length of the input buffer to prevent overflows.
 * @param value Pointer to a uint8_t* variable where the pointer to the OID
 *              value will be stored. This will point to the raw bytes of the
 *              OID within the input buffer.
 * @param valueLen Pointer to a size_t variable where the length of the OID
 *                 value in bytes will be stored.
 * @param consumed Pointer to a size_t variable where the total number of bytes
 *                 read from the input buffer for this OID will be stored.
 *
 * @return 1 on successful parsing, or 0 if parsing fails (e.g., invalid format,
 *         insufficient data).
 */
int asn1ParseOid(const uint8_t	*data, size_t	maxLen,
				 uint8_t		**out, size_t	*outLen,
				 size_t			*consumed);

/**
 * @brief Parses an ASN.1 BIT STRING from a buffer.
 *
 * @param data      Pointer to the input buffer containing the BIT STRING.
 * @param maxLen    Maximum number of bytes available in @p data.
 * @param out       Receives a pointer to the parsed bit string content.
 * @param outLen    Receives the length (in bytes) of the parsed content.
 * @param consumed  Receives the number of bytes consumed from @p data.
 *
 * @return Integer status code indicating success or failure.
 */
int asn1ParseBitString(const uint8_t	*data,	size_t	maxLen,
					 uint8_t			**out,	size_t	*outLen,
					 size_t				*consumed);

/**
 * @brief Parses an ASN.1 UTF8String from a buffer.
 *
 * @param data      Pointer to the input buffer containing the UTF8String.
 * @param maxLen    Maximum number of bytes available in @p data.
 * @param out       Receives a pointer to the parsed UTF8String content.
 * @param outLen    Receives the length (in bytes) of the parsed content.
 * @param consumed  Receives the number of bytes consumed from @p data.
 *
 * @return Integer status code indicating success or failure.
 *
 * @note The caller is responsible for freeing the memory allocated for @p out.
 */
int asn1ParseUTF8String(const uint8_t *data, size_t maxLen, char **out, size_t *consumed);

/**
 * @brief Parses an ASN.1 UTCTime or GeneralizedTime value from a buffer.
 *
 * This function attempts to parse an ASN.1 time value, which can be encoded as either
 * UTCTime (tag 0x17) or GeneralizedTime (tag 0x18). It extracts the time value and converts it to a time_t representation.
 *
 * @param data      Pointer to the input buffer containing the ASN.1 DER encoded time value.
 * @param maxLen    Maximum number of bytes available in @p data.
 * @param out       Receives the parsed time value as a time_t.
 * @param consumed  Receives the number of bytes consumed from @p data during parsing.
 * @return Integer status code indicating success (1) or failure (0) of the parsing operation.
 */
int asn1DecodeUTCTime(const uint8_t *data, size_t maxLen, time_t *out, size_t *consumed);

/**
 * @brief Parses an ASN.1 GeneralizedTime value from a buffer.
 *
 * This function reads an ASN.1 GeneralizedTime structure from the provided input buffer,
 * extracting the time value while validating the format. The GeneralizedTime is expected
 * to be in the format "YYYYMMDDHHMMSSZ" (UTC time).
 *
 * @param data Pointer to the input buffer containing the ASN.1 DER encoded GeneralizedTime value.
 * @param maxLen    Maximum number of bytes available in @p data.
 * @param out       Receives the parsed time value as a time_t.
 * @param consumed  Receives the number of bytes consumed from @p data during parsing.
 *
 * @return 1 on successful parsing, or 0 if parsing fails (e.g., invalid format,
 *         insufficient data).
 */
int asn1DecodeGeneralizedTime(const uint8_t *data, size_t maxLen, time_t *out, size_t *consumed);

/**
 * @brief Parses an ASN.1 time value (UTCTime or GeneralizedTime) from a buffer.
 *
 * This function attempts to parse an ASN.1 time value, which can be encoded as either
 * UTCTime (tag 0x17) or GeneralizedTime (tag 0x18). It extracts the time value and converts it to a time_t representation.
 *
 * @param data      Pointer to the input buffer containing the ASN.1 DER encoded time value.
 * @param maxLen    Maximum number of bytes available in @p data.
 * @param out       Receives the parsed time value as a time_t.
 * @param consumed  Receives the number of bytes consumed from @p data during parsing.
 * @return Integer status code indicating success (1) or failure (0) of the parsing operation.
 */
int asn1DecodeTime(const uint8_t *data, size_t maxLen, time_t *out, size_t *consumed);

#endif
