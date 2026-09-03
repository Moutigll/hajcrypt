#include "../../hajlib/include/hstring.h"
#include "../../hajlib/include/hmemory.h"

#include "../../includes/cipher/aes.h"
#include "../../includes/x509/asn1.h"
#include "../../includes/x509/pem.h"
#include "../../includes/utils/dispatch.h"

#include "../../includes/totp.h"

uint8_t *totpEntryEncode(const t_totpEntry *entry, size_t *outLen)
{
	if (!entry || !entry->label || !entry->secretLen || !entry->algo) return (NULL);

	size_t labelLen, issuerLen, secretLen, oidLen, digitLen, periodLen;

	uint8_t	*labelDer = asn1EncodeUTF8String(entry->label, &labelLen);
	uint8_t	*issuerDer = NULL;
	if (entry->issuer) issuerDer = asn1EncodeUTF8String(entry->issuer, &issuerLen);

	uint8_t	*secretDer = asn1EncodeOctetString(entry->secret, entry->secretLen, &secretLen);
	uint8_t	*oidDer = asn1EncodeOid(entry->algo->oid.data, entry->algo->oid.len, &oidLen);

	uint8_t		digitVal = entry->digits;
	uint8_t		*digitDer = asn1EncodeInteger(&digitVal, 1, &digitLen);
	uint32_t	periodBE = htobe32(entry->period); /* Big-endian for ASN.1 INTEGER */
	uint8_t		*periodDer = asn1EncodeInteger((uint8_t*)&periodBE, 4, &periodLen);

	uint8_t	*elems[6];
	size_t	lens[6];
	int		n = 0;
	elems[n] = labelDer; lens[n++] = labelLen;
	if (issuerDer) { elems[n] = issuerDer; lens[n++] = issuerLen; }
	elems[n] = secretDer; lens[n++] = secretLen;
	elems[n] = oidDer; lens[n++] = oidLen;
	elems[n] = digitDer; lens[n++] = digitLen;
	elems[n] = periodDer; lens[n++] = periodLen;

	uint8_t *seq = asn1EncodeSequence(elems, lens, n, outLen);
	free(labelDer); free(issuerDer); free(secretDer);
	free(oidDer); free(digitDer); free(periodDer);
	return (seq);
}

int totpEntryDecode(const uint8_t *der, size_t derLen, t_totpEntry *entry)
{
	uint8_t	*content;
	size_t	contentLen, consumed;
	if (!asn1ParseSequence(der, derLen, &content, &contentLen, &consumed))
		return (0);

	size_t pos = 0;
	/* Parse label (UTF8String) */
	if (!asn1ParseUTF8String(content + pos, contentLen - pos, &entry->label, &consumed))
		return (0);
	pos += consumed;
	/* Parse issuer (optional UTF8String) */
	entry->issuer = NULL;
	if (pos < contentLen) {
		/* Try to parse as UTF8String; if it fails, assume it's the secret */
		char *issuerTmp = NULL;
		if (asn1ParseUTF8String(content + pos, contentLen - pos, &issuerTmp, &consumed)) {
			entry->issuer = issuerTmp;
			pos += consumed;
		}
	}
	/* Parse secret (OCTET STRING) */
	uint8_t	*secret = NULL;
	size_t	secretLen = 0;
	if (pos >= contentLen || !asn1ParseOctetString(content + pos, contentLen - pos,
				&secret, &secretLen, &consumed))
		return (0);
	if (secretLen > sizeof(entry->secret)) {
		free(secret);
		return (0);
	}
	ft_memcpy(entry->secret, secret, secretLen);
	entry->secretLen = secretLen;
	free(secret);
	pos += consumed;

	/* Parse algorithm OID (OBJECT IDENTIFIER) */
	uint8_t	*oidVal;
	size_t	oidLen;
	if (pos >= contentLen || !asn1ParseOid(content + pos, contentLen - pos, &oidVal, &oidLen, &consumed))
		return (0);
	pos += consumed;
	entry->algo = getHashByOid(oidVal, oidLen);
	if (!entry->algo) return (0);

	/* Parse digits (INTEGER) */
	uint8_t	*digitVal;
	size_t	digitLen;
	if (pos >= contentLen || !asn1ParseInteger(content + pos, contentLen - pos, &digitVal, &digitLen, &consumed))
		return (0);
	pos += consumed;
	if (digitLen != 1 || digitVal[0] < 6 || digitVal[0] > 8) return (0);
	entry->digits = digitVal[0];

	/* Parse period (INTEGER) */
	uint8_t	*periodVal;
	size_t	periodLen;
	if (pos >= contentLen || !asn1ParseInteger(content + pos, contentLen - pos, &periodVal, &periodLen, &consumed))
		return (0);
	if (periodLen != 4) return (0);
	uint32_t periodBE;
	ft_memcpy(&periodBE, periodVal, 4);
	entry->period = be32toh(periodBE);
	if (entry->period == 0) return (0);
	return (1);
}

uint8_t *totpStoreEncode(const t_totpStore *store, size_t *outLen)
{
	if (!store || store->count == 0) return (NULL);
	uint8_t	**elems = malloc(store->count * sizeof(uint8_t*));
	size_t	*lens = malloc(store->count * sizeof(size_t));
	if (!elems || !lens) goto fail;

	for (size_t i = 0; i < store->count; i++) {
		elems[i] = totpEntryEncode(&store->entries[i], &lens[i]);
		if (!elems[i]) {
			for (size_t j = 0; j < i; j++) free(elems[j]);
			goto fail;
		}
	}
	uint8_t *seq = asn1EncodeSequence(elems, lens, store->count, outLen);
	for (size_t i = 0; i < store->count; i++) free(elems[i]);
	free(elems); free(lens);
	return (seq);
fail:
	free(elems); free(lens);
	return (NULL);
}

int totpStoreDecode(const uint8_t *der, size_t derLen, t_totpStore *store)
{
	uint8_t	*content, *ptr;
	size_t	contentLen, consumed;
	if (!asn1ParseSequence(der, derLen, &content, &contentLen, &consumed))
		return (0);

	/* Count the number of entries (SEQUENCE) */
	size_t count = 0;
	ptr = content;
	size_t rem = contentLen;
	while (rem > 0) {
		t_asn1Tlv tlv;
		if (!asn1ParseTlv(ptr, rem, &tlv, &consumed)) break;
		ptr += consumed;
		rem -= consumed;
		if (tlv.tag == ASN1_SEQUENCE) count++;
		else break;
	}
	if (count == 0) return (0);
	store->entries = calloc(count, sizeof(t_totpEntry));
	if (!store->entries) return (0);
	store->count = count;
	ptr = content;
	rem = contentLen;
	for (size_t i = 0; i < count; i++) {
		t_asn1Tlv tlv;
		if (!asn1ParseTlv(ptr, rem, &tlv, &consumed)) {
			totpStoreFree(store);
			return (0);
		}
		if (tlv.tag != ASN1_SEQUENCE) { totpStoreFree(store); return (0); }
		if (!totpEntryDecode(tlv.value, tlv.length, &store->entries[i])) {
			totpStoreFree(store);
			return (0);
		}
		ptr += consumed;
		rem -= consumed;
	}
	return (1);
}

void totpStoreFree(t_totpStore *store)
{
	if (!store) return;
	for (size_t i = 0; i < store->count; i++) {
		free(store->entries[i].label);
		free(store->entries[i].issuer);
	}
	free(store->entries);
	store->entries = NULL;
	store->count = 0;
}



char *totpStoreToPem(const t_totpStore *store, const char *password, const t_cipher *cipher)
{
	size_t	derLen;
	uint8_t	*der = totpStoreEncode(store, &derLen);
	if (!der) return (NULL);

	char *pem = NULL;
	if (password && *password) {
		const t_cipher *encCipher = cipher ? cipher : &g_aes256CbcCipher;
		pem = pkcs8EncryptPem(der, derLen, encCipher, password, NULL, "ENCRYPTED TOTP");
	} else
		pem = pemEncode(der, derLen, "TOTP");
	free(der);
	return (pem);
}

int totpStoreFromPem(const char *pem, const char *password, t_totpStore *store)
{
	if (!pem) return (0);
	uint8_t	*der = NULL;
	size_t	derLen = 0;

	if (ft_strstr(pem, "-----BEGIN ENCRYPTED TOTP-----")) {
		if (!password || !*password) return (0);
		der = pkcs8DecryptedDer(pem, password, &derLen, "ENCRYPTED TOTP");
		if (!der) return (0);
	} else {
		t_pemBlock block;
		if (!pemDecode(pem, &block)) return (0);
		if (ft_strcmp(block.header, "TOTP") != 0) {
			pemFreeBlock(&block);
			return (0);
		}
		der = block.der;
		derLen = block.derLen;
		block.der = NULL;
		pemFreeBlock(&block);
	}

	int ret = totpStoreDecode(der, derLen, store);
	free(der);
	return (ret);
}
