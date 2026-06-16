#include <stdlib.h>
#include "../../hajlib/include/hmemory.h"
#include "../../includes/kdf/hkdf.h"
#include "../../includes/utils/utils.h"
#include "../../hajlib/include/hprintf.h"

#include "../includes/hkdf.h"
#include "../includes/keySchedule.h"
#include "../includes/constants.h"

int	tls13DeriveSecret(const uint8_t	*secret,	size_t	secretLen,
					  const char	*label,
					  const uint8_t	*context,	size_t	contextLen,
					  uint8_t		*output,	size_t	outputLen,
					  const t_hash	*hash)
{
	if (!secret || !label || !output || !hash)
		return 0;

	/* If context is NULL or has zero length, use the hash of an empty string as context */
	if (!context || contextLen == 0) {
		uint8_t empty_hash[64];
		uint8_t hash_state[hash->ctxSize];
		hash->init(hash_state);
		hash->final(empty_hash, hash_state);
	
		return (tlsHkdfExpandLabel(secret,	secretLen,
								  label,	empty_hash, hash->digestSize,
								  output,	outputLen, hash));
	}
	
	return (tlsHkdfExpandLabel(secret,	secretLen,
							  label,	context,	contextLen,
							  output,	outputLen,	hash));
}

void	tls13KeyScheduleInit(t_tls13Secrets *secrets, const t_hash *hash)
{
	if (!secrets || !hash)
		return ;

	ft_bzero(secrets, sizeof(t_tls13Secrets));
	secrets->hash = hash;
	secrets->pskEnabled = 0;
}

int	tls13KeyScheduleExtractHandshake(t_tls13Secrets	*secrets,
									 const uint8_t	*psk,			size_t pskLen,
									 const uint8_t	*sharedSecret,	size_t sharedLen)
{
	uint8_t	derived[64];
	uint8_t	zeroSalt[64];
	uint8_t	zeroPsk[64];
	size_t	digestSize;

	if (!secrets || !sharedSecret) {
		BTLS_DEBUG("tls13KeyScheduleExtractHandshake: secrets or sharedSecret NULL");
		return (0);
	}

	if (!secrets->hash) {
		BTLS_DEBUG("tls13KeyScheduleExtractHandshake: secrets->hash is NULL");
		return (0);
	}

	digestSize = secrets->hash->digestSize;
	if (digestSize == 0 || digestSize > 64) {
		BTLS_DEBUG("tls13KeyScheduleExtractHandshake: invalid digestSize %zu", digestSize);
		return (0);
	}

	ft_bzero(zeroSalt, digestSize);
	ft_bzero(zeroPsk, digestSize);

	/* Step 1: early_secret = HKDF-Extract(0, 0) or HKDF-Extract(0, psk) */
	const uint8_t *ikm = zeroPsk;
	size_t ikmLen = digestSize;
	if (psk && pskLen > 0) {
		ikm = psk;
		ikmLen = pskLen;
	}

	if (!hkdfExtract(zeroSalt, digestSize, ikm, ikmLen,
					 secrets->earlySecret, digestSize, secrets->hash)) {
		BTLS_DEBUG("hkdfExtract for early_secret failed");
		return (0);
	}

	/* Step 2: derived = Derive-Secret(early_secret, "derived", "") */
	if (!tls13DeriveSecret(secrets->earlySecret, digestSize,
						   TLS13_LABEL_DERIVED, NULL, 0,
						   derived, digestSize, secrets->hash)) {
		BTLS_DEBUG("tls13DeriveSecret for derived failed");
		return (0);
	}

	/* Step 3: handshake_secret = HKDF-Extract(derived, shared_secret) */
	if (!hkdfExtract(derived, digestSize,
					 sharedSecret, sharedLen,
					 secrets->handshakeSecret, digestSize, secrets->hash)) {
		BTLS_DEBUG("hkdfExtract for handshake_secret failed");
		return (0);
	}

	/* If a PSK is provided, derive the external binder key for early data */
	if (psk && pskLen > 0) {
		if (!tls13DeriveSecret(secrets->earlySecret, digestSize,
							   TLS13_LABEL_EXTRACTOR, NULL, 0,
							   secrets->externalBinderKey, digestSize,
							   secrets->hash)) {
			BTLS_DEBUG("tls13DeriveSecret for external_binder_key failed");
			return (0);
		}
		secrets->pskEnabled = 1;
	} else
		secrets->pskEnabled = 0;

	secureZeroMemory(derived, sizeof(derived));
	secureZeroMemory(zeroSalt, sizeof(zeroSalt));
	secureZeroMemory(zeroPsk, sizeof(zeroPsk));
	return (1);
}

int	tls13KeyScheduleDeriveHandshakeSecrets(t_tls13Secrets	*secrets,
										   const uint8_t	*handshakeHash,
										   size_t			hashLen)
{
	uint8_t	derived[64];
	size_t	digestSize;

	if (!secrets || !handshakeHash)
	{
		BTLS_DEBUG("tls13KeyScheduleDeriveHandshakeSecrets: NULL parameter");
		return (0);
	}
	
	if (!secrets->hash)
	{
		BTLS_DEBUG("tls13KeyScheduleDeriveHandshakeSecrets: secrets->hash is NULL");
		return (0);
	}
	
	digestSize = secrets->hash->digestSize;
	if (hashLen != digestSize)
	{
		BTLS_DEBUG("tls13KeyScheduleDeriveHandshakeSecrets: hashLen mismatch (%zu vs %zu)", hashLen, digestSize);
		return (0);
	}

	/* client_handshake_traffic_secret */
	if (!tls13DeriveSecret(secrets->handshakeSecret, digestSize,
						   TLS13_LABEL_CLIENT_HS_TRAFFIC,
						   handshakeHash, hashLen,
						   secrets->clientHandshakeTrafficSecret,
						   digestSize, secrets->hash))
	{
		BTLS_DEBUG("client_handshake_traffic_secret derivation failed");
		return (0);
	}

	/* server_handshake_traffic_secret */
	if (!tls13DeriveSecret(secrets->handshakeSecret, digestSize,
						   TLS13_LABEL_SERVER_HS_TRAFFIC,
						   handshakeHash, hashLen,
						   secrets->serverHandshakeTrafficSecret,
						   digestSize, secrets->hash))
	{
		BTLS_DEBUG("server_handshake_traffic_secret derivation failed");
		return (0);
	}

	/* derived = Derive-Secret(handshake_secret, "derived", "") */
	if (!tls13DeriveSecret(secrets->handshakeSecret, digestSize,
						   TLS13_LABEL_DERIVED, NULL, 0,
						   derived, digestSize,
						   secrets->hash))
	{
		BTLS_DEBUG("derived (handshake) derivation failed");
		return (0);
	}

	/* master_secret = HKDF-Extract(derived, 0) */
	uint8_t zeroIkm[64] = {0};
	if (!hkdfExtract(derived, digestSize, zeroIkm, digestSize,
		 secrets->masterSecret, digestSize, secrets->hash))
	{
		BTLS_DEBUG("master_secret extraction failed");
		return (0);
	}

	secureZeroMemory(derived, sizeof(derived));
	return (1);
}

int	tls13KeyScheduleDeriveAppSecrets(t_tls13Secrets	*secrets,
									const uint8_t	*handshakeHash,
									size_t			hashLen)
{
	size_t	digestSize;

	if (!secrets || !handshakeHash)
	{
		BTLS_DEBUG("tls13KeyScheduleDeriveAppSecrets: NULL parameter");
		return (0);
	}
	
	if (!secrets->hash)
	{
		BTLS_DEBUG("tls13KeyScheduleDeriveAppSecrets: secrets->hash is NULL");
		return (0);
	}
	
	digestSize = secrets->hash->digestSize;
	if (hashLen != digestSize)
	{
		BTLS_DEBUG("tls13KeyScheduleDeriveAppSecrets: hashLen mismatch (%zu vs %zu)", hashLen, digestSize);
		return (0);
	}

	/* client_application_traffic_secret */
	if (!tls13DeriveSecret(secrets->masterSecret, digestSize,
						   TLS13_LABEL_CLIENT_APP_TRAFFIC,
						   handshakeHash, hashLen,
						   secrets->clientAppTrafficSecret,
						   digestSize, secrets->hash))
	{
		BTLS_DEBUG("client_application_traffic_secret derivation failed");
		return (0);
	}

	/* server_application_traffic_secret */
	if (!tls13DeriveSecret(secrets->masterSecret, digestSize,
						   TLS13_LABEL_SERVER_APP_TRAFFIC,
						   handshakeHash, hashLen,
						   secrets->serverAppTrafficSecret,
						   digestSize, secrets->hash))
	{
		BTLS_DEBUG("server_application_traffic_secret derivation failed");
		return (0);
	}

	/* exporter_master_secret */
	if (!tls13DeriveSecret(secrets->masterSecret, digestSize,
						   TLS13_LABEL_EXPORTER_MASTER,
						   handshakeHash, hashLen,
						   secrets->exporterMasterSecret,
						   digestSize, secrets->hash))
	{
		BTLS_DEBUG("exporter_master_secret derivation failed");
		return (0);
	}

	/* resumption_master_secret */
	if (!tls13DeriveSecret(secrets->masterSecret, digestSize,
						   TLS13_LABEL_RESUMPTION_MASTER,
						   handshakeHash, hashLen,
						   secrets->resumptionMasterSecret,
						   digestSize, secrets->hash))
	{
		BTLS_DEBUG("resumption_master_secret derivation failed");
		return (0);
	}

	return (1);
}

int	tls13DeriveTrafficKeys(t_tls13TrafficKeys	*keys,
						   const uint8_t		*secret,
						   size_t				secretLen,
						   const t_hash			*hash,
						   size_t				cipherKeyLen)
{
	if (!keys || !secret || !hash)
		return (0);
	if (cipherKeyLen != 16 && cipherKeyLen != 32)
		return (0);

	ft_memset(keys, 0, sizeof(t_tls13TrafficKeys));

	/* Derive encryption key */
	if (!tlsHkdfExpandLabel(secret, secretLen,
							TLS13_LABEL_TRAFFIC_KEY, NULL, 0,
							keys->key, cipherKeyLen, hash))
	{
		BTLS_DEBUG("traffic key derivation failed");
		return (0);
	}
	keys->keyLen = cipherKeyLen;

	/* Derive IV (12 bytes) */
	if (!tlsHkdfExpandLabel(secret, secretLen,
							TLS13_LABEL_TRAFFIC_IV, NULL, 0,
							keys->iv, 12, hash))
	{
		BTLS_DEBUG("traffic IV derivation failed");
		return (0);
	}
	keys->ivLen = 12;

	return (1);
}

void	tls13PrintSecrets(const t_tls13Secrets *secrets)
{
	size_t	i;

	if (!secrets)
		return ;

	ft_printf("=== TLS 1.3 Secrets (hashLen=%zu, pskEnabled=%d) ===\n",
		   secrets->hash->digestSize, secrets->pskEnabled);

	ft_printf("earlySecret: ");
	for (i = 0; i < secrets->hash->digestSize; i++)
		ft_printf("%02x", secrets->earlySecret[i]);
	ft_printf("\n");

	ft_printf("handshakeSecret: ");
	for (i = 0; i < secrets->hash->digestSize; i++)
		ft_printf("%02x", secrets->handshakeSecret[i]);
	ft_printf("\n");

	ft_printf("masterSecret: ");
	for (i = 0; i < secrets->hash->digestSize; i++)
		ft_printf("%02x", secrets->masterSecret[i]);
	ft_printf("\n");

	ft_printf("clientHandshakeTrafficSecret: ");
	for (i = 0; i < secrets->hash->digestSize; i++)
		ft_printf("%02x", secrets->clientHandshakeTrafficSecret[i]);
	ft_printf("\n");

	ft_printf("serverHandshakeTrafficSecret: ");
	for (i = 0; i < secrets->hash->digestSize; i++)
		ft_printf("%02x", secrets->serverHandshakeTrafficSecret[i]);
	ft_printf("\n");

	ft_printf("clientAppTrafficSecret: ");
	for (i = 0; i < secrets->hash->digestSize; i++)
		ft_printf("%02x", secrets->clientAppTrafficSecret[i]);
	ft_printf("\n");

	ft_printf("serverAppTrafficSecret: ");
	for (i = 0; i < secrets->hash->digestSize; i++)
		ft_printf("%02x", secrets->serverAppTrafficSecret[i]);
	ft_printf("\n");

	ft_printf("exporterMasterSecret: ");
	for (i = 0; i < secrets->hash->digestSize; i++)
		ft_printf("%02x", secrets->exporterMasterSecret[i]);
	ft_printf("\n");

	ft_printf("resumptionMasterSecret: ");
	for (i = 0; i < secrets->hash->digestSize; i++)
		ft_printf("%02x", secrets->resumptionMasterSecret[i]);
	ft_printf("\n");

	if (secrets->pskEnabled)
	{
		ft_printf("externalBinderKey: ");
		for (i = 0; i < secrets->hash->digestSize; i++)
			ft_printf("%02x", secrets->externalBinderKey[i]);
		ft_printf("\n");
	}
}
