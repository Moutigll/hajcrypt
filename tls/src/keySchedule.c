#include <stdlib.h>
#include "../../hajlib/include/hmemory.h"
#include "../../includes/kdf/hkdf.h"
#include "../../includes/utils/utils.h"
#include "../../hajlib/include/hprintf.h"

#include "../includes/hkdf.h"
#include "../includes/keySchedule.h"
#include "../includes/constants.h"


int	tls13DeriveSecret(const uint8_t		*secret,	size_t	secretLen,
					  const char		*label,
					  const uint8_t		*context,	size_t	contextLen,
					  uint8_t			*output,	size_t	outputLen,
					  const t_hashAlgo	*hash)
{
	if (!secret || !label || !output || !hash)
		return (0);

	return (tlsHkdfExpandLabel(secret, secretLen,
							   label, context, contextLen,
							   output, outputLen, hash));
}


void	tls13KeyScheduleInit(t_tls13Secrets *secrets, const t_hashAlgo *hash)
{
	if (!secrets || !hash)
		return ;

	ft_memset(secrets, 0, sizeof(t_tls13Secrets));
	secrets->hash = hash;
	secrets->pskEnabled = 0;
}

int	tls13KeyScheduleExtractHandshake(t_tls13Secrets	*secrets,
									 const uint8_t	*psk,			size_t pskLen,
									 const uint8_t	*sharedSecret,	size_t sharedLen)
{
	uint8_t	derived[64];
	uint8_t	zero[64];

	if (!secrets || !sharedSecret)
		return (0);

	ft_memset(zero, 0, secrets->hash->digestSize);

	if (psk && pskLen > 0)
	{
		/* early_secret = HKDF-Extract(0, psk) */
		if (!hkdfExtract(NULL, 0, psk, pskLen,
						 secrets->earlySecret, secrets->hash->digestSize,
						 secrets->hash))
			return (0);

		/* external_binder_key = Derive-Secret(early_secret, "ext binder", "") */
		if (!tls13DeriveSecret(secrets->earlySecret, secrets->hash->digestSize,
							   TLS13_LABEL_EXTRACTOR, NULL, 0,
							   secrets->externalBinderKey, secrets->hash->digestSize,
							   secrets->hash))
			return (0);

		/* derived = Derive-Secret(early_secret, "derived", "") */
		if (!tls13DeriveSecret(secrets->earlySecret, secrets->hash->digestSize,
							   TLS13_LABEL_DERIVED, NULL, 0,
							   derived, secrets->hash->digestSize,
							   secrets->hash))
			return (0);

		/* handshake_secret = HKDF-Extract(derived, shared_secret) */
		if (!hkdfExtract(derived, secrets->hash->digestSize,
						 sharedSecret, sharedLen,
						 secrets->handshakeSecret, secrets->hash->digestSize,
						 secrets->hash))
			return (0);

		secrets->pskEnabled = 1;
	}
	else
	{
		/* no PSK : handshake_secret = HKDF-Extract(0, shared_secret) */
		if (!hkdfExtract(NULL, 0,
						 sharedSecret, sharedLen,
						 secrets->handshakeSecret, secrets->hash->digestSize,
						 secrets->hash))
			return (0);

		secrets->pskEnabled = 0;
	}

	secureZeroMemory(derived, sizeof(derived));
	secureZeroMemory(zero, sizeof(zero));
	return (1);
}

int	tls13KeyScheduleDeriveHandshakeSecrets(t_tls13Secrets	*secrets,
										   const uint8_t	*handshakeHash,
										   size_t			hashLen)
{
	uint8_t	derived[64];

	if (!secrets || !handshakeHash || hashLen != secrets->hash->digestSize)
		return (0);

	/* client_handshake_traffic_secret */
	if (!tls13DeriveSecret(secrets->handshakeSecret, secrets->hash->digestSize,
						   TLS13_LABEL_CLIENT_HS_TRAFFIC,
						   handshakeHash, hashLen,
						   secrets->clientHandshakeTrafficSecret,
						   secrets->hash->digestSize, secrets->hash))
		return (0);

	/* server_handshake_traffic_secret */
	if (!tls13DeriveSecret(secrets->handshakeSecret, secrets->hash->digestSize,
						   TLS13_LABEL_SERVER_HS_TRAFFIC,
						   handshakeHash, hashLen,
						   secrets->serverHandshakeTrafficSecret,
						   secrets->hash->digestSize, secrets->hash))
		return (0);

	/* derived = Derive-Secret(handshake_secret, "derived", "") */
	if (!tls13DeriveSecret(secrets->handshakeSecret, secrets->hash->digestSize,
						   TLS13_LABEL_DERIVED, NULL, 0,
						   derived, secrets->hash->digestSize,
						   secrets->hash))
		return (0);

	/* master_secret = HKDF-Extract(derived, 0) */
	if (!hkdfExtract(derived, secrets->hash->digestSize,
					 NULL, 0,
					 secrets->masterSecret, secrets->hash->digestSize,
					 secrets->hash))
		return (0);

	secureZeroMemory(derived, sizeof(derived));
	return (1);
}

int	tls13KeyScheduleDeriveAppSecrets(t_tls13Secrets	*secrets,
									const uint8_t	*handshakeHash,
									size_t			hashLen)
{
	if (!secrets || !handshakeHash || hashLen != secrets->hash->digestSize)
		return (0);

	/* client_application_traffic_secret */
	if (!tls13DeriveSecret(secrets->masterSecret, secrets->hash->digestSize,
						   TLS13_LABEL_CLIENT_APP_TRAFFIC,
						   handshakeHash, hashLen,
						   secrets->clientAppTrafficSecret,
						   secrets->hash->digestSize, secrets->hash))
		return (0);

	/* server_application_traffic_secret */
	if (!tls13DeriveSecret(secrets->masterSecret, secrets->hash->digestSize,
						   TLS13_LABEL_SERVER_APP_TRAFFIC,
						   handshakeHash, hashLen,
						   secrets->serverAppTrafficSecret,
						   secrets->hash->digestSize, secrets->hash))
		return (0);

	/* exporter_master_secret */
	if (!tls13DeriveSecret(secrets->masterSecret, secrets->hash->digestSize,
						   TLS13_LABEL_EXPORTER_MASTER,
						   handshakeHash, hashLen,
						   secrets->exporterMasterSecret,
						   secrets->hash->digestSize, secrets->hash))
		return (0);

	/* resumption_master_secret */
	if (!tls13DeriveSecret(secrets->masterSecret, secrets->hash->digestSize,
						   TLS13_LABEL_RESUMPTION_MASTER,
						   handshakeHash, hashLen,
						   secrets->resumptionMasterSecret,
						   secrets->hash->digestSize, secrets->hash))
		return (0);

	return (1);
}

int	tls13DeriveTrafficKeys(t_tls13TrafficKeys	*keys,
						   const uint8_t		*secret,
						   size_t				secretLen,
						   const t_hashAlgo		*hash,
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
		return (0);
	keys->keyLen = cipherKeyLen;

	/* Derive IV (12 bytes) */
	if (!tlsHkdfExpandLabel(secret, secretLen,
							TLS13_LABEL_TRAFFIC_IV, NULL, 0,
							keys->iv, 12, hash))
		return (0);
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
