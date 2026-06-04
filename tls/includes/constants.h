#ifndef TLS_CONSTANTS_H
# define TLS_CONSTANTS_H

/* TLS record content types (RFC 8446) */
#define TLS_RT_CHANGE_CIPHER_SPEC	0x14
#define TLS_RT_ALERT				0x15
#define TLS_RT_HANDSHAKE			0x16
#define TLS_RT_APPLICATION_DATA		0x17

/* TLS record header size */
#define TLS_RECORD_HEADER_SIZE		5

/* Maximum fragment length (2^14) */
#define TLS_MAX_FRAGMENT_LEN		16384

/* Legacy version for compatibility (TLS 1.2) */
#define TLS_LEGACY_VERSION			0x0303

/* Labels TLS 1.3 (RFC 8446 §7.1) */
#define TLS13_LABEL_DERIVED				"derived"
#define TLS13_LABEL_EXTRACTOR			"ext binder"
#define TLS13_LABEL_HANDSHAKE			"handshake"
#define TLS13_LABEL_CLIENT_HS_TRAFFIC	"c hs traffic"
#define TLS13_LABEL_SERVER_HS_TRAFFIC	"s hs traffic"
#define TLS13_LABEL_CLIENT_APP_TRAFFIC	"c ap traffic"
#define TLS13_LABEL_SERVER_APP_TRAFFIC	"s ap traffic"
#define TLS13_LABEL_EXPORTER_MASTER		"exp master"
#define TLS13_LABEL_RESUMPTION_MASTER	"res master"
#define TLS13_LABEL_TRAFFIC_KEY			"key"
#define TLS13_LABEL_TRAFFIC_IV			"iv"

#endif /* TLS_CONSTANTS_H */
