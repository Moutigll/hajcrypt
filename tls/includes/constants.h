#ifndef TLS_CONSTANTS_H
# define TLS_CONSTANTS_H

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
