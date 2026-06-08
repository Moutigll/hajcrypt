#include "../../includes/extensions.h"

void putExt(uint8_t *out, size_t *pos, uint16_t type, const uint8_t *data, size_t dlen) {
	wU16(out, *pos, type);
	wU16(out, *pos + 2, (uint16_t)dlen);
	wBytes(out, *pos + 4, data, dlen);
	*pos += 4 + dlen;
}
