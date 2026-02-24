#include "../../hajlib/include/hmemory.h"
#include "../../hajlib/include/hprintf.h"
#include "../../hajlib/include/hstring.h"
#include "../../includes/hash/md5.h"

#include "../test.h"

/* Vecteurs de test MD5 (RFC 1321) */
static testVector_t md5_vectors[] = {
	{"", 0, "d41d8cd98f00b204e9800998ecf8427e"},
	{"a", 1, "0cc175b9c0f1b6a831c399e269772661"},
	{"abc", 3, "900150983cd24fb0d6963f7d28e17f72"},
	{"message digest", 14, "f96b697d7cb7938d525a2f31aaf161d0"},
	{"abcdefghijklmnopqrstuvwxyz", 26, "c3fcd3d76192e4007dfb496cca67e13b"},
	{"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 62,
	 "d174ab98d277d9f5a5611c2c9f419d9f"},
	{"12345678901234567890123456789012345678901234567890123456789012345678901234567890", 80,
	 "57edf4a22be3c955ac49da2e2107b67a"},
	{NULL, 0, NULL}
};

static int runMd5Test(const testVector_t *vec) {
	uint8_t digest[16];
	t_md5Ctx ctx;
	
	md5Init(&ctx);
	md5Update(&ctx, (const uint8_t*)vec->input, vec->input_len);
	md5Final(digest, &ctx);
	
	return compareHex(vec->expected, digest, 16);
}

int testMd5Basic(void) {
	int passed = 0;
	int total = 0;
	
	printInfo("Testing MD5 basic vectors...");
	
	for (int i = 0; md5_vectors[i].input != NULL; i++) {
		total++;
		if (runMd5Test(&md5_vectors[i])) {
			passed++;
			printSuccess(md5_vectors[i].input);
		} else
			printFailure(md5_vectors[i].input);
	}
	
	ft_printf("MD5 basic: %d/%d passed\n", passed, total);
	return (passed == total);
}

int testMd5Update(void) {
	uint8_t digest1[16], digest2[16];
	t_md5Ctx ctx;
	const char *msg = "The quick brown fox jumps over the lazy dog";
	size_t len = ft_strlen(msg);
	
	/* One-shot */
	md5Init(&ctx);
	md5Update(&ctx, (const uint8_t*)msg, len);
	md5Final(digest1, &ctx);
	
	/* Split updates */
	md5Init(&ctx);
	md5Update(&ctx, (const uint8_t*)msg, 10);
	md5Update(&ctx, (const uint8_t*)msg + 10, len - 10);
	md5Final(digest2, &ctx);
	
	if (ft_memcmp(digest1, digest2, 16) == 0) {
		printSuccess("MD5 update consistency");
		return (1);
	} else {
		printFailure("MD5 update consistency");
		return (0);
	}
}
