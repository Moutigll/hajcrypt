#include "../../hajlib/include/hprintf.h"
#include "../../includes/hash/whirlpool.h"

#include "../test.h"

/* Vecteurs de test Whirlpool (ISO/IEC 10118-3) */
static testVector_t whirlpool_vectors[] = {
	{"", 0,
	 "19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a7"
	 "3e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3"},
	{"a", 1,
	 "8aca2602792aec6f11a67206531fb7d7f0dff59413145e6973c45001d0087b42"
	 "d11bc645413aeff63a42391a39145a591a92200d560195e53b478584fdae231a"},
	{"abc", 3,
	 "4e2448a4c6f486bb16b6562c73b4020bf3043e3a731bce721ae1b303d97e6d4c7"
	 "181eebdb6c57e277d0e34957114cbd6c797fc9d95d8b582d225292076d4eef5"},
	{"The quick brown fox jumps over the lazy dog", 43,
	 "b97de512e91e3828b40d2b0fdce9ceb3c4a71f9bea8d88e75c4fa854df36725f"
	 "d2b52eb6544edcacd6f8beddfea403cb55ae31f03ad62a5ef54e42ee82c3fb35"},
	{NULL, 0, NULL}
};

int testWhirlpoolBasic(void) {
	int passed = 0;
	int total = 0;
	
	printInfo("Testing Whirlpool basic vectors...");
	
	for (int i = 0; whirlpool_vectors[i].input != NULL; i++) {
		uint8_t digest[64];
		t_whirlpoolCtx ctx;
		
		whirlpoolInit(&ctx);
		whirlpoolUpdate(&ctx, (const uint8_t*)whirlpool_vectors[i].input,
						whirlpool_vectors[i].input_len);
		whirlpoolFinal(digest, &ctx);
		
		total++;
		if (compareHex(whirlpool_vectors[i].expected, digest, 64)) {
			passed++;
			printSuccess(whirlpool_vectors[i].input);
		} else {
			printFailure(whirlpool_vectors[i].input);
		}
	}
	
	ft_printf("Whirlpool basic: %d/%d passed\n", passed, total);
	g_totalTests += total;
	g_passedTests += passed;
	return (passed == total);
}
