#include "../../includes/asymmetric/bigint.h"

#include "../test.h"

int testBigIntIsOddEven(void)
{
	int passed = 0, total = 0;
	printInfo("Testing bigIntIsOdd/Even...");

	struct {
		uint64_t	val;
		int			odd;
		int			even;
	} vectors[] = {
		{0, 0, 1},
		{1, 1, 0},
		{2, 0, 1},
		{0xFFFFFFFFFFFFFFFFULL, 1, 0},
		{0xFFFFFFFFFFFFFFFEULL, 0, 1},
	};
	for (size_t i = 0; i < sizeof(vectors)/sizeof(vectors[0]); i++) {
		t_bigInt *n = bigIntFromUint64(vectors[i].val);
		int odd = bigIntIsOdd(n);
		int even = bigIntIsEven(n);
		if (odd == vectors[i].odd && even == vectors[i].even) {
			passed++; printSuccess("odd/even detection");
		} else {
			printFailure("odd/even detection");
		}
		total++;
		bigIntFree(n);
	}

	/* Multi-word odd/even: test only least significant word */
	t_bigInt *bigOdd = bigIntFromHex("000000010000000000000001", 2); /* odd */
	t_bigInt *bigEven = bigIntFromHex("000000010000000000000002", 2); /* even */
	if (bigOdd && bigEven) {
		if (bigIntIsOdd(bigOdd) && !bigIntIsEven(bigOdd) &&
			!bigIntIsOdd(bigEven) && bigIntIsEven(bigEven)) {
			passed++; printSuccess("multi-word odd/even");
		} else
			printFailure("multi-word odd/even");
		total++;
	}
	bigIntFree(bigOdd); bigIntFree(bigEven);

	g_totalTests += total;
	g_passedTests += passed;
	return (passed == total);
}

int	testBigIntAdd(void)
{
	int		passed = 0;
	int		total = 0;

	printInfo("Testing bigIntAdd()...");
	/* ---------- Simple single-word additions ---------- */
	struct {
		uint64_t	a;
		uint64_t	b;
		uint64_t	expected;
	} simple[] = {
		{0,						0,						0						},
		{1,						2,						3						},
		{0xFFFFFFFFFFFFFFFEULL,	1,						0xFFFFFFFFFFFFFFFFULL	},
		{0x1234567890ABCDEFULL,	0x1111111111111111ULL,	0x23456789A1BCDF00ULL	},
	};
	for (size_t i = 0; i < sizeof(simple) / sizeof(simple[0]); i++)
	{
		t_bigInt	*a   = bigIntFromUint64(simple[i].a);
		t_bigInt	*b   = bigIntFromUint64(simple[i].b);
		t_bigInt	*res = bigIntNew(2);

		if (bigIntAdd(res, a, b)
			&& res->used == (simple[i].expected ? 1 : 0)
			&& (res->used == 0 || res->words[0] == simple[i].expected))
		{
			passed++;
			printSuccess("single-word add, no carry");
		}
		else
			printFailure("single-word add, no carry");
		total++;
		bigIntFree(a);
		bigIntFree(b);
		bigIntFree(res);
	}
	/* ---------- Single-word additions with carry ---------- */
	struct {
		uint64_t	a;
		uint64_t	b;
		uint64_t	lo;		/* expected words[0] */
		uint64_t	hi;		/* expected words[1] */
	} carry[] = {
		{0xFFFFFFFFFFFFFFFFULL,	1,						0,						1},
		{0xFFFFFFFFFFFFFFFFULL,	0xFFFFFFFFFFFFFFFFULL,	0xFFFFFFFFFFFFFFFEULL,	1},
		{0x8000000000000000ULL,	0x8000000000000000ULL,	0,						1},
	};
	for (size_t i = 0; i < sizeof(carry) / sizeof(carry[0]); i++)
	{
		t_bigInt	*a = bigIntFromUint64(carry[i].a);
		t_bigInt	*b = bigIntFromUint64(carry[i].b);

		/* 2a. Enough capacity: result must hold two words */
		t_bigInt	*res = bigIntNew(2);
		if (bigIntAdd(res, a, b)
			&& res->used == 2
			&& res->words[0] == carry[i].lo
			&& res->words[1] == carry[i].hi)
		{
			passed++;
			printSuccess("single-word add with carry (enough capacity)");
		}
		else
			printFailure("single-word add with carry (enough capacity)");
		total++;
		bigIntFree(res);

		/* 2b. Insufficient capacity: must return NULL */
		t_bigInt	*small = bigIntNew(1);
		if (bigIntAdd(small, a, b) == NULL)
		{
			passed++;
			printSuccess("single-word add returns NULL on insufficient capacity");
		}
		else
			printFailure("single-word add should return NULL on insufficient capacity");
		total++;
		bigIntFree(small);

		bigIntFree(a);
		bigIntFree(b);
	}
	/* ---------- Multi-word additions ---------- */
	{
		t_bigInt	*a   = bigIntFromHex("ffffffffffffffff", 2);
		t_bigInt	*b   = bigIntFromHex("100000000", 2);
		t_bigInt	*exp = bigIntFromHex("100000000ffffffff", 2);
		t_bigInt	*res = bigIntNew(3);

		if (a && b && exp && res
			&& bigIntAdd(res, a, b)
			&& bigIntCmp(res, exp) == 0)
		{
			passed++;
			printSuccess("multi-word add: 0xFFFF…FFFF + 0x1_0000_0000");
		}
		else
			printFailure("multi-word add: 0xFFFF…FFFF + 0x1_0000_0000");
		total++;
		bigIntFree(a);
		bigIntFree(b);
		bigIntFree(exp);
		bigIntFree(res);
	}

	{
		t_bigInt	*a   = bigIntFromHex("ffffffffffffffff", 2);
		t_bigInt	*b   = bigIntFromUint64(1);
		t_bigInt	*exp = bigIntFromHex("10000000000000000", 2);
		t_bigInt	*res = bigIntNew(3);

		if (a && b && exp && res
			&& bigIntAdd(res, a, b)
			&& bigIntCmp(res, exp) == 0)
		{
			passed++;
			printSuccess("add different lengths: 0xFFFF…FFFF + 1 = 2^64");
		}
		else
			printFailure("add different lengths: 0xFFFF…FFFF + 1 = 2^64");
		total++;
		bigIntFree(a);
		bigIntFree(b);
		bigIntFree(exp);
		bigIntFree(res);
	}
	/* ---------- Result aliasing: result can be same as operand ---------- */
	{
		t_bigInt	*a   = bigIntFromUint64(100);
		t_bigInt	*b   = bigIntFromUint64(200);
		t_bigInt	*res = bigIntNew(2);

		if (a && b && res
			&& bigIntCopy(res, a)
			&& bigIntAdd(res, res, b)
			&& res->used == 1
			&& res->words[0] == 300)
		{
			passed++;
			printSuccess("add with result aliasing first operand");
		}
		else
			printFailure("add with result aliasing first operand");
		total++;
		bigIntFree(a);
		bigIntFree(b);
		bigIntFree(res);
	}

	{
		t_bigInt	*a   = bigIntFromUint64(0);
		t_bigInt	*b   = bigIntFromUint64(123);
		t_bigInt	*res = bigIntNew(2);

		if (a && b && res
			&& bigIntAdd(res, a, b)
			&& res->used == 1
			&& res->words[0] == 123)
		{
			passed++;
			printSuccess("add identity: 0 + 123 = 123");
		}
		else
			printFailure("add identity: 0 + 123 = 123");
		total++;
		bigIntFree(a);
		bigIntFree(b);
		bigIntFree(res);
	}

	g_totalTests  += total;
	g_passedTests += passed;
	return (passed == total);
}

int	testBigIntSub(void)
{
	int	passed = 0;
	int	total = 0;

	printInfo("Testing bigIntSub()...");

	/* ---------- Single-word subtraction (a > b, no borrow) ---------- */
	struct {
		uint64_t	a;
		uint64_t	b;
		uint64_t	expected;
	} simple[] = {
		{5, 3, 2},
		{0, 0, 0},
		{0xFFFFFFFFFFFFFFFEULL, 1, 0xFFFFFFFFFFFFFFFDULL},
		{0x1234567890ABCDEFULL, 0x1111111111111111ULL, 0x012345677F9ABCDEULL}
	};
	for (size_t i = 0; i < sizeof(simple)/sizeof(simple[0]); i++) {
		t_bigInt *a   = bigIntFromUint64(simple[i].a);
		t_bigInt *b   = bigIntFromUint64(simple[i].b);
		t_bigInt *res = bigIntNew(2);

		if (a && b && res &&
			bigIntSub(res, a, b) &&
			res->used == (simple[i].expected ? 1 : 0) &&
			(res->used == 0 || res->words[0] == simple[i].expected))
		{
			passed++;
			printSuccess("single-word sub, no borrow");
		} else
			printFailure("single-word sub, no borrow");
		total++;
		bigIntFree(a);
		bigIntFree(b);
		bigIntFree(res);
	}

	/* ---------- Single-word subtraction a < b -> must fail (NULL) ---------- */
	{
		t_bigInt *a   = bigIntFromUint64(3);
		t_bigInt *b   = bigIntFromUint64(5);
		t_bigInt *res = bigIntNew(2);

		if (a && b && res && bigIntSub(res, a, b) == NULL) {
			passed++;
			printSuccess("single-word sub a<b returns NULL");
		} else
			printFailure("single-word sub a<b returns NULL");
		total++;
		bigIntFree(a);
		bigIntFree(b);
		bigIntFree(res);
	}

	/* ---------- Multi-word subtraction with borrow ---------- */
	{
		/* a = 2^64 = [0, 1], b = 1, expected = 2^64 - 1 = [0xFFFFFFFFFFFFFFFF, 0] */
		t_bigInt *a   = bigIntFromHex("00000000000000010000000000000000", 2);
		t_bigInt *b   = bigIntFromUint64(1);
		t_bigInt *exp = bigIntFromHex("FFFFFFFFFFFFFFFF", 1);
		t_bigInt *res = bigIntNew(2);

		if (a && b && exp && res &&
			bigIntSub(res, a, b) &&
			bigIntCmp(res, exp) == 0)
		{
			passed++;
			printSuccess("multi-word sub with borrow: 2^64 - 1");
		} else
			printFailure("multi-word sub with borrow: 2^64 - 1");
		total++;
		bigIntFree(a); bigIntFree(b); bigIntFree(exp); bigIntFree(res);
	}

	{
		/* a = [0x00000000FFFFFFFF, 0x0000000100000000] (2^64 + 2^32 -1)
		 * b = [0x0000000100000000, 0x0000000000000000] (2^64)
		 * expected = 2^32 -1 = [0xFFFFFFFF, 0] */
		t_bigInt *a   = bigIntFromHex("000000010000000000000000FFFFFFFF", 2);
		t_bigInt *b   = bigIntFromHex("00000001000000000000000000000000", 2);
		t_bigInt *exp = bigIntFromHex("FFFFFFFF", 1);
		t_bigInt *res = bigIntNew(2);

		if (a && b && exp && res &&
			bigIntSub(res, a, b) &&
			bigIntCmp(res, exp) == 0)
		{
			passed++;
			printSuccess("multi-word sub borrow across words, result shorter");
		} else
			printFailure("multi-word sub borrow across words, result shorter");
		total++;
		bigIntFree(a); bigIntFree(b); bigIntFree(exp); bigIntFree(res);
	}

	/* ---------- Subtraction resulting in zero ---------- */
	{
		t_bigInt *a   = bigIntFromHex("DEADBEEFCAFEBABE", 1);
		t_bigInt *b   = bigIntFromHex("DEADBEEFCAFEBABE", 1);
		t_bigInt *res = bigIntNew(2);

		if (a && b && res &&
			bigIntSub(res, a, b) &&
			res->used == 0)   /* zero is represented with used=0 */
		{
			passed++;
			printSuccess("sub a == b yields zero");
		} else
			printFailure("sub a == b yields zero");
		total++;
		bigIntFree(a); bigIntFree(b); bigIntFree(res);
	}

	/* ---------- Result aliasing: res == a ---------- */
	{
		t_bigInt *a   = bigIntFromUint64(1000);
		t_bigInt *b   = bigIntFromUint64(300);
		t_bigInt *res = bigIntNew(2);

		if (a && b && res &&
			bigIntCopy(res, a) &&
			bigIntSub(res, res, b) &&
			res->used == 1 && res->words[0] == 700)
		{
			passed++;
			printSuccess("sub with result aliasing first operand");
		} else
			printFailure("sub with result aliasing first operand");
		total++;
		bigIntFree(a); bigIntFree(b); bigIntFree(res);
	}

	/* ---------- Result aliasing: res == b ---------- */
	{
		t_bigInt *a   = bigIntFromUint64(1000);
		t_bigInt *b   = bigIntFromUint64(300);
		t_bigInt *res = bigIntNew(2);

		if (a && b && res &&
			bigIntCopy(res, b) &&
			bigIntSub(res, a, res) &&
			res->used == 1 && res->words[0] == 700)
		{
			passed++;
			printSuccess("sub with result aliasing second operand");
		} else
			printFailure("sub with result aliasing second operand");
		total++;
		bigIntFree(a); bigIntFree(b); bigIntFree(res);
	}

	/* ---------- Insufficient capacity: result must have enough words ---------- */
	{
		t_bigInt *a   = bigIntFromHex("10000000000000000", 2); /* 2^64, needs 2 words */
		t_bigInt *b   = bigIntFromUint64(1);
		t_bigInt *res = bigIntNew(1);  /* only one word, insufficient */

		if (a && b && res && bigIntSub(res, a, b) == NULL) {
			passed++;
			printSuccess("insufficient capacity -> NULL");
		} else
			printFailure("insufficient capacity -> NULL");
		total++;
		bigIntFree(a); bigIntFree(b); bigIntFree(res);
	}

	/* ---------- a > b but b has more (zero) words ---------- */
	{
		t_bigInt *a   = bigIntFromUint64(42);
		t_bigInt *b   = bigIntFromHex("0000000000000000", 2); /* two words, all zero */
		t_bigInt *exp = bigIntFromUint64(42);
		t_bigInt *res = bigIntNew(2);

		if (a && b && exp && res &&
			bigIntSub(res, a, b) &&
			bigIntCmp(res, exp) == 0)
		{
			passed++;
			printSuccess("subtract zero-extended b");
		} else
			printFailure("subtract zero-extended b");
		total++;
		bigIntFree(a); bigIntFree(b); bigIntFree(exp); bigIntFree(res);
	}

	/* ---------- a < b with multi-word: expect NULL ---------- */
	{
		t_bigInt *a   = bigIntFromHex("FFFFFFFFFFFFFFFF", 1);  /* 2^64 - 1 */
		t_bigInt *b   = bigIntFromHex("10000000000000000", 2); /* 2^64 */
		t_bigInt *res = bigIntNew(2);

		if (a && b && res && bigIntSub(res, a, b) == NULL) {
			passed++;
			printSuccess("multi-word a<b returns NULL");
		} else
			printFailure("multi-word a<b returns NULL");
		total++;
		bigIntFree(a); bigIntFree(b); bigIntFree(res);
	}

	{
		t_bigInt *a = bigIntFromHex("10000000000000000", 2); // 2^64
		t_bigInt *b = bigIntFromUint64(1);
		t_bigInt *res = bigIntNew(2); // capacité 2, exactement ce qu'il faut
		if (a && b && res && bigIntSub(res, a, b) != NULL && res->used == 1 && res->words[0] == 0xFFFFFFFFFFFFFFFFULL) {
			passed++; printSuccess("capacity exactly enough");
		} else { printFailure("capacity exactly enough"); }
		total++;
		bigIntFree(a); bigIntFree(b); bigIntFree(res);
	}

	/* ---------- Capacité supérieure (ne doit pas planter) ---------- */
	{
		t_bigInt *a = bigIntFromUint64(100);
		t_bigInt *b = bigIntFromUint64(50);
		t_bigInt *res = bigIntNew(5); // beaucoup trop de place
		if (a && b && res && bigIntSub(res, a, b) != NULL && res->used == 1 && res->words[0] == 50) {
			passed++; printSuccess("extra capacity ok");
		} else { printFailure("extra capacity ok"); }
		total++;
		bigIntFree(a); bigIntFree(b); bigIntFree(res);
	}

		g_totalTests  += total;
		g_passedTests += passed;
		return (passed == total);
}

int	testBigIntMul(void)
{
	int	passed = 0;
	int	total = 0;

	printInfo("Testing bigIntMul()...");
	{
		t_bigInt *a = bigIntFromHex("DEADBEEFCAFEBABE12345678", 2);
		t_bigInt *b = bigIntFromUint64(0);
		t_bigInt *res = bigIntNew(3);
		t_bigInt *exp = bigIntNew(1);

		if (a && b && res && exp &&
			bigIntMul(res, a, b) &&
			bigIntIsZero(res))
		{
			passed++;
			printSuccess("mul by zero");
		} else
			printFailure("mul by zero");
		total++;
		bigIntFree(a); bigIntFree(b); bigIntFree(res); bigIntFree(exp);
	}
	{
		t_bigInt *a = bigIntFromHex("DEADBEEFCAFEBABE12345678", 2);
		t_bigInt *b = bigIntFromUint64(1);
		t_bigInt *res = bigIntNew(3);
		t_bigInt *exp = bigIntDup(a);

		if (a && b && res && exp &&
			bigIntMul(res, a, b) &&
			bigIntCmp(res, exp) == 0)
		{
			passed++;
			printSuccess("mul by one (identity)");
		} else {
			printFailure("mul by one (identity)");
		}
		total++;
		bigIntFree(a); bigIntFree(b); bigIntFree(res); bigIntFree(exp);
	}
	struct {
		uint64_t	a;
		uint64_t	b;
		uint64_t	expected_lo;
		uint64_t	expected_hi;
		int			need_two_words;
	} small[] = {
		{0, 0, 0, 0, 0},
		{1, 1, 1, 0, 0},
		{0xFFFFFFFFFFFFFFFFULL, 1, 0xFFFFFFFFFFFFFFFFULL, 0, 0},
		{0xFFFFFFFFFFFFFFFFULL, 2, 0xFFFFFFFFFFFFFFFEULL, 1, 1},
	};
	for (size_t i = 0; i < sizeof(small)/sizeof(small[0]); i++) {
		t_bigInt *a = bigIntFromUint64(small[i].a);
		t_bigInt *b = bigIntFromUint64(small[i].b);
		t_bigInt *res = bigIntNew(3);
		t_bigInt *exp = NULL;
		
		if (small[i].need_two_words) {
			exp = bigIntNew(2);
			if (exp) {
				exp->words[0] = small[i].expected_lo;
				exp->words[1] = small[i].expected_hi;
				exp->used = (small[i].expected_hi != 0) ? 2 : (small[i].expected_lo != 0);
			}
		} else
			exp = bigIntFromUint64(small[i].expected_lo);

		if (a && b && res && exp &&
			bigIntMul(res, a, b) &&
			bigIntCmp(res, exp) == 0)
		{
			passed++;
			printSuccess("small mul");
		} else
			printFailure("small mul");
		total++;
		bigIntFree(a); bigIntFree(b); bigIntFree(res); bigIntFree(exp);
	}
	{
		t_bigInt *a = bigIntFromUint64(12345);
		t_bigInt *b = bigIntFromUint64(6789);
		t_bigInt *res = bigIntNew(3);
		t_bigInt *exp = bigIntFromUint64(12345 * 6789); /* 83810205 */

		if (a && b && res && exp &&
			bigIntMul(res, a, b) &&
			bigIntCmp(res, exp) == 0)
		{
			passed++;
			printSuccess("12345 * 6789");
		} else
			printFailure("12345 * 6789");
		total++;
		bigIntFree(a); bigIntFree(b); bigIntFree(res); bigIntFree(exp);
	}
	{
		t_bigInt *a = bigIntFromHex("FFFFFFFFFFFFFFFF", 1);
		t_bigInt *b = bigIntFromHex("FFFFFFFFFFFFFFFF", 1);
		t_bigInt *res = bigIntNew(3);
		/* (2^64 - 1)^2 = 2^128 - 2^65 + 1 */
		t_bigInt *exp = bigIntFromHex("FFFFFFFFFFFFFFFE0000000000000001", 2);

		if (a && b && res && exp &&
			bigIntMul(res, a, b) &&
			bigIntCmp(res, exp) == 0)
		{
			passed++;
			printSuccess("(2^64 - 1) * (2^64 - 1)");
		} else
			printFailure("(2^64 - 1) * (2^64 - 1)");
		total++;
		bigIntFree(a); bigIntFree(b); bigIntFree(res); bigIntFree(exp);
	}
	{
		t_bigInt *a = bigIntFromHex("00000000000000010000000000000000", 2);
		t_bigInt *b = bigIntFromHex("00000000000000010000000000000000", 2);
		t_bigInt *res = bigIntNew(4);
		t_bigInt *exp = bigIntFromHex("000000000000000100000000000000000000000000000000", 3);

		if (a && b && res && exp &&
			bigIntMul(res, a, b) &&
			bigIntCmp(res, exp) == 0)
		{
			passed++;
			printSuccess("2^64 * 2^64 = 2^128");
		} else
			printFailure("2^64 * 2^64 = 2^128");
		total++;
		bigIntFree(a); bigIntFree(b); bigIntFree(res); bigIntFree(exp);
	}
	{
		/* a = 2^64, b = 2^64 - 1 */
		t_bigInt *a = bigIntFromHex("00000000000000010000000000000000", 2);
		t_bigInt *b = bigIntFromHex("FFFFFFFFFFFFFFFF", 1);
		t_bigInt *res = bigIntNew(4);
		t_bigInt *exp = bigIntFromHex("FFFFFFFFFFFFFFFF0000000000000000", 2);

		if (a && b && res && exp &&
			bigIntMul(res, a, b) &&
			bigIntCmp(res, exp) == 0)
		{
			passed++;
			printSuccess("2^64 * (2^64 - 1)");
		} else
			printFailure("2^64 * (2^64 - 1)");
		total++;
		bigIntFree(a); bigIntFree(b); bigIntFree(res); bigIntFree(exp);
	}
	{
		/* a = 0x100000001, b = 0x100000001 */
		t_bigInt *a = bigIntFromHex("100000001", 1);
		t_bigInt *b = bigIntFromHex("100000001", 1);
		t_bigInt *res = bigIntNew(3);
		/* (2^32 + 1)^2 = 2^64 + 2^33 + 1 */
		t_bigInt *exp = bigIntFromHex("10000000200000001", 2);

		if (a && b && res && exp &&
			bigIntMul(res, a, b) &&
			bigIntCmp(res, exp) == 0)
		{
			passed++;
			printSuccess("(2^32 + 1)^2");
		} else
			printFailure("(2^32 + 1)^2");
		total++;
		bigIntFree(a); bigIntFree(b); bigIntFree(res); bigIntFree(exp);
	}
	{
		t_bigInt *a = bigIntFromHex("FFFFFFFFFFFFFFFF", 1);
		t_bigInt *b = bigIntFromHex("FFFFFFFFFFFFFFFF", 1);
		t_bigInt *res = bigIntNew(1); /* capacité : 1 mot, besoin de 2 words minimum */

		if (a && b && res && bigIntMul(res, a, b) == NULL) {
			passed++;
			printSuccess("insufficient capacity -> NULL");
		} else
			printFailure("insufficient capacity -> NULL");
		total++;
		bigIntFree(a); bigIntFree(b); bigIntFree(res);
	}
	{
		t_bigInt *a = bigIntFromHex("FFFFFFFFFFFFFFFF", 1);
		t_bigInt *b = bigIntFromHex("FFFFFFFFFFFFFFFF", 1);
		t_bigInt *res = bigIntNew(2); /* exactement ce qu'il faut */
		t_bigInt *exp = bigIntFromHex("FFFFFFFFFFFFFFFE0000000000000001", 2);

		if (a && b && res && exp &&
			bigIntMul(res, a, b) != NULL &&
			bigIntCmp(res, exp) == 0)
		{
			passed++;
			printSuccess("exact capacity works");
		} else
			printFailure("exact capacity works");
		total++;
		bigIntFree(a); bigIntFree(b); bigIntFree(res); bigIntFree(exp);
	}
	{
		t_bigInt *a = bigIntFromUint64(1000);
		t_bigInt *b = bigIntFromUint64(2000);
		t_bigInt *res = bigIntNew(3);
		t_bigInt *expected = bigIntFromUint64(2000000);

		if (a && b && res && expected &&
			bigIntCopy(res, a) &&
			bigIntMul(res, res, b) &&
			bigIntCmp(res, expected) == 0)
		{
			passed++;
			printSuccess("aliasing res == a");
		} else
			printFailure("aliasing res == a");
		total++;
		bigIntFree(a); bigIntFree(b); bigIntFree(res); bigIntFree(expected);
	}
	{
		t_bigInt *a = bigIntFromUint64(1000);
		t_bigInt *b = bigIntFromUint64(2000);
		t_bigInt *res = bigIntNew(3);
		t_bigInt *expected = bigIntFromUint64(2000000);

		if (a && b && res && expected &&
			bigIntCopy(res, b) &&
			bigIntMul(res, a, res) &&
			bigIntCmp(res, expected) == 0)
		{
			passed++;
			printSuccess("aliasing res == b");
		} else 
			printFailure("aliasing res == b");
		total++;
		bigIntFree(a); bigIntFree(b); bigIntFree(res); bigIntFree(expected);
	}
	{
		t_bigInt *a = bigIntFromHex("DEADBEEFCAFEBABE1234567890ABCDEF", 3);
		t_bigInt *b = bigIntFromUint64(0);
		t_bigInt *res = bigIntNew(5);

		if (a && b && res &&
			bigIntMul(res, a, b) &&
			bigIntIsZero(res))
		{
			passed++;
			printSuccess("large mul by zero");
		} else
			printFailure("large mul by zero");
		total++;
		bigIntFree(a); bigIntFree(b); bigIntFree(res);
	}
	{
		t_bigInt *a = bigIntFromHex("1234567890ABCDEFFEDCBA0987654321", 2);
		t_bigInt *b = bigIntFromHex("FEDCBA09876543211234567890ABCDEF", 2);
		t_bigInt *res1 = bigIntNew(5);
		t_bigInt *res2 = bigIntNew(5);

		if (a && b && res1 && res2 &&
			bigIntMul(res1, a, b) &&
			bigIntMul(res2, b, a) &&
			bigIntCmp(res1, res2) == 0)
		{
			passed++;
			printSuccess("commutativity a*b == b*a");
		} else
			printFailure("commutativity a*b == b*a");
		total++;
		bigIntFree(a); bigIntFree(b); bigIntFree(res1); bigIntFree(res2);
	}
	{
		t_bigInt *a = bigIntFromHex("00000000000000010000000000000000", 2);
		t_bigInt *b = bigIntFromHex("123456789ABCDEF", 1);
		t_bigInt *res = bigIntNew(4);
		t_bigInt *exp = bigIntFromHex("123456789ABCDEF0000000000000000", 2);

		if (a && b && res && exp &&
			bigIntMul(res, a, b) &&
			bigIntCmp(res, exp) == 0)
		{
			passed++;
			printSuccess("multi-word * single-word shift");
		} else
			printFailure("multi-word * single-word shift");
		total++;
		bigIntFree(a); bigIntFree(b); bigIntFree(res); bigIntFree(exp);
	}
	{
		t_bigInt *a = bigIntFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 2);
		t_bigInt *b = bigIntFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 2);
		t_bigInt *res = bigIntNew(5);
		/* (2^128 - 1)^2 = 2^256 - 2^129 + 1 */
		t_bigInt *exp = bigIntFromHex(
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE00000000000000000000000000000001", 4);

		if (a && b && res && exp &&
			bigIntMul(res, a, b) &&
			bigIntCmp(res, exp) == 0)
		{
			passed++;
			printSuccess("(2^128 - 1) * (2^128 - 1)");
		} else
			printFailure("(2^128 - 1) * (2^128 - 1)");
		total++;
		bigIntFree(a); bigIntFree(b); bigIntFree(res); bigIntFree(exp);
	}

	g_totalTests  += total;
	g_passedTests += passed;
	return (passed == total);
}

int	testBigIntDivMod(void)
{
	int	passed = 0;
	int	total = 0;

	printInfo("Testing bigIntDiv() and bigIntMod()...");
	{
		t_bigInt *a = bigIntFromUint64(42);
		t_bigInt *b = bigIntFromUint64(0);
		t_bigInt *quot = bigIntNew(2);
		t_bigInt *rem = bigIntNew(2);

		if (a && b && quot && rem && bigIntDiv(quot, rem, a, b) == NULL) {
			passed++;
			printSuccess("division by zero returns NULL");
		} else
			printFailure("division by zero returns NULL");
		total++;
		bigIntFree(a); bigIntFree(b); bigIntFree(quot); bigIntFree(rem);
	}
	{
		t_bigInt *a = bigIntFromUint64(5);
		t_bigInt *b = bigIntFromUint64(10);
		t_bigInt *quot = bigIntNew(2);
		t_bigInt *rem = bigIntNew(2);
		t_bigInt *exp_quot = bigIntFromUint64(0);
		t_bigInt *exp_rem = bigIntFromUint64(5);

		if (a && b && quot && rem && exp_quot && exp_rem &&
			bigIntDiv(quot, rem, a, b) != NULL &&
			bigIntCmp(quot, exp_quot) == 0 &&
			bigIntCmp(rem, exp_rem) == 0)
		{
			passed++;
			printSuccess("a < b: quot=0, rem=a");
		} else
			printFailure("a < b: quot=0, rem=a");
		total++;
		bigIntFree(a); bigIntFree(b); bigIntFree(quot); bigIntFree(rem);
		bigIntFree(exp_quot); bigIntFree(exp_rem);
	}
	{
		t_bigInt *a = bigIntFromUint64(42);
		t_bigInt *b = bigIntFromUint64(42);
		t_bigInt *quot = bigIntNew(2);
		t_bigInt *rem = bigIntNew(2);
		t_bigInt *exp_quot = bigIntFromUint64(1);

		if (a && b && quot && rem && exp_quot &&
			bigIntDiv(quot, rem, a, b) != NULL &&
			bigIntCmp(quot, exp_quot) == 0 &&
			bigIntIsZero(rem))
		{
			passed++;
			printSuccess("a == b: quot=1, rem=0");
		} else
			printFailure("a == b: quot=1, rem=0");
		total++;
		bigIntFree(a); bigIntFree(b); bigIntFree(quot); bigIntFree(rem);
		bigIntFree(exp_quot);
	}
	{
		/* 2^128 / 2^64 = 2^64 */
		t_bigInt *a = bigIntFromHex("00000000000000010000000000000000", 2);
		t_bigInt *b = bigIntFromHex("00000000000000010000000000000000", 2);
		t_bigInt *quot = bigIntNew(3);
		t_bigInt *rem = bigIntNew(2);
		t_bigInt *exp_quot = bigIntFromUint64(1);

		if (a && b && quot && rem && exp_quot &&
			bigIntDiv(quot, rem, a, b) != NULL &&
			bigIntCmp(quot, exp_quot) == 0 &&
			bigIntIsZero(rem))
		{
			passed++;
			printSuccess("2-words / 2-words: 2^128 / 2^64 = 1");
		} else
			printFailure("2-words / 2-words: 2^128 / 2^64 = 1");
		total++;
		bigIntFree(a); bigIntFree(b); bigIntFree(quot); bigIntFree(rem);
		bigIntFree(exp_quot);
	}
	{
		/* (2^128 - 1) / 2^64 = 2^64 - 1, reste = 2^64 - 1 */
		t_bigInt *a = bigIntFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 2);
		t_bigInt *b = bigIntFromHex("00000000000000010000000000000000", 2);
		t_bigInt *quot = bigIntNew(3);
		t_bigInt *rem = bigIntNew(2);
		t_bigInt *exp_quot = bigIntFromHex("FFFFFFFFFFFFFFFF", 1);
		t_bigInt *exp_rem = bigIntFromHex("FFFFFFFFFFFFFFFF", 1);

		if (a && b && quot && rem && exp_quot && exp_rem &&
			bigIntDiv(quot, rem, a, b) != NULL &&
			bigIntCmp(quot, exp_quot) == 0 &&
			bigIntCmp(rem, exp_rem) == 0)
		{
			passed++;
			printSuccess("2-words / 2-words: (2^128-1) / 2^64");
		} else
			printFailure("2-words / 2-words: (2^128-1) / 2^64");
		total++;
		bigIntFree(a); bigIntFree(b); bigIntFree(quot); bigIntFree(rem);
		bigIntFree(exp_quot); bigIntFree(exp_rem);
	}
	{
		t_bigInt *a = bigIntFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 2);
		t_bigInt *b = bigIntFromHex("FFFFFFFFFFFFFFFF", 1);
		t_bigInt *quot = bigIntNew(4);
		t_bigInt *rem = bigIntNew(2);
		t_bigInt *exp_quot = bigIntFromHex("00000000000000010000000000000001", 2);

		if (a && b && quot && rem && exp_quot &&
			bigIntDiv(quot, rem, a, b) != NULL &&
			bigIntCmp(quot, exp_quot) == 0 &&
			bigIntIsZero(rem))
		{
			passed++;
			printSuccess("(2^128-1) / (2^64-1) = 2^64+1");
		} else
			printFailure("(2^128-1) / (2^64-1) = 2^64+1");
		total++;
		bigIntFree(a); bigIntFree(b); bigIntFree(quot); bigIntFree(rem);
		bigIntFree(exp_quot);
	}
	{
		/* a = 2^192 - 1, b = 2^128 - 1, quot = 2^64, rem = 2^64 - 1 */
		t_bigInt *a = bigIntFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 3);
		t_bigInt *b = bigIntFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 2);
		t_bigInt *quot = bigIntNew(4);
		t_bigInt *rem = bigIntNew(3);
		t_bigInt *exp_quot = bigIntFromHex("00000000000000010000000000000000", 2); // 2^64
		t_bigInt *exp_rem = bigIntFromHex("FFFFFFFFFFFFFFFF", 1); // 2^64-1

		if (a && b && quot && rem && exp_quot && exp_rem &&
			bigIntDiv(quot, rem, a, b) != NULL &&
			bigIntCmp(quot, exp_quot) == 0 &&
			bigIntCmp(rem, exp_rem) == 0)
		{
			passed++;
			printSuccess("3-words / 2-words: (2^192-1)/(2^128-1)=2^64, rem=2^64-1");
		} else
			printFailure("3-words / 2-words: (2^192-1)/(2^128-1)=2^64, rem=2^64-1");
		total++;
		bigIntFree(a); bigIntFree(b); bigIntFree(quot); bigIntFree(rem);
		bigIntFree(exp_quot); bigIntFree(exp_rem);
	}
	{
		/* a = 2^192, b = 2^64, quot = 2^128, rem = 0 */
		t_bigInt *a = bigIntFromHex("000000000000000100000000000000000000000000000000", 3);
		t_bigInt *b = bigIntFromHex("00000000000000010000000000000000", 2);
		t_bigInt *quot = bigIntNew(4);
		t_bigInt *rem = bigIntNew(3);
		t_bigInt *exp_quot = bigIntFromHex("00000000000000010000000000000000", 2);

		if (a && b && quot && rem && exp_quot &&
			bigIntDiv(quot, rem, a, b) != NULL &&
			bigIntCmp(quot, exp_quot) == 0 &&
			bigIntIsZero(rem))
		{
			passed++;
			printSuccess("2^192 / 2^64 = 2^128");
		} else
			printFailure("2^192 / 2^64 = 2^128");
		total++;
		bigIntFree(a); bigIntFree(b); bigIntFree(quot); bigIntFree(rem);
		bigIntFree(exp_quot);
	}
	{
		/* Cas où l'algorithme de Knuth doit corriger q_hat */
		t_bigInt *a = bigIntFromHex("80000000000000000000000000000000", 2);
		t_bigInt *b = bigIntFromHex("40000000000000000000000000000000", 2);
		t_bigInt *quot = bigIntNew(3);
		t_bigInt *rem = bigIntNew(2);
		t_bigInt *exp_quot = bigIntFromUint64(2);

		if (a && b && quot && rem && exp_quot &&
			bigIntDiv(quot, rem, a, b) != NULL &&
			bigIntCmp(quot, exp_quot) == 0 &&
			bigIntIsZero(rem))
		{
			passed++;
			printSuccess("q_hat correction case");
		} else
			printFailure("q_hat correction case");
		total++;
		bigIntFree(a); bigIntFree(b); bigIntFree(quot); bigIntFree(rem);
		bigIntFree(exp_quot);
	}
	{
		/* a = 2^128 + 1, b = 2^64, quot = 2^64, rem = 1 */
		t_bigInt *a = bigIntFromHex("00000000000000010000000000000001", 2);
		t_bigInt *b = bigIntFromHex("00000000000000010000000000000000", 2);
		t_bigInt *quot = bigIntNew(3);
		t_bigInt *rem = bigIntNew(2);
		t_bigInt *exp_quot = bigIntFromUint64(1);
		t_bigInt *exp_rem = bigIntFromUint64(1);

		if (a && b && quot && rem && exp_quot && exp_rem &&
			bigIntDiv(quot, rem, a, b) != NULL &&
			bigIntCmp(quot, exp_quot) == 0 &&
			bigIntCmp(rem, exp_rem) == 0)
		{
			passed++;
			printSuccess("multi-word remainder non-zero");
		} else
			printFailure("multi-word remainder non-zero");
		total++;
		bigIntFree(a); bigIntFree(b); bigIntFree(quot); bigIntFree(rem);
		bigIntFree(exp_quot); bigIntFree(exp_rem);
	}
	struct {
		const char *a_hex;
		const char *b_hex;
	} pairs[] = {
		{"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", "123456789ABCDEF"},
		{"DEADBEEFCAFEBABE1234567890ABCDEF", "FEDCBA0987654321"},
		{"1234567890ABCDEFFEDCBA0987654321", "10000000000000000"},
		{"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", "8000000000000000"},
		{"ABCDEF1234567890", "1234"},
	};
	for (size_t i = 0; i < sizeof(pairs)/sizeof(pairs[0]); i++) {
		t_bigInt *a = bigIntFromHex(pairs[i].a_hex, 0);
		t_bigInt *b = bigIntFromHex(pairs[i].b_hex, 0);
		t_bigInt *quot = bigIntNew(a->used + 2);
		t_bigInt *rem = bigIntNew(b->used + 2);
		t_bigInt *prod = bigIntNew(a->used + b->used + 2);
		t_bigInt *sum = bigIntNew(a->used + b->used + 2);

		if (a && b && quot && rem && prod && sum &&
			bigIntDiv(quot, rem, a, b) != NULL)
		{
			bigIntMul(prod, b, quot);
			bigIntAdd(sum, prod, rem);

			if (bigIntCmp(sum, a) == 0 && bigIntCmp(rem, b) < 0) {
				passed++;
				printSuccess("verify: a = b*q + r, r < b");
			} else
				printFailure("verify: a = b*q + r, r < b");
		} else
			printFailure("verify: a = b*q + r, r < b");
		total++;
		bigIntFree(a); bigIntFree(b); bigIntFree(quot); bigIntFree(rem);
		bigIntFree(prod); bigIntFree(sum);
	}
	{
		t_bigInt *a = bigIntFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 2);
		t_bigInt *m = bigIntFromHex("10000000000000000", 2);
		t_bigInt *res = bigIntNew(2);
		t_bigInt *exp = bigIntFromHex("FFFFFFFFFFFFFFFF", 1);

		if (a && m && res && exp &&
			bigIntMod(res, a, m) != NULL &&
			bigIntCmp(res, exp) == 0)
		{
			passed++;
			printSuccess("bigIntMod: 2^128-1 mod 2^64 = 2^64-1");
		} else
			printFailure("bigIntMod: 2^128-1 mod 2^64 = 2^64-1");
		total++;
		bigIntFree(a); bigIntFree(m); bigIntFree(res); bigIntFree(exp);
	}

	{
		t_bigInt *a = bigIntFromHex("1234567890ABCDEF", 1);
		t_bigInt *m = bigIntFromHex("100000000", 1);
		t_bigInt *res = bigIntNew(2);
		t_bigInt *exp = bigIntFromHex("90ABCDEF", 1);

		if (a && m && res && exp &&
			bigIntMod(res, a, m) != NULL &&
			bigIntCmp(res, exp) == 0)
		{
			passed++;
			printSuccess("bigIntMod: 0x1234567890ABCDEF mod 0x100000000");
		} else
			printFailure("bigIntMod: 0x1234567890ABCDEF mod 0x100000000");
		total++;
		bigIntFree(a); bigIntFree(m); bigIntFree(res); bigIntFree(exp);
	}
	{
		t_bigInt *a = bigIntFromUint64(42);
		t_bigInt *m = bigIntFromUint64(0);
		t_bigInt *res = bigIntNew(2);

		if (a && m && res && bigIntMod(res, a, m) == NULL) {
			passed++;
			printSuccess("bigIntMod with zero modulus returns NULL");
		} else
			printFailure("bigIntMod with zero modulus returns NULL");
		total++;
		bigIntFree(a); bigIntFree(m); bigIntFree(res);
	}
	{
		t_bigInt *a = bigIntFromUint64(5);
		t_bigInt *m = bigIntFromUint64(10);
		t_bigInt *res = bigIntNew(2);
		t_bigInt *exp = bigIntFromUint64(5);

		if (a && m && res && exp &&
			bigIntMod(res, a, m) != NULL &&
			bigIntCmp(res, exp) == 0)
		{
			passed++;
			printSuccess("bigIntMod a < m returns a");
		} else
			printFailure("bigIntMod a < m returns a");
		total++;
		bigIntFree(a); bigIntFree(m); bigIntFree(res); bigIntFree(exp);
	}

	g_totalTests  += total;
	g_passedTests += passed;
	return (passed == total);
}

/**
 * Test all modular arithmetic functions with known values.
 * No reference implementations, only pre‑computed expected results.
 */
int testModularArithmetic(void)
{
	int passed = 0;
	int total = 0;
	printInfo("Testing modular arithmetic (MulMod, ModExp, ModInverse, Gcd)...");

	/* ---------- bigIntMulMod ---------- */
	{
		struct {
			uint64_t a, b, m;
			uint64_t expected;
		} vectors[] = {
			{0, 5, 7, 0},
			{1, 1, 100, 1},
			{5, 3, 7, 1},	/* 15 mod 7 = 1 */
			{100, 200, 999, 20000 % 999},
			{0xFFFFFFFFFFFFFFFFULL, 1, 0xFFFFFFFFFFFFFFFFULL, 0},
			{0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0},
		};
		for (size_t i = 0; i < sizeof(vectors)/sizeof(vectors[0]); i++) {
			t_bigInt *a = bigIntFromUint64(vectors[i].a);
			t_bigInt *b = bigIntFromUint64(vectors[i].b);
			t_bigInt *m = bigIntFromUint64(vectors[i].m);
			t_bigInt *res = bigIntNew(3);
			t_bigInt *exp = bigIntFromUint64(vectors[i].expected);
			if (a && b && m && res && exp &&
				bigIntMulMod(res, a, b, m) &&
				bigIntCmp(res, exp) == 0) {
				passed++; printSuccess("MulMod single‑word");
			} else {
				printFailure("MulMod single‑word");
			}
			total++;
			bigIntFree(a); bigIntFree(b); bigIntFree(m); bigIntFree(res); bigIntFree(exp);
		}
		/* Multi‑word test: (2^128 - 1) * (2^128 - 1) mod (2^128) = 1 */
		{
			t_bigInt *a = bigIntFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 2);
			t_bigInt *b = bigIntFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 2);
			t_bigInt *m = bigIntFromHex("00000001000000000000000000000000", 2); /* 2^128 */
			t_bigInt *res = bigIntNew(4);
			t_bigInt *exp = bigIntFromUint64(1);
			if (a && b && m && res && exp &&
				bigIntMulMod(res, a, b, m) &&
				bigIntCmp(res, exp) == 0) {
				passed++; printSuccess("MulMod multi‑word (2^128-1)^2 mod 2^128 = 1");
			} else {
				printFailure("MulMod multi‑word");
			}
			total++;
			bigIntFree(a); bigIntFree(b); bigIntFree(m); bigIntFree(res); bigIntFree(exp);
		}
		/* Modulus zero -> NULL */
		{
			t_bigInt *a = bigIntFromUint64(42);
			t_bigInt *b = bigIntFromUint64(42);
			t_bigInt *m = bigIntFromUint64(0);
			t_bigInt *res = bigIntNew(2);
			if (a && b && m && res && bigIntMulMod(res, a, b, m) == NULL) {
				passed++; printSuccess("MulMod mod zero -> NULL");
			} else {
				printFailure("MulMod mod zero -> NULL");
			}
			total++;
			bigIntFree(a); bigIntFree(b); bigIntFree(m); bigIntFree(res);
		}
	}

	/* ---------- bigIntModExp ---------- */
	{
		struct {
			uint64_t base, exp, mod;
			uint64_t expected;
		} vectors[] = {
			{0, 0, 100, 1},		/* 0^0 mod m = 1 */
			{0, 5, 100, 0},
			{1, 0, 100, 1},
			{2, 10, 100, 24},	/* 2^10 = 1024, 1024 mod 100 = 24 */
			{3, 5, 7, 5},		/* 3^5 = 243, 243 mod 7 = 5 */
			{7, 3, 13, 5},		/* 7^3 = 343, 343 mod 13 = 5 */
			{5, 7, 23, 17},		/* 5^7 = 78125, 78125 mod 23 = 17 */
		};
		for (size_t i = 0; i < sizeof(vectors)/sizeof(vectors[0]); i++) {
			t_bigInt *base = bigIntFromUint64(vectors[i].base);
			t_bigInt *exp  = bigIntFromUint64(vectors[i].exp);
			t_bigInt *mod  = bigIntFromUint64(vectors[i].mod);
			t_bigInt *res  = bigIntNew(3);
			t_bigInt *expected = bigIntFromUint64(vectors[i].expected);
			if (base && exp && mod && res && expected &&
				bigIntModExp(res, base, exp, mod) &&
				bigIntCmp(res, expected) == 0) {
				passed++; printSuccess("ModExp small");
			} else {
				printFailure("ModExp small");
			}
			total++;
			bigIntFree(base); bigIntFree(exp); bigIntFree(mod); bigIntFree(res); bigIntFree(expected);
		}
		/* Modulus 1 -> result must be 0 (except 0^0? 0^0 mod1 = 0 usually) */
		{
			t_bigInt *base = bigIntFromUint64(123456);
			t_bigInt *exp  = bigIntFromUint64(789);
			t_bigInt *mod  = bigIntFromUint64(1);
			t_bigInt *res  = bigIntNew(2);
			if (base && exp && mod && res &&
				bigIntModExp(res, base, exp, mod) &&
				bigIntIsZero(res)) {
				passed++; printSuccess("ModExp mod 1 -> 0");
			} else {
				printFailure("ModExp mod 1 -> 0");
			}
			total++;
			bigIntFree(base); bigIntFree(exp); bigIntFree(mod); bigIntFree(res);
		}
	}

	/* ---------- bigIntModInverse ---------- */
	{
		struct {
			uint64_t a, m;
			uint64_t expected;  /* 0 means "no inverse" */
		} vectors[] = {
			{1, 7, 1},
			{2, 5, 3},	/* 2*3=6 ≡ 1 mod5 */
			{3, 7, 5},	/* 3*5=15 ≡ 1 mod7 */
			{4, 9, 7},	/* 4*7=28 ≡ 1 mod9 */
			{5, 12, 5},	/* 5*5=25 ≡ 1 mod12 */
			{6, 9, 0},	/* gcd(6,9)=3 ≠ 1 -> no inverse */
			{0, 7, 0},	/* zero has no inverse */
		};
		for (size_t i = 0; i < sizeof(vectors)/sizeof(vectors[0]); i++) {
			t_bigInt *a = bigIntFromUint64(vectors[i].a);
			t_bigInt *m = bigIntFromUint64(vectors[i].m);
			t_bigInt *res = bigIntNew(3);
			if (vectors[i].expected == 0) {
				if (a && m && res && bigIntModInverse(res, a, m) == NULL) {
					passed++; printSuccess("ModInverse no inverse -> NULL");
				} else {
					printFailure("ModInverse no inverse -> NULL");
				}
			} else {
				t_bigInt *exp = bigIntFromUint64(vectors[i].expected);
				if (a && m && res && exp &&
					bigIntModInverse(res, a, m) &&
					bigIntCmp(res, exp) == 0) {
					passed++; printSuccess("ModInverse valid");
				} else {
					printFailure("ModInverse valid");
				}
				bigIntFree(exp);
			}
			total++;
			bigIntFree(a); bigIntFree(m); bigIntFree(res);
		}
	}

	/* ---------- bigIntGcd ---------- */
	{
		struct {
			uint64_t a, b;
			uint64_t expected;
		} vectors[] = {
			{0, 5, 5},
			{5, 0, 5},
			{12, 18, 6},
			{100, 25, 25},
			{123456, 789012, 12},
			{0xFFFFFFFFFFFFFFFFULL, 0x8000000000000000ULL, 1},
			{0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL},
		};
		for (size_t i = 0; i < sizeof(vectors)/sizeof(vectors[0]); i++) {
			t_bigInt *a = bigIntFromUint64(vectors[i].a);
			t_bigInt *b = bigIntFromUint64(vectors[i].b);
			t_bigInt *res = bigIntNew(3);
			t_bigInt *exp = bigIntFromUint64(vectors[i].expected);
			if (a && b && res && exp &&
				bigIntGcd(res, a, b) &&
				bigIntCmp(res, exp) == 0) {
				passed++; printSuccess("Gcd basic");
			} else {
				printFailure("Gcd basic");
			}
			total++;
			bigIntFree(a); bigIntFree(b); bigIntFree(res); bigIntFree(exp);
		}
		/* Multi‑word test: gcd(2^128, 2^128 - 1) = 1 */
		{
			t_bigInt *a = bigIntFromHex("00000001000000000000000000000000", 2); /* 2^128 */
			t_bigInt *b = bigIntFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 2); /* 2^128-1 */
			t_bigInt *res = bigIntNew(4);
			t_bigInt *one = bigIntFromUint64(1);
			if (a && b && res && one &&
				bigIntGcd(res, a, b) &&
				bigIntCmp(res, one) == 0) {
				passed++; printSuccess("Gcd multi‑word (coprime)");
			} else {
				printFailure("Gcd multi‑word (coprime)");
			}
			total++;
			bigIntFree(a); bigIntFree(b); bigIntFree(res); bigIntFree(one);
		}
	}

	g_totalTests += total;
	g_passedTests += passed;
	return (passed == total);
}
