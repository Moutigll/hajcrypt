#include "../../hajlib/include/hmemory.h"
#include "../../hajlib/include/hprintf.h"
#include "../../hajlib/include/hstring.h"

#include "../../includes/kdf/bcrypt.h"
#include "../test.h"

typedef struct s_bcryptVector {
	const char	*password;
	const char  *salt_b64;
	uint32_t	cost;
	const char	*expected;
} t_bcryptVector;

static const t_bcryptVector bcryptVectors[] = {
	{ "",							"......................", 4,
	  "$2b$04$......................w74bL5gU7LSJClZClCa.Pkz14aTv/XO" },
	{ "a",						   "......................", 4,
	  "$2b$04$......................ab4uk7zdS0i/IlhKXBIf8klDpk4gLJu" },
	{ "abc",						 "......................", 4,
	  "$2b$04$......................ini1L2hXWkegMV822DC6vks..mWmZHK" },
	{ "password",					"......................", 4,
	  "$2b$04$......................LAtw7/ohmmBAhnXqmkuIz83Rl5Qdjhm" },
	{ "password",		 "Oo4L1LHqi2o7M7U5FwJQ4e", 5,
	  "$2b$05$Oo4L1LHqi2o7M7U5FwJQ4eyePa8PikHpU8XyqzDS8pFiXvklYR3Ye" },
	{ "correct horse battery staple", "rDiqH3V5a0F1XyB2PwL8Ne", 6,
	  "$2b$06$rDiqH3V5a0F1XyB2PwL8NekKIUeQkOZrKKd/.SR.lySVCU8nHnKhK" },
	{ NULL, NULL, 0, NULL }
};

int testBcryptHash(void)
{
	int passed = 0, total = 0;
	printInfo("Testing bcryptHash...");

	for (int i = 0; bcryptVectors[i].password != NULL; i++)
	{
		char	output[64]; /* 61 needed; 64 for alignment */
		uint8_t	salt_bytes[BCRYPT_SALT_LEN];
		int		ret;

		total++;
		if (bcryptDecodeBase64(salt_bytes, bcryptVectors[i].salt_b64,
							   BCRYPT_SALT_LEN) != BCRYPT_SALT_LEN) {
			printFailure("bcryptDecodeBase64 failed");
			continue;
		}

		ret = bcryptHash(bcryptVectors[i].password, salt_bytes,
						 bcryptVectors[i].cost, output);
		if (ret != 0) {
			printFailure("bcryptHash returned error");
			continue;
		}

		if (ft_strcmp(output, bcryptVectors[i].expected) == 0) {
			passed++;
			printSuccess("Hash matches expected");
		} else {
			printFailure("Hash mismatch");
			ft_printf("Got:	  %s\nExpected: %s\n",
					  output, bcryptVectors[i].expected);
		}
	}

	ft_printf("bcryptHash: %d/%d passed\n", passed, total);
	g_totalTests  += total;
	g_passedTests += passed;
	return (passed == total);
}

int testBcryptVerify(void)
{
	int passed = 0, total = 0;
	printInfo("Testing bcryptVerify...");

	for (int i = 0; bcryptVectors[i].password != NULL; i++)
	{
		int match;

		total++;
		match = bcryptVerify(bcryptVectors[i].password,
							 bcryptVectors[i].expected);
		if (match == 0) {
			passed++;
			printSuccess("Correct password verified");
		} else
			printFailure("Correct password rejected");

		total++;
		match = bcryptVerify("wrongpassword", bcryptVectors[i].expected);
		if (match != 0) {
			passed++;
			printSuccess("Wrong password rejected");
		} else {
			printFailure("Wrong password accepted");
		}
	}

	ft_printf("bcryptVerify: %d/%d passed\n", passed, total);
	g_totalTests  += total;
	g_passedTests += passed;
	return (passed == total);
}

int testBcryptGenSalt(void)
{
	int		passed = 0, total = 0;
	uint8_t	salt1[BCRYPT_SALT_LEN];
	uint8_t	salt2[BCRYPT_SALT_LEN];
	uint8_t	zeros[BCRYPT_SALT_LEN];

	printInfo("Testing bcryptGenSalt...");
	ft_bzero(zeros, sizeof(zeros));

	total++;
	if (bcryptGenSalt(salt1) == 0) {
		passed++;
		printSuccess("First salt generated");
	} else {
		printFailure("bcryptGenSalt failed");
		goto cleanup;
	}

	total++;
	if (bcryptGenSalt(salt2) == 0) {
		passed++;
		printSuccess("Second salt generated");
	} else {
		printFailure("bcryptGenSalt failed");
		goto cleanup;
	}

	total++;
	if (ft_memcmp(salt1, zeros, BCRYPT_SALT_LEN) != 0) {
		passed++;
		printSuccess("First salt is non-zero");
	} else
		printFailure("First salt is all zeros");

	total++;
	if (ft_memcmp(salt1, salt2, BCRYPT_SALT_LEN) != 0) {
		passed++;
		printSuccess("Salts are different");
	} else
		printFailure("Salts are identical");

cleanup:
	ft_printf("bcryptGenSalt: %d/%d passed\n", passed, total);
	g_totalTests  += total;
	g_passedTests += passed;
	return (passed == total);
}

/* ============================================================================
 * testBcryptEdgeCases — boundary / error-path coverage
 * ========================================================================== */
int testBcryptEdgeCases(void)
{
	int		passed = 0, total = 0;
	char	output[BCRYPT_STRING_LEN];
	uint8_t	salt[BCRYPT_SALT_LEN];
	int		ret;
	char	longpass[80];

	printInfo("Testing bcrypt edge cases...");
	ft_bzero(salt, sizeof(salt));

	/* Cost below minimum */
	total++;
	ret = bcryptHash("pass", salt, BCRYPT_COST_MIN - 1, output);
	if (ret != 0) { passed++; printSuccess("Cost below minimum rejected"); }
	else		  { printFailure("Cost below minimum accepted"); }

	/* Cost above maximum */
	total++;
	ret = bcryptHash("pass", salt, BCRYPT_COST_MAX + 1, output);
	if (ret != 0) { passed++; printSuccess("Cost above maximum rejected"); }
	else		  { printFailure("Cost above maximum accepted"); }

	/* Password at truncation boundary — must still hash successfully */
	total++;
	ft_memset(longpass, 'x', 79);
	longpass[79] = '\0';
	ret = bcryptHash(longpass, salt, 4, output);
	if (ret == 0) { passed++; printSuccess("Long password handled"); }
	else		  { printFailure("Long password rejected"); }

	/* Invalid hash string in bcryptVerify */
	total++;
	ret = bcryptVerify("pass", "$2b$04$invalidhash");
	if (ret != 0) { passed++; printSuccess("Invalid hash rejected by verify"); }
	else		  { printFailure("Invalid hash accepted by verify"); }

	/* Hash string too short */
	total++;
	ret = bcryptVerify("pass", "$2b$04$short");
	if (ret != 0) { passed++; printSuccess("Short hash rejected"); }
	else		  { printFailure("Short hash accepted"); }

	/* NULL password */
	total++;
	ret = bcryptHash(NULL, salt, 4, output);
	if (ret != 0) { passed++; printSuccess("NULL password rejected"); }
	else		  { printFailure("NULL password accepted"); }

	/* NULL salt */
	total++;
	ret = bcryptHash("pass", NULL, 4, output);
	if (ret != 0) { passed++; printSuccess("NULL salt rejected"); }
	else		  { printFailure("NULL salt accepted"); }

	ft_printf("bcrypt edge cases: %d/%d passed\n", passed, total);
	g_totalTests  += total;
	g_passedTests += passed;
	return (passed == total);
}

int testBcryptHashWithSaltStr(void)
{
	int		passed = 0, total = 0;
	char	output[BCRYPT_STRING_LEN];
	int		ret;

	printInfo("Testing bcryptHashWithSalt...");

	total++;
	ret = bcryptHashWithSalt("testpass", "Oo4L1LHqi2o7M7U5FwJQ4e", 5, output);
	if (ret == 0) {
		passed++;
		printSuccess("bcryptHashWithSalt succeeded");

		/* Hash must start with the expected $2b$05$<salt> prefix */
		total++;
		if (ft_strncmp(output, "$2b$05$Oo4L1LHqi2o7M7U5FwJQ4e", 29) == 0) {
			passed++;
			printSuccess("Hash prefix matches");
		} else {
			printFailure("Hash prefix mismatch");
			ft_printf("Got: %s\n", output);
		}
	} else
		printFailure("bcryptHashWithSalt failed");

	/* Salt string too short — must be rejected */
	total++;
	ret = bcryptHashWithSalt("pass", "short", 5, output);
	if (ret != 0) {
		passed++;
		printSuccess("Invalid salt string rejected");
	} else
		printFailure("Invalid salt string accepted");

	ft_printf("bcryptHashWithSalt: %d/%d passed\n", passed, total);
	g_totalTests  += total;
	g_passedTests += passed;
	return (passed == total);
}
