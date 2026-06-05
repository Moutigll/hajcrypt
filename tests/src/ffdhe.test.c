#include <stdlib.h>

#include "../../hajlib/include/hprintf.h"
#include "../../hajlib/include/hmemory.h"
#include "../../includes/asymmetric/ffdhe.h"

#include "../test.h"

int	testFfdheGenerateKeypair(void)
{
	int		passed = 0;
	int		total = 0;
	t_ffdheCtx	ctx;

	printInfo("Testing FFDHE generate keypair...");

	if (!ffdheInit(&ctx, FFDHE_GROUP_2048))
	{
		printFailure("ffdheInit failed");
		g_totalTests += 1;
		return (0);
	}

	/* Generate keypair */
	total++;
	if (ffdheGenerateKeypair(&ctx))
	{
		passed++;
		printSuccess("ffdheGenerateKeypair success");
	}
	else
		printFailure("ffdheGenerateKeypair failed");

	total++;
	if (ctx.priv && ctx.pub)
	{
		passed++;
		printSuccess("priv and pub not NULL");
	}
	else
		printFailure("priv or pub is NULL");

	total++;
	if (!bigIntIsZero(ctx.pub))
	{
		passed++;
		printSuccess("public key not zero");
	}
	else
		printFailure("public key is zero");

	ffdheFree(&ctx);

	ft_printf("FFDHE generate keypair: %d/%d passed\n", passed, total);
	g_totalTests += total;
	g_passedTests += passed;
	return (passed == total);
}

int	testFfdheGetPublicBytes(void)
{
	int			passed = 0;
	int			total = 0;
	t_ffdheCtx	ctx;
	uint8_t		buf[512];
	size_t		len;
	size_t		len2;
	int			ret;

	printInfo("Testing FFDHE get public bytes...");

	if (!ffdheInit(&ctx, FFDHE_GROUP_2048))
	{
		printFailure("ffdheInit failed");
		g_totalTests += 1;
		return (0);
	}

	if (!ffdheGenerateKeypair(&ctx))
	{
		printFailure("ffdheGenerateKeypair failed");
		ffdheFree(&ctx);
		g_totalTests += 1;
		return (0);
	}

	/* Test query length */
	len = 0;
	ret = ffdheGetPublicBytes(&ctx, NULL, &len);
	total++;
	if (ret && len > 0)
	{
		passed++;
		printSuccess("ffdheGetPublicBytes query length");
	}
	else
		printFailure("ffdheGetPublicBytes query length");

	/* Test actual export */
	len2 = sizeof(buf);
	ret = ffdheGetPublicBytes(&ctx, buf, &len2);
	total++;
	if (ret && len2 > 0 && len2 <= sizeof(buf))
	{
		passed++;
		printSuccess("ffdheGetPublicBytes actual");
	}
	else
		printFailure("ffdheGetPublicBytes actual");

	ffdheFree(&ctx);

	ft_printf("FFDHE get public bytes: %d/%d passed\n", passed, total);
	g_totalTests += total;
	g_passedTests += passed;
	return (passed == total);
}

static int	testFfdheGroup(int groupId, const char *groupName, size_t bufSize)
{
	int			passed = 0;
	t_ffdheCtx	alice;
	t_ffdheCtx	bob;
	uint8_t		*alicePub;
	uint8_t		*bobPub;
	uint8_t		*aliceShared;
	uint8_t		*bobShared;
	size_t		alicePubLen;
	size_t		bobPubLen;
	size_t		aliceSharedLen;
	size_t		bobSharedLen;
	int			ret;

	alicePub = ft_calloc(1, bufSize);
	bobPub = ft_calloc(1, bufSize);
	aliceShared = ft_calloc(1, bufSize);
	bobShared = ft_calloc(1, bufSize);
	if (!alicePub || !bobPub || !aliceShared || !bobShared)
	{
		printFailure("Buffer allocation failed");
		free(alicePub);
		free(bobPub);
		free(aliceShared);
		free(bobShared);
		return (0);
	}

	if (!ffdheInit(&alice, groupId))
	{
		printFailure("Alice init");
		goto cleanup;
	}

	if (!ffdheInit(&bob, groupId))
	{
		printFailure("Bob init");
		ffdheFree(&alice);
		goto cleanup;
	}

	if (ffdheGenerateKeypair(&alice) && ffdheGenerateKeypair(&bob))
	{
		passed++;
		printSuccess("Both keypairs generated");
	}
	else
		printFailure("Keypair generation failed");

	alicePubLen = bufSize;
	bobPubLen = bufSize;
	ret = ffdheGetPublicBytes(&alice, alicePub, &alicePubLen) &&
		  ffdheGetPublicBytes(&bob, bobPub, &bobPubLen);
	if (ret)
	{
		passed++;
		printSuccess("Get public bytes");
	}
	else
	{
		printFailure("Get public bytes failed");
		goto cleanupCtx;
	}

	aliceSharedLen = bufSize;
	bobSharedLen = bufSize;
	ret = ffdheComputeShared(&alice, bobPub, bobPubLen,
							 aliceShared, &aliceSharedLen) &&
		  ffdheComputeShared(&bob, alicePub, alicePubLen,
							 bobShared, &bobSharedLen);
	if (ret)
	{
		passed++;
		printSuccess("Shared secrets computed");
	}
	else
	{
		printFailure("Shared secret computation failed");
		goto cleanupCtx;
	}

	if (aliceSharedLen == bobSharedLen &&
		ft_memcmp(aliceShared, bobShared, aliceSharedLen) == 0)
	{
		passed++;
		printSuccess("Shared secrets match");
	}
	else
		printFailure("Shared secrets mismatch");

cleanupCtx:
	ffdheFree(&alice);
	ffdheFree(&bob);

cleanup:
	free(alicePub);
	free(bobPub);
	free(aliceShared);
	free(bobShared);

	ft_printf("FFDHE exchange %s: %d/%d passed\n", groupName, passed, 4);
	g_totalTests += 4;
	g_passedTests += passed;
	return (passed == 4);
}

int	testFfdheExchange(void)
{
	int passed = 0;

	if (testFfdheGroup(FFDHE_GROUP_2048, "2048", 256))
		passed++;
	if (testFfdheGroup(FFDHE_GROUP_3072, "3072", 384))
		passed++;
	if (testFfdheGroup(FFDHE_GROUP_4096, "4096", 512))
		passed++;
	if (testFfdheGroup(FFDHE_GROUP_6144, "6144", 768))
		passed++;
	if (testFfdheGroup(FFDHE_GROUP_8192, "8192", 1024))
		passed++;

	return (passed == 5);
}

int	testFfdheFreeZeroing(void)
{
	int		passed = 0;
	int		total = 0;
	t_ffdheCtx	ctx;

	printInfo("Testing FFDHE free zeroing...");

	if (!ffdheInit(&ctx, FFDHE_GROUP_2048))
	{
		printFailure("ffdheInit failed");
		g_totalTests += 1;
		return (0);
	}

	if (!ffdheGenerateKeypair(&ctx))
	{
		printFailure("ffdheGenerateKeypair failed");
		ffdheFree(&ctx);
		g_totalTests += 1;
		return (0);
	}

	ffdheFree(&ctx);

	total++;
	if (ctx.p == NULL && ctx.g == NULL && ctx.priv == NULL &&
		ctx.pub == NULL && ctx.shared == NULL)
	{
		passed++;
		printSuccess("All pointers NULL after free");
	}
	else
		printFailure("Some pointers not NULL after free");

	total++;
	if (ctx.groupId == 0)
	{
		passed++;
		printSuccess("groupId zeroed");
	}
	else
		printFailure("groupId not zeroed");

	ft_printf("FFDHE free zeroing: %d/%d passed\n", passed, total);
	g_totalTests += total;
	g_passedTests += passed;
	return (passed == total);
}

int	testFfdheGetGroupParams(void)
{
	int			passed = 0;
	int			total = 0;
	const char	*pHex;
	const char	*gHex;
	int			ret;

	printInfo("Testing FFDHE getGroupParams...");

	/* Test 2048 */
	ret = getGroupParams(FFDHE_GROUP_2048, &pHex, &gHex);
	total++;
	if (ret && pHex != NULL && gHex != NULL)
	{
		passed++;
		printSuccess("getGroupParams 2048");
	}
	else
		printFailure("getGroupParams 2048");

	/* Test 3072 */
	ret = getGroupParams(FFDHE_GROUP_3072, &pHex, &gHex);
	total++;
	if (ret && pHex != NULL && gHex != NULL)
	{
		passed++;
		printSuccess("getGroupParams 3072");
	}
	else
		printFailure("getGroupParams 3072");

	/* Test invalid group */
	ret = getGroupParams(9999, &pHex, &gHex);
	total++;
	if (!ret)
	{
		passed++;
		printSuccess("getGroupParams invalid group rejected");
	}
	else
		printFailure("getGroupParams invalid group accepted");

	ft_printf("FFDHE getGroupParams: %d/%d passed\n", passed, total);
	g_totalTests += total;
	g_passedTests += passed;
	return (passed == total);
}
