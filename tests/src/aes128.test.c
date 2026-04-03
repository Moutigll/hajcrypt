#include "../../hajlib/include/hmath.h"
#include "../../hajlib/include/hmemory.h"
#include "../../hajlib/include/hprintf.h"
#include "../../hajlib/include/hstring.h"

#include "../../includes/cipher/aes.h"
#include "../test.h"
#include <stdio.h>

/* ============================================================================
 * AES-128 Test Vectors
 * ============================================================================ */

static const struct {
	const char	*key;
	const char	*plaintext;
	const char	*ciphertext;
} aes128EcbVectors[] = {
	{
		"00000000000000000000000000000000",
		"00000000000000000000000000000000",
		"66e94bd4ef8a2c3b884cfa59ca342b2e"
	},
	{
		"ffffffffffffffffffffffffffffffff",
		"00000000000000000000000000000000",
		"a1f6258c877d5fcd8964484538bfc92c"
	},
	{
		"00112233445566778899aabbccddeeff",
		"000102030405060708090a0b0c0d0e0f",
		"279fb74a7572135e8f9b8ef6d1eee003"
	},
	{
		"2b7e151628aed2a6abf7158809cf4f3c",
		"6bc1bee22e409f96e93d7e117393172a",
		"3ad77bb40d7a3660a89ecaf32466ef97"
	},
	{
		"000102030405060708090a0b0c0d0e0f",
		"00112233445566778899aabbccddeeff",
		"69c4e0d86a7b0430d8cdb78070b4c55a"
	},
	{ NULL, NULL, NULL }
};

static const struct {
	const char	*key;
	const char	*iv;
	const char	*plaintext;
	const char	*ciphertext;
} aes128CbcVectors[] = {
	{
		"00000000000000000000000000000000",
		"00000000000000000000000000000000",
		"00000000000000000000000000000000",
		"66e94bd4ef8a2c3b884cfa59ca342b2e"
	},
	{
		"ffffffffffffffffffffffffffffffff",
		"00000000000000000000000000000000",
		"00000000000000000000000000000000",
		"a1f6258c877d5fcd8964484538bfc92c"
	},
	{
		"00112233445566778899aabbccddeeff",
		"102030405060708090a0b0c0d0e0f001",
		"000102030405060708090a0b0c0d0e0f",
		"854f06d0f45a50b6a1081e819820a86c"
	},
	{
		"2b7e151628aed2a6abf7158809cf4f3c",
		"000102030405060708090a0b0c0d0e0f",
		"6bc1bee22e409f96e93d7e117393172a",
		"7649abac8119b246cee98e9b12e9197d"
	},
	{
		"000102030405060708090a0b0c0d0e0f",
		"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
		"00112233445566778899aabbccddeeff",
		"7702fc9b71c63d26a2f09df5c445102a"
	},
	{ NULL, NULL, NULL, NULL }
};

static const struct {
	const char	*key;
	const char	*iv;
	const char	*plaintext;
	const char	*ciphertext;
} aes128CfbVectors[] = {
	{
		"00000000000000000000000000000000",
		"00000000000000000000000000000000",
		"00000000000000000000000000000000",
		"66e94bd4ef8a2c3b884cfa59ca342b2e"
	},
	{
		"ffffffffffffffffffffffffffffffff",
		"00000000000000000000000000000000",
		"00000000000000000000000000000000",
		"a1f6258c877d5fcd8964484538bfc92c"
	},
	{
		"00112233445566778899aabbccddeeff",
		"102030405060708090a0b0c0d0e0f001",
		"000102030405060708090a0b0c0d0e0f",
		"b4c7efcc8622c13c5edea1b61633bf40"
	},
	{
		"2b7e151628aed2a6abf7158809cf4f3c",
		"000102030405060708090a0b0c0d0e0f",
		"6bc1bee22e409f96e93d7e117393172a",
		"3b3fd92eb72dad20333449f8e83cfb4a"
	},
	{
		"000102030405060708090a0b0c0d0e0f",
		"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
		"00112233445566778899aabbccddeeff",
		"66b6e5db7007573f1fc874bcffcb4352"
	},
	{ NULL, NULL, NULL, NULL }
};

static const struct {
	const char	*key;
	const char	*iv;
	const char	*plaintext;
	const char	*ciphertext;
} aes128Cfb8Vectors[] = {
	{
		"00000000000000000000000000000000",
		"00000000000000000000000000000000",
		"00000000000000000000000000000000",
		"6616f92e42a8f11a911668578ec3aa0f"
	},
	{
		"ffffffffffffffffffffffffffffffff",
		"00000000000000000000000000000000",
		"00000000000000000000000000000000",
		"a143afec3e68c65f691408c3e74314fc"
	},
	{
		"00112233445566778899aabbccddeeff",
		"102030405060708090a0b0c0d0e0f001",
		"000102030405060708090a0b0c0d0e0f",
		"b4c1cf3f4396094e1b6348a4ed3bedd4"
	},
	{
		"2b7e151628aed2a6abf7158809cf4f3c",
		"000102030405060708090a0b0c0d0e0f",
		"6bc1bee22e409f96e93d7e117393172a",
		"3b79424c9c0dd436bace9e0ed4586a4f"
	},
	{
		"000102030405060708090a0b0c0d0e0f",
		"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
		"00112233445566778899aabbccddeeff",
		"66ae2b061cce426197cbc31e1b871f0f"
	},
	{ NULL, NULL, NULL, NULL }
};

static const struct {
	const char	*key;
	const char	*iv;
	const char	*plaintext;
	const char	*ciphertext;
} aes128Cfb1Vectors[] = {
	{
		"00000000000000000000000000000000",
		"00000000000000000000000000000000",
		"00000000000000000000000000000000",
		"00000000000000000000000000000000"
	},
	{
		"ffffffffffffffffffffffffffffffff",
		"00000000000000000000000000000000",
		"00000000000000000000000000000000",
		"8d5e997f9d3996a5715f706d4adb2376"
	},
	{
		"00112233445566778899aabbccddeeff",
		"102030405060708090a0b0c0d0e0f001",
		"000102030405060708090a0b0c0d0e0f",
		"c1d415e7da6e162034666e5f615d6398"
	},
	{
		"2b7e151628aed2a6abf7158809cf4f3c",
		"000102030405060708090a0b0c0d0e0f",
		"6bc1bee22e409f96e93d7e117393172a",
		"68b3a264f838f5f8c3101070d1ab4c2e"
	},
	{
		"000102030405060708090a0b0c0d0e0f",
		"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
		"00112233445566778899aabbccddeeff",
		"11dc67e8b6a334abbd630e1da4cedcc4"
	},
	{ NULL, NULL, NULL, NULL }
};

static const struct {
	const char	*key;
	const char	*iv;
	const char	*plaintext;
	const char	*ciphertext;
} aes128OfbVectors[] = {
	{
		"00000000000000000000000000000000",
		"00000000000000000000000000000000",
		"00000000000000000000000000000000",
		"66e94bd4ef8a2c3b884cfa59ca342b2e"
	},
	{
		"ffffffffffffffffffffffffffffffff",
		"00000000000000000000000000000000",
		"00000000000000000000000000000000",
		"a1f6258c877d5fcd8964484538bfc92c"
	},
	{
		"00112233445566778899aabbccddeeff",
		"102030405060708090a0b0c0d0e0f001",
		"000102030405060708090a0b0c0d0e0f",
		"b4c7efcc8622c13c5edea1b61633bf40"
	},
	{
		"2b7e151628aed2a6abf7158809cf4f3c",
		"000102030405060708090a0b0c0d0e0f",
		"6bc1bee22e409f96e93d7e117393172a",
		"3b3fd92eb72dad20333449f8e83cfb4a"
	},
	{
		"000102030405060708090a0b0c0d0e0f",
		"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
		"00112233445566778899aabbccddeeff",
		"66b6e5db7007573f1fc874bcffcb4352"
	},
	{ NULL, NULL, NULL, NULL }
};

static const struct {
	const char	*key;
	const char	*iv;
	const char	*plaintext;
	const char	*ciphertext;
} aes128CtrVectors[] = {
	{
		"00000000000000000000000000000000",
		"00000000000000000000000000000000",
		"00000000000000000000000000000000",
		"66e94bd4ef8a2c3b884cfa59ca342b2e"
	},
	{
		"ffffffffffffffffffffffffffffffff",
		"00000000000000000000000000000000",
		"00000000000000000000000000000000",
		"a1f6258c877d5fcd8964484538bfc92c"
	},
	{
		"00112233445566778899aabbccddeeff",
		"102030405060708090a0b0c0d0e0f001",
		"000102030405060708090a0b0c0d0e0f",
		"b4c7efcc8622c13c5edea1b61633bf40"
	},
	{
		"2b7e151628aed2a6abf7158809cf4f3c",
		"000102030405060708090a0b0c0d0e0f",
		"6bc1bee22e409f96e93d7e117393172a",
		"3b3fd92eb72dad20333449f8e83cfb4a"
	},
	{
		"000102030405060708090a0b0c0d0e0f",
		"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
		"00112233445566778899aabbccddeeff",
		"66b6e5db7007573f1fc874bcffcb4352"
	},
	{ NULL, NULL, NULL, NULL }
};

static const struct {
	const char  *key;
	const char  *iv;
	const char  *plaintext;
	const char  *ciphertext;
} aes128PcbcVectors[] = {
	{
		"1bb46016387910bc4d32362b1a22345a",
		"6e2e585257994eb75f970956a771e7c3",
		"b7bfe43dd428a4f86af7a3380d02d00e69537e26bab6093d266782cd5c776f5f",
		"405e8a4a94f495fe2732e526aeb876983cf88b26378a09afb6066fb4da42ea0e2670f2ab5f2237aecb28d268ef5aca86"
	},
	{
		"4dd97c7084fa2f74292a74c8e57c2458",
		"a13fc4747337e223dcca59d1d2dd329e",
		"6c694d141a2251e00513eead00ef4fc8601e78c8330089bedce1cebdfceb4845",
		"a1bb9c5d39932f6a21ae913368ca37bf84c2caf06def44a90843e8effd3fb4e4007a5f8040d9ff29136d2b07b36908b2"
	},
	{
		"34ff2259f17643f7fe1dd1946934f999",
		"68eb349a2d7e1b96374e815b2b537fa8",
		"1f6b8f085e337da889fd25a61bc2411300e2d78a363ca9ca943b3cfd5a15c59b",
		"afb5ed2c715bb1e9bde6093856702e7f17ac8d586e062f10e729b27e7f1b632b47afc1ed2a8dec3fefb6e45bdfd61664"
	},
	{
		"475eff7d831520f59784ca73a757ffce",
		"d8ecaba4142c1bb4388633dc9960b09f",
		"bc84f380208a52e2b79752f0e8507f0daeb1d7fc6f8e5b5e7569b9b7d295a0d7",
		"681b46206294b58692ff96f74eff2d9ffcc4165c48a4f5b9f96545830c1ff9f44c9e43747c4d3e36dcb64c903d1fd8df"
	},
	{
		"ccf99d8a55ddbf4f3168599cd7b96f84",
		"6e84f6d70d82c7b4cd5028f2e9ef15d6",
		"bd58091f1e9107e83f1b113f1890134e40d976947fd83d3bd90554a21ddb67f2",
		"24ea2abc28ce195de83b3b6143d6c89c2cda07a2b616da3a5407f046eb8f5353b3196d8f750ea813ac42f9d1152d048d"
	},
	{ NULL, NULL, NULL, NULL }
};

static const struct {
	const char  *key;
	const char  *iv;
	const char  *aad;
	const char  *plaintext;
	const char  *ciphertext;
	const char  *tag;
} aes128GcmVectors[] = {
{
		"ae7042f562e3c0852b0ec6dfe1d77626",
		"d24c0a18a82895e2b37c43d5",
		"cfb77d57987ab8b5",
		"637968b82d01d3a2f7a2ff4b169165a2d1bf8c6cb9b7ae127b0ab5898138e058",
		"8f6865c0816ef66af2b8ed25d4412a96d68b43c980a1bafadf26f192213062a0",
		"d955a45f0ae36e3127d995501be07fec"
	},
	{
		"75b610caeb4d2735853eca83e8351a53",
		"a86e3e5df3d11cc8dea1339d",
		"731c3c3e9d034a9d",
		"99d656348eaa373f99c6ca714366d1a3cbc39e61a33e5f51792a5db5da2292da",
		"7e656d4a2549c79c349d56c03b46b0b2b9c23a1e8a968caa3734003bf705e6bb",
		"12be0b342c22f82caf8c79de7ff273f6"
	},
	{
		"49b3c78c7b22a16c2585b5a4c6803c2e",
		"1b14576f5c0c09edc09f1659",
		"99ddbbd8eb3ce49c",
		"550b2ebf89f7587eddb81911ce3dc85d537ee10310703a002c5e43eada2da30c",
		"a612cf6c3fd2ecc0e92e0f20f80027dd8e676f11679ad86546f83f679636bfd9",
		"ad6f31ed88eb3e45c4c11d65cf9dbd86"
	},
	{
		"032afb84cc927bd52ba37e94aacb86e2",
		"63acadaeccc81e27a0e01d72",
		"61631c53ca2a1259",
		"ac02c70a5c86319a1fa56855fad6b01584a9d2174472c91973302b13e4d789bc",
		"6e26a372d7895bf6be3214655705b7ad34fc3a9909b3c54c9fb1ae6c96680f4c",
		"81cb1db9d851f39045ebf3306328dd7f"
	},
	{
		"a78b61e0938d71cf9a7f5344aebf893a",
		"83d3c31bc87e1948ec17d2b0",
		"799a9befd52ac4ee",
		"b69858c7541925ec08cef6a3899c46cfca48f96f71d39174a3abc3c78c78bf25",
		"12f6f36362a6a16d438868420930e70fbbd4b6843c6521eb6024b77f28c879e8",
		"375c97af01132f092d7bda013ead9361"
	},
	{ NULL, NULL, NULL, NULL, NULL, NULL }
};

/* --------------- Helper Functions --------------- */

static int hexToBytes(const char *hex, uint8_t *out, size_t maxLen) {
	size_t hexLen = ft_strlen(hex);
	if (hexLen % 2 != 0 || hexLen / 2 > maxLen)
		return (-1);
	for (size_t i = 0; i < hexLen / 2; i++) {
		char byteStr[3] = { hex[i*2], hex[i*2+1], 0 };
		out[i] = (uint8_t)ft_strtol(byteStr, NULL, 16);
	}
	return (int)(hexLen / 2);
}

static int compareBytes(const uint8_t *expected, const uint8_t *actual, size_t len) {
	for (size_t i = 0; i < len; i++) {
		if (expected[i] != actual[i])
			return (0);
	}
	return (1);
}

/* --------------- Test Functions for Each Mode --------------- */

