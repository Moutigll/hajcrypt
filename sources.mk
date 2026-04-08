SRC_DIR			= src
CONST_DIR		= $(SRC_DIR)/consts
CONST_HDR_DIR	= includes/consts

CONST_HEADERS = \
	$(CONST_HDR_DIR)/md5.h \
	$(CONST_HDR_DIR)/sha256.h \
	$(CONST_HDR_DIR)/whirlpool.h \
	$(CONST_HDR_DIR)/base64.h \
	$(CONST_HDR_DIR)/des.h \
	$(CONST_HDR_DIR)/blake2b.h \
	$(CONST_HDR_DIR)/aes.h

CONST_SRC = \
	$(CONST_DIR)/main.const.c \
	$(CONST_DIR)/md5.const.c \
	$(CONST_DIR)/sha256.const.c \
	$(CONST_DIR)/whirlpool.const.c \
	$(CONST_DIR)/base64.const.c \
	$(CONST_DIR)/des.const.c \
	$(CONST_DIR)/blake2b.const.c \
	$(CONST_DIR)/aes.const.c

LIB_SRC = \
	$(SRC_DIR)/utils.c \
	$(SRC_DIR)/hajSecRandBytes.c \
	$(SRC_DIR)/hash/common/padding.c \
	$(SRC_DIR)/hash/common/endian.c \
	$(SRC_DIR)/hash/md5/md5.c \
	$(SRC_DIR)/hash/md5/transform.c \
	$(SRC_DIR)/hash/sha256/sha256.c \
	$(SRC_DIR)/hash/sha256/transform.c \
	$(SRC_DIR)/hash/whirlpool/whirlpool.c \
	$(SRC_DIR)/hash/whirlpool/transform.c \
	$(SRC_DIR)/hash/whirlpool/transform.opt.c \
	$(SRC_DIR)/hash/blake2b/blake2b.c \
	$(SRC_DIR)/hash/blake2b/transform.c \
	$(SRC_DIR)/hash/hmac.c \
	$(SRC_DIR)/cipher/utils.c \
	$(SRC_DIR)/cipher/modes/cbc.c \
	$(SRC_DIR)/cipher/modes/cfb.c \
	$(SRC_DIR)/cipher/modes/ofb.c \
	$(SRC_DIR)/cipher/modes/ctr.c \
	$(SRC_DIR)/cipher/modes/pcbc.c \
	$(SRC_DIR)/cipher/base64.c \
	$(SRC_DIR)/cipher/blowfish/transform.c \
	$(SRC_DIR)/cipher/blowfish/ecb.c \
	$(SRC_DIR)/cipher/blowfish/cbc.c \
	$(SRC_DIR)/cipher/blowfish/cfb.c \
	$(SRC_DIR)/cipher/blowfish/ofb.c \
	$(SRC_DIR)/cipher/blowfish/ctr.c \
	$(SRC_DIR)/cipher/blowfish/pcbc.c \
	$(SRC_DIR)/cipher/des/transform.c \
	$(SRC_DIR)/cipher/des/ecb.c \
	$(SRC_DIR)/cipher/des/cbc.c \
	$(SRC_DIR)/cipher/des/cfb.c \
	$(SRC_DIR)/cipher/des/ofb.c \
	$(SRC_DIR)/cipher/des/ctr.c \
	$(SRC_DIR)/cipher/des/pcbc.c \
	$(SRC_DIR)/cipher/des3/transform.c \
	$(SRC_DIR)/cipher/des3/ecb.c \
	$(SRC_DIR)/cipher/des3/cbc.c \
	$(SRC_DIR)/cipher/des3/cfb.c \
	$(SRC_DIR)/cipher/des3/ofb.c \
	$(SRC_DIR)/cipher/des3/ctr.c \
	$(SRC_DIR)/cipher/des3/pcbc.c \
	$(SRC_DIR)/cipher/aes/transform.c \
	$(SRC_DIR)/cipher/aes/ecb.c \
	$(SRC_DIR)/cipher/aes/cbc.c \
	$(SRC_DIR)/cipher/aes/cfb.c \
	$(SRC_DIR)/cipher/aes/ofb.c \
	$(SRC_DIR)/cipher/aes/ctr.c \
	$(SRC_DIR)/cipher/aes/gcm.c \
	$(SRC_DIR)/cipher/aes/pcbc.c \
	$(SRC_DIR)/cipher/aes/transform_arm64.c \
	$(SRC_DIR)/cipher/aes/transform_x86.c \
	$(SRC_DIR)/kdf/kdf.c \
	$(SRC_DIR)/kdf/bytesToKey.c \
	$(SRC_DIR)/kdf/pbkdf2.c \
	$(SRC_DIR)/kdf/bcrypt.c \
	$(SRC_DIR)/kdf/argon2.c

LIB_ASM_ARM_SRC = \
	$(SRC_DIR)/hash/sha256/transform_arm64.s

CLI_SRC = \
	$(SRC_DIR)/cli/main.c \
	$(SRC_DIR)/cli/parser.c \
	$(SRC_DIR)/cli/dispatch.c \
	$(SRC_DIR)/cli/processHash.c \
	$(SRC_DIR)/cli/processCipher.c \
	$(SRC_DIR)/cli/cipherIo.c \
	$(SRC_DIR)/cli/prompt.c

TEST_SRC = \
	tests/main.test.c \
	tests/utils.test.c \
	tests/src/md5.test.c \
	tests/src/sha256.test.c \
	tests/src/whirlpool.test.c \
	tests/src/aes128.test.c \
	tests/src/des.test.c \
	tests/src/des3.test.c \
	tests/src/blowfish.test.c \
	tests/src/base64.test.c \
	tests/src/blake2b.test.c \
	tests/src/pbkdf2.test.c \
	tests/src/argon2.test.c \

CONST_OBJ = $(patsubst $(CONST_DIR)/%.c, $(BUILD_DIR)/consts/%.o, $(CONST_SRC))
LIB_SRC_OBJ = $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(LIB_SRC))
LIB_ASM_ARM_OBJ = $(patsubst $(SRC_DIR)/%.s, $(BUILD_DIR)/%.o, $(LIB_ASM_ARM_SRC))
CLI_OBJ = $(patsubst $(SRC_DIR)/cli/%.c, $(BUILD_DIR)/cli/%.o, $(CLI_SRC))
