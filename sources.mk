SRC_DIR			= src
CONST_DIR		= $(SRC_DIR)/consts
CONST_HDR_DIR	= includes/consts

CONST_HEADERS = \
	$(CONST_HDR_DIR)/md5.h \
	$(CONST_HDR_DIR)/sha256.h \
	$(CONST_HDR_DIR)/whirlpool.h

CONST_SRC = \
	$(CONST_DIR)/main.const.c \
	$(CONST_DIR)/md5.const.c \
	$(CONST_DIR)/sha256.const.c \
	$(CONST_DIR)/whirlpool.const.c

LIB_SRC = \
	$(SRC_DIR)/hash/common/padding.c \
	$(SRC_DIR)/hash/common/endian.c \
	$(SRC_DIR)/random/hajSecRandBytes.c \
	$(SRC_DIR)/hash/md5/md5.c \
	$(SRC_DIR)/hash/md5/transform.c \
	$(SRC_DIR)/hash/sha256/sha256.c \
	$(SRC_DIR)/hash/sha256/transform.c \
	$(SRC_DIR)/hash/whirlpool/whirlpool.c \
	$(SRC_DIR)/hash/whirlpool/transform.c \
	$(SRC_DIR)/hash/whirlpool/transform.opt.c

LIB_ASM_ARM_SRC = \
	$(SRC_DIR)/hash/sha256/transform_arm64.s

CLI_SRC = \
	$(SRC_DIR)/cli/main.c \
	$(SRC_DIR)/cli/parser.c \
	$(SRC_DIR)/cli/dispatch.c

TEST_SRC = \
	tests/main.test.c \
	tests/utils.test.c \
	tests/src/md5.test.c \
	tests/src/sha256.test.c \
	tests/src/whirlpool.test.c

CONST_OBJ = $(patsubst $(CONST_DIR)/%.c, $(BUILD_DIR)/consts/%.o, $(CONST_SRC))
LIB_SRC_OBJ = $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(LIB_SRC))
LIB_ASM_ARM_OBJ = $(patsubst $(SRC_DIR)/hash/sha256/transform_arm64.s, $(BUILD_DIR)/hash/sha256/transform_arm64.o, $(LIB_ASM_ARM_SRC))
LIB_ASM_X86_OBJ = $(patsubst $(SRC_DIR)/hash/sha256/transform_x86_64.s, $(BUILD_DIR)/hash/sha256/transform_x86_64.o, $(LIB_ASM_X86_SRC))
CLI_OBJ = $(patsubst $(SRC_DIR)/cli/%.c, $(BUILD_DIR)/cli/%.o, $(CLI_SRC))
