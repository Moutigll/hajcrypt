SRC_DIR			= src
CONST_DIR		= $(SRC_DIR)/consts
CONST_HDR_DIR	= includes/consts

CONST_HEADERS = \
	$(CONST_HDR_DIR)/md5.h

CONST_SRC = \
	$(CONST_DIR)/main.c \
	$(CONST_DIR)/md5.c

LIB_SRC = \
	$(SRC_DIR)/hash/common/padding.c \
	$(SRC_DIR)/hash/common/endian.c


CLI_SRC = \
	$(SRC_DIR)/cli/main.c \
	$(SRC_DIR)/cli/parser.c

CONST_OBJ = $(patsubst $(CONST_DIR)/%.c, $(BUILD_DIR)/consts/%.o, $(CONST_SRC))
LIB_OBJ = $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(LIB_SRC))
CLI_OBJ = $(patsubst $(SRC_DIR)/cli/%.c, $(BUILD_DIR)/cli/%.o, $(CLI_SRC))
