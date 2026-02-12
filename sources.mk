SRC_DIR	= src

LIB_SRC = \
	$(SRC_DIR)/hash/common/padding.c \
	$(SRC_DIR)/hash/common/endian.c

LIB_OBJ = $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(LIB_SRC))

CLI_SRC = \
	$(SRC_DIR)/cli/main.c \
	$(SRC_DIR)/cli/parser.c

CLI_OBJ = $(patsubst $(SRC_DIR)/cli/%.c, $(BUILD_DIR)/cli/%.o, $(CLI_SRC))
