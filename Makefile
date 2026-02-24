NAME		= ft_ssl
BUILD_DIR	= build

ARCH := $(shell uname -m)

CONST_EXEC	= $(BUILD_DIR)/genConst

LIB_NAME	= hajcrypt
HLIB_PATH	= hajlib
HLIB_LIBA	= $(HLIB_PATH)/hajlib.a

CC			= clang
BASE_FLAGS	= -Wall -Wextra -Werror
OPT_FLAGS	?= -O3
SAN_FLAGS	?=
ASM_FLAGS	?=
CFLAGS		= $(BASE_FLAGS) $(OPT_FLAGS) $(SAN_FLAGS)

INCLUDES	= -I./includes -I$(HLIB_PATH)/include

include sources.mk

LIB_OBJ = $(LIB_SRC_OBJ)

# --- ANSI colors ---
GREEN   = \033[0;32m
YELLOW  = \033[1;33m
BLUE	= \033[0;34m
RED		= \033[0;31m
RESET   = \033[0m

all: $(NAME)

lib: $(LIB_NAME).a

const: $(CONST_EXEC) $(CONST_HEADERS)



# --- Compile with optimized assembly file for architecture if avaible ---

ifeq ($(ARCH),aarch64)
LIB_OBJ += $(LIB_ASM_ARM_OBJ)
ASM_FLAGS := -march=armv8.2-a+crypto
endif


# --- Check for leak flag to add debug flags ---
ifneq (,$(filter leak,$(MAKECMDGOALS)))
SAN_FLAGS = --pedantic -g -fsanitize=address -fno-omit-frame-pointer
OPT_FLAGS = -O1
endif

# --- Build hajlib ---
$(HLIB_LIBA):
	@echo -e "$(BLUE)Building hajlib...$(RESET)"
	$(MAKE) -C $(HLIB_PATH) -j $(nproc)
	@echo -e "$(GREEN)hajlib built.$(RESET)"


# ---- Generate constants ----
$(BUILD_DIR)/consts/%.o: $(CONST_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(CONST_EXEC): $(HLIB_LIBA) $(CONST_OBJ)
	@echo -e "$(GREEN)Linking genConst executable...$(RESET)"
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $(CONST_OBJ) $(HLIB_LIBA)
	@echo -e "$(GREEN)Executable $@ generated.$(RESET)"

$(CONST_HEADERS): $(CONST_EXEC)
	@echo -e "$(YELLOW)Generating constant headers...$(RESET)"
	@mkdir -p $(CONST_HDR_DIR)
	./$(CONST_EXEC) $(CONST_HDR_DIR)
	@echo -e "$(YELLOW)Headers generated.$(RESET)"

# --- Compile project objects ---
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.s
	@mkdir -p $(dir $@)
	@echo -e "$(BLUE)Assembling $<...$(RESET)"
	$(CC) $(BASE_FLAGS) $(ASM_FLAGS) -g  $(INCLUDES) -c $< -o $@

# --- Build static library ---
$(LIB_NAME).a: $(CONST_HEADERS) $(LIB_OBJ)
	@echo -e "$(GREEN)Building static library $@...$(RESET)"
	@mkdir -p $(BUILD_DIR)
	ar rcs $@ $(LIB_OBJ)
	@echo -e "$(GREEN)Library $@ generated.$(RESET)"

# --- Build executable ---
$(NAME): $(HLIB_LIBA) $(LIB_NAME).a $(CLI_OBJ)
	@echo -e "$(BLUE)Linking final executable $(NAME)...$(RESET)"
	$(CC) $(CFLAGS) $(INCLUDES) -o $(NAME) \
		$(CLI_OBJ) \
		$(LIB_NAME).a \
		$(HLIB_LIBA)
	@echo -e "$(GREEN)Executable $(NAME) ready.$(RESET)"

test: $(LIB_NAME).a $(TEST_SRC)
	@echo -e "$(BLUE)Compiling tests...$(RESET)"
	@mkdir -p $(BUILD_DIR)/tests
	$(CC) $(CFLAGS) $(INCLUDES) -o $(BUILD_DIR)/tests/test_runner \
		$(TEST_SRC) \
		$(LIB_NAME).a \
		$(HLIB_LIBA)
	@echo -e "$(GREEN)Running tests...$(RESET)"
	$(BUILD_DIR)/tests/test_runner

# --- Clean ---
clean:
	$(MAKE) -C $(HLIB_PATH) clean
	rm -f $(CONST_HEADERS)
	rm -rf $(BUILD_DIR)

fclean: clean
	rm -f $(NAME)
	rm -f $(LIB_NAME).a
	$(MAKE) -C $(HLIB_PATH) fclean

re: fclean all

leak:
	@true

.PHONY: all clean fclean re const lib leak
