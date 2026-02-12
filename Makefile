NAME		= ft_ssl

LIB_NAME	= hajcrypt
LIB_PATH	= hajlib
LIB_LIBA	= $(LIB_PATH)/hajlib.a

CC			= clang
CFLAGS		= -Wall -Wextra -Werror -g
INCLUDES	= -I./includes -I$(LIB_PATH)/include

BUILD_DIR   = build

include sources.mk


all: $(NAME)


# Build external hajlib
$(LIB_LIBA):
	@echo "Building hajlib..."
	$(MAKE) -C $(LIB_PATH)

# Compile project objects
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Build project static library
$(BUILD_DIR)/lib$(LIB_NAME).a: $(LIB_OBJ)
	@mkdir -p $(BUILD_DIR)
	ar rcs $@ $(LIB_OBJ)

# Build executable
$(NAME): $(LIB_LIBA) $(BUILD_DIR)/lib$(LIB_NAME).a $(CLI_OBJ)
	@echo "Linking $(NAME)..."
	$(CC) $(CFLAGS) $(INCLUDES) -o $(NAME) \
		$(CLI_OBJ) \
		$(BUILD_DIR)/lib$(LIB_NAME).a \
		$(LIB_LIBA)


# Clean

clean:
	$(MAKE) -C $(LIB_PATH) clean
	rm -rf $(BUILD_DIR)

fclean: clean
	rm -f $(NAME)
	$(MAKE) -C $(LIB_PATH) fclean

re: fclean all

.PHONY: all clean fclean re
