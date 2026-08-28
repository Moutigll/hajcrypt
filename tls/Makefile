NAME		= libbtls.a

include sources.mk

INC_DIR		= includes
OBJ_DIR		= obj

HAJCRYPT_DIR	= ..
HAJLIB_DIR		= $(HAJCRYPT_DIR)/hajlib

# --- Cross-compilation support ---
include ../hajlib/cross.mk

CFLAGS		= -O3 -Wall -Wextra -Werror -pedantic
CPPFLAGS	= -I$(INC_DIR) \
			  -I$(HAJCRYPT_DIR)/includes \
			  -I$(HAJLIB_DIR)/include

ifeq ($(CROSS_COMPILING),1)
    CFLAGS := $(filter-out -Werror -pedantic,$(CFLAGS))
endif

#CFLAGS		+= -fsanitize=address -fno-omit-frame-pointer

all: $(NAME)

$(NAME): $(OBJS)
	$(AR) rcs $@ $^

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJ_DIR)

fclean: clean
	rm -f $(NAME)

re: fclean all

.PHONY: all clean fclean re
