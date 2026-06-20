SRC_DIR	= src

SRCS	= $(SRC_DIR)/cipher.c \
		  $(SRC_DIR)/dispatch.c \
		  $(SRC_DIR)/hkdf.c \
		  $(SRC_DIR)/io.c \
		  $(SRC_DIR)/keySchedule.c \
		  $(SRC_DIR)/record.c \
		  $(SRC_DIR)/tls.c \
		  $(SRC_DIR)/extensions/decode.c \
		  $(SRC_DIR)/extensions/encode.c \
		  $(SRC_DIR)/extensions/print.c \
		  $(SRC_DIR)/extensions/decodeTls12.c \
		  $(SRC_DIR)/extensions/encodeTls12.c \
		  $(SRC_DIR)/extensions/decodeTls13.c \
		  $(SRC_DIR)/extensions/encodeTls13.c \
		  $(SRC_DIR)/handshake/hello/decode.c \
		  $(SRC_DIR)/handshake/hello/encode.c \
		  $(SRC_DIR)/handshake/hello/hello.c \
		  $(SRC_DIR)/handshake/tls13/messages.c \
		  $(SRC_DIR)/handshake/tls13/server.c \
		  $(SRC_DIR)/handshake/handshakeUtils.c

OBJS		= $(SRCS:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
