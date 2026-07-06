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

VERSION_FILE	:= VERSION
VERSION_H		:= includes/version.h
VERSION_H_IN	:= includes/version.h.in
VERSION_META	:= .version_meta
CHANGELOG_MD	:= CHANGELOG.md

include sources.mk

# Installation paths
PREFIX						?= /usr/local
BINDIR						?= $(PREFIX)/bin
COMPLETION_DIR_SYSTEM		?= /usr/share/bash-completion/completions
ZSH_COMPLETION_DIR_SYSTEM	?= /usr/share/zsh/site-functions

# Completion files
COMPLETION_SRC_BASH	:= src/ft_ssl.bash
COMPLETION_SRC_ZSH	:= src/ft_ssl.zsh

# User directories
HOME_BIN					:= $(HOME)/.local/bin
BASH_COMPLETION_USER_DIR	:= $(HOME)/.local/share/bash-completion/completions
ZSH_COMPLETION_USER_DIR		:= $(HOME)/.local/share/zsh/site-functions

# Shell config files
BASHRC			:= $(HOME)/.bashrc
ZSHRC			:= $(HOME)/.zshrc

# Check if bash-completion is installed
HAS_BASH_COMPLETION	:= $(shell command -v _init_completion 2>/dev/null || echo "no")

LIB_OBJ = $(LIB_SRC_OBJ)

# --- ANSI colors ---
GREEN	= \033[0;32m
YELLOW	= \033[1;33m
BLUE	= \033[0;34m
RED		= \033[0;31m
RESET	= \033[0m

all: $(NAME)

lib: $(LIB_NAME).a

const: $(CONST_EXEC) $(CONST_HEADERS)

# --- Compile with optimized assembly for architecture ---
ifeq ($(ARCH),aarch64)
LIB_OBJ += $(LIB_ASM_ARM_OBJ)
ASM_FLAGS := -march=armv8.2-a+crypto
CFLAGS += $(ASM_FLAGS)
endif

# --- Build hajlib ---
$(HLIB_LIBA):
	@echo -e "$(BLUE)Building hajlib...$(RESET)"
	$(MAKE) -C $(HLIB_PATH) -j $(nproc)
	@echo -e "$(GREEN)hajlib built.$(RESET)"

# ---- Generate constants ----
$(BUILD_DIR)/consts/%.o: $(CONST_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(BASE_FLAGS) $(OPT_FLAGS) $(INCLUDES) -c $< -o $@

$(CONST_EXEC): $(HLIB_LIBA) $(CONST_OBJ)
	@echo -e "$(GREEN)Linking genConst executable...$(RESET)"
	$(CC) $(BASE_FLAGS) $(OPT_FLAGS) $(INCLUDES) -o $@ $(CONST_OBJ) $(HLIB_LIBA)
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
	$(CC) $(BASE_FLAGS) $(ASM_FLAGS) -g $(INCLUDES) -c $< -o $@

# --- Build static library ---
$(LIB_NAME).a: $(VERSION_H) $(CONST_HEADERS) $(LIB_OBJ)
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
	@echo -e "$(YELLOW)Building with AddressSanitizer...$(RESET)"
	@$(MAKE) fclean > /dev/null 2>&1
	@$(MAKE) all SAN_FLAGS="-g -fsanitize=address -fno-omit-frame-pointer" OPT_FLAGS=""
	@echo -e "$(GREEN)Leak check build complete.$(RESET)"
	@echo -e "$(YELLOW)Run with: ./$(NAME)$(RESET)"
	@echo -e "$(YELLOW)Or: ASAN_OPTIONS=detect_leaks=1 ./$(NAME)$(RESET)"

leak-test: $(LIB_NAME).a $(TEST_SRC)
	@echo -e "$(YELLOW)Building tests with AddressSanitizer...$(RESET)"
	@$(MAKE) $(LIB_NAME).a SAN_FLAGS="-g -fsanitize=address -fno-omit-frame-pointer" OPT_FLAGS=""
	@echo -e "$(BLUE)Compiling test runner with ASAN...$(RESET)"
	@mkdir -p $(BUILD_DIR)/tests
	$(CC) $(BASE_FLAGS) -g -fsanitize=address -fno-omit-frame-pointer $(ASM_FLAGS) $(INCLUDES) -o $(BUILD_DIR)/tests/test_runner \
		$(TEST_SRC) \
		$(LIB_NAME).a \
		$(HLIB_LIBA)
	@echo -e "$(GREEN)Running tests with ASAN...$(RESET)"
	@echo -e "$(YELLOW)ASAN_OPTIONS=detect_leaks=1 $(BUILD_DIR)/tests/test_runner$(RESET)"
	ASAN_OPTIONS=detect_leaks=1 $(BUILD_DIR)/tests/test_runner


# --------------- Installation targets ---------------

install: $(NAME)
	@SHELL_NAME=$$(basename "$$SHELL"); \
	printf "$(BLUE)Detected shell: $$SHELL_NAME$(RESET)\n"; \
	if [ -w $(BINDIR) ] 2>/dev/null; then \
		printf "$(GREEN)System install (writable directory)...$(RESET)\n"; \
		$(MAKE) install-system; \
	elif command -v sudo >/dev/null 2>&1; then \
		printf "$(GREEN)System install (using sudo)...$(RESET)\n"; \
		sudo $(MAKE) install-system; \
	else \
		printf "$(YELLOW)User install...$(RESET)\n"; \
		$(MAKE) install-user; \
	fi; \
	$(MAKE) install-config SHELL_NAME=$$SHELL_NAME

install-system: $(NAME)
	@printf "$(BLUE)Installing to system directories...$(RESET)\n"
	install -d $(BINDIR)
	install -m 755 $(NAME) $(BINDIR)/
	install -d $(COMPLETION_DIR_SYSTEM)
	install -m 644 $(COMPLETION_SRC_BASH) $(COMPLETION_DIR_SYSTEM)/$(NAME)
	install -d $(ZSH_COMPLETION_DIR_SYSTEM)
	install -m 644 $(COMPLETION_SRC_ZSH) $(ZSH_COMPLETION_DIR_SYSTEM)/_$(NAME)
	@printf "$(GREEN)System installation complete.$(RESET)\n"

install-user: $(NAME)
	@SHELL_NAME=$$(basename "$$SHELL"); \
	printf "$(BLUE)Installing to user directories...$(RESET)\n"; \
	mkdir -p $(HOME_BIN); \
	install -m 755 $(NAME) $(HOME_BIN)/; \
	printf "$(YELLOW)Installing completion for $$SHELL_NAME...$(RESET)\n"; \
	case "$$SHELL_NAME" in \
		bash) \
			mkdir -p $(BASH_COMPLETION_USER_DIR); \
			install -m 644 $(COMPLETION_SRC_BASH) $(BASH_COMPLETION_USER_DIR)/$(NAME); \
			;; \
		zsh) \
			mkdir -p $(ZSH_COMPLETION_USER_DIR); \
			install -m 644 $(COMPLETION_SRC_ZSH) $(ZSH_COMPLETION_USER_DIR)/_$(NAME); \
			;; \
		*) \
			printf "$(YELLOW)Unsupported shell for completion: $$SHELL_NAME$(RESET)\n"; \
			;; \
	esac

install-config:
	@printf "$(BLUE)Configuring shell...$(RESET)\n"
	@case "$(SHELL_NAME)" in \
		bash) \
			if ! grep -q "ft_ssl completion" $(BASHRC) 2>/dev/null; then \
				printf "\n# ft_ssl completion\n" >> $(BASHRC); \
				printf "export PATH=\"\$$HOME/.local/bin:\$$PATH\"\n" >> $(BASHRC); \
				if [ "$(HAS_BASH_COMPLETION)" = "no" ]; then \
					printf "if [ -f $(BASH_COMPLETION_USER_DIR)/$(NAME) ]; then\n" >> $(BASHRC); \
					printf "    source $(BASH_COMPLETION_USER_DIR)/$(NAME)\n" >> $(BASHRC); \
					printf "fi\n" >> $(BASHRC); \
				fi; \
				printf "$(GREEN)Added configuration to $(BASHRC)$(RESET)\n"; \
			else \
				printf "$(YELLOW)Configuration already present in $(BASHRC)$(RESET)\n"; \
			fi; \
			;; \
		zsh) \
			if ! grep -q "ft_ssl completion" $(ZSHRC) 2>/dev/null; then \
				printf "\n# ft_ssl completion\n" >> $(ZSHRC); \
				printf "export PATH=\"\$$HOME/.local/bin:\$$PATH\"\n" >> $(ZSHRC); \
				printf "fpath=($(ZSH_COMPLETION_USER_DIR) \$$fpath)\n" >> $(ZSHRC); \
				printf "autoload -Uz compinit\n" >> $(ZSHRC); \
				printf "compinit\n" >> $(ZSHRC); \
				printf "$(GREEN)Added configuration to $(ZSHRC)$(RESET)\n"; \
			else \
				printf "$(YELLOW)Configuration already present in $(ZSHRC)$(RESET)\n"; \
			fi; \
			;; \
		*) \
			printf "$(YELLOW)Please manually add ~/.local/bin to your PATH$(RESET)\n"; \
			;; \
	esac
	@printf "$(GREEN)Installation complete!$(RESET)\n"
	@printf "$(YELLOW)Run the following command to use ft_ssl now:$(RESET)\n"
	@case "$(SHELL_NAME)" in \
		bash) \
			printf "  source $(BASHRC)\n"; \
			;; \
		zsh) \
			printf "  source $(ZSHRC)\n"; \
			;; \
		*) \
			printf "  export PATH=\"\$$HOME/.local/bin:\$$PATH\"\n"; \
			;; \
	esac

uninstall:
	@printf "$(RED)Uninstalling...$(RESET)\n"
	@if [ -w $(BINDIR) ] 2>/dev/null; then \
		rm -f $(BINDIR)/$(NAME); \
		rm -f $(COMPLETION_DIR_SYSTEM)/$(NAME); \
		rm -f $(ZSH_COMPLETION_DIR_SYSTEM)/_$(NAME); \
	else \
		rm -f $(HOME_BIN)/$(NAME); \
		rm -f $(BASH_COMPLETION_USER_DIR)/$(NAME); \
		rm -f $(ZSH_COMPLETION_USER_DIR)/_$(NAME); \
	fi
	@printf "$(YELLOW)Removing configuration from shell rc files...$(RESET)\n"
	@case "$(SHELL_NAME)" in \
		bash) \
			sed -i '/# ft_ssl completion/,/fi/d' $(BASHRC) 2>/dev/null || true; \
			;; \
		zsh) \
			sed -i '/# ft_ssl completion/,/compinit/d' $(ZSHRC) 2>/dev/null || true; \
			;; \
	esac
	@printf "$(GREEN)Uninstall complete. Please restart your shell.$(RESET)\n"

# --------------- Version management ---------------

$(VERSION_H): update-version $(VERSION_H_IN) $(VERSION_FILE)
	@echo "Generating $(VERSION_H)..."
	@VERSION=$$(cat $(VERSION_FILE)); \
	MAJOR=$$(echo $$VERSION | cut -d. -f1); \
	MINOR=$$(echo $$VERSION | cut -d. -f2); \
	PATCH=$$(echo $$VERSION | cut -d. -f3); \
	HASH=$$(git log -1 --format="%h"); \
	SUBJ=$$(git log -1 --format="%s"); \
	DATE=$$(git log -1 --format="%ad" --date=format:"%d %b %Y"); \
	sed -e "s/@MAJOR@/$$MAJOR/g" \
	    -e "s/@MINOR@/$$MINOR/g" \
	    -e "s/@PATCH@/$$PATCH/g" \
	    -e "s/@VERSION@/$$VERSION/g" \
	    -e "s/@GIT_COMMIT_HASH@/$$HASH/g" \
	    -e "s/@GIT_COMMIT_SUBJECT@/$$SUBJ/g" \
	    -e "s/@GIT_COMMIT_DATE@/$$DATE/g" \
	    $(VERSION_H_IN) > $(VERSION_H)

update-version:
	./version.sh

release: update-version changelog
	@VERSION=$$(cat $(VERSION_FILE)); \
	git add $(VERSION_FILE) $(VERSION_H) $(CHANGELOG_MD); \
	git commit -m "chore(release): $$VERSION";
	@printf "$(GREEN)Release commit created for version $$VERSION.$(RESET)\n You can now run 'git push && git push --tags' to push the release to the remote repository.$(RESET)\n"

changelog:
	./changelog.sh

.PHONY: all clean fclean re const lib leak leak-test
.PHONY: install install-system install-user install-config uninstall
.PHONY: update-version release changelog
