#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counters
TOTAL=0
PASSED=0
FAILED=0

# Get the directory where the script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FT_SSL="$SCRIPT_DIR/ft_ssl"

# Check if ft_ssl exists
if [ ! -x "$FT_SSL" ]; then
	echo -e "${RED}Error: ft_ssl not found at $FT_SSL${NC}"
	exit 1
fi

# Create temp directory for test files
TEST_DIR=$(mktemp -d)
cd "$TEST_DIR" || exit 1

echo -e "${BLUE}=== FT_SSL MD5 TEST SUITE ===${NC}\n"

# Function to run a test
run_test() {
	local description="$1"
	local command="$2"
	local expected="$3"
	local input="${4:-}"
	
	TOTAL=$((TOTAL + 1))
	
	echo -e "${YELLOW}Test $TOTAL: $description${NC}"
	echo "Command: $command"
	
	# Create a temporary file for output
	local out_file="out_$$.tmp"
	local err_file="err_$$.tmp"
	
	# Run the command with proper path
	if [ -n "$input" ]; then
		# If there's input, use printf to handle special characters
		printf "%b" "$input" | eval "$command" > "$out_file" 2> "$err_file"
	else
		eval "$command" > "$out_file" 2> "$err_file"
	fi
	
	# Capture stdout and stderr
	local output
	output=$(cat "$out_file")
	local stderr
	stderr=$(cat "$err_file")
	
	# If there's stderr, add it to output for comparison
	if [ -n "$stderr" ]; then
		if [ -n "$output" ]; then
			output="$output"$'\n'"$stderr"
		else
			output="$stderr"
		fi
	fi
	
	# Compare with expected
	if [ "$output" = "$expected" ]; then
		echo -e "${GREEN}✓ PASS${NC}"
		PASSED=$((PASSED + 1))
	else
		echo -e "${RED}✗ FAIL${NC}"
		echo "Expected:"
		echo "$expected" | sed 's/^/  /'
		echo "Got:"
		if [ -z "$output" ]; then
			echo "  (empty output)"
		else
			echo "$output" | sed 's/^/  /'
		fi
		FAILED=$((FAILED + 1))  # ← Ligne ajoutée !
	fi
	echo
	
	# Cleanup
	rm -f "$out_file" "$err_file"
}

# Create test files
echo "And above all," > file
echo "And above all," > file_with_newline

# Test 1
run_test "Basic stdin without flags" \
	"echo '42 is nice' | $FT_SSL md5" \
	"(stdin)= 35f1d6de0302e2086a4e472266efb3a9"

# Test 2
run_test "Stdin with -p flag" \
	"echo '42 is nice' | $FT_SSL md5 -p" \
	"(\"42 is nice\")= 35f1d6de0302e2086a4e472266efb3a9"

# Test 3
run_test "Quiet mode (-q) and reverse (-r)" \
	"echo 'Pity the living.' | $FT_SSL md5 -q -r" \
	"e20c3b973f63482a778f3fd1869b7f25"

# Test 4
run_test "File input" \
	"$FT_SSL md5 file" \
	"MD5 (file) = 53d53ea94217b259c11a5a2d104ec58a"

# Test 5
run_test "File input with -r flag" \
	"$FT_SSL md5 -r file" \
	"53d53ea94217b259c11a5a2d104ec58a file"

# Test 6
run_test "String with -s flag" \
	"$FT_SSL md5 -s \"pity those that aren't following baerista on spotify.\"" \
	"MD5 (\"pity those that aren't following baerista on spotify.\") = a3c990a1964705d9bf0e602f44572f5f"

# Test 7
run_test "Stdin with -p and file argument" \
	"echo 'be sure to handle edge cases carefully' | $FT_SSL md5 -p file" \
	"(\"be sure to handle edge cases carefully\")= 3553dc7dc5963b583c056d1b9fa3349c
MD5 (file) = 53d53ea94217b259c11a5a2d104ec58a"

# Test 8
run_test "Stdin with file argument (no -p)" \
	"echo 'some of this will not make sense at first' | $FT_SSL md5 file" \
	"MD5 (file) = 53d53ea94217b259c11a5a2d104ec58a"

# Test 9
run_test "Stdin with -p -r and file" \
	"echo 'but eventually you will understand' | $FT_SSL md5 -p -r file" \
	"(\"but eventually you will understand\")= dcdd84e0f635694d2a943fa8d3905281
53d53ea94217b259c11a5a2d104ec58a file"

# Test 10
run_test "Stdin with -p, -s, and file" \
	"echo 'GL HF let'\''s go' | $FT_SSL md5 -p -s 'foo' file" \
	"(\"GL HF let's go\")= d1e3cc342b6da09480b27ec57ff243e2
MD5 (\"foo\") = acbd18db4cc2f85cedef654fccc4a4d8
MD5 (file) = 53d53ea94217b259c11a5a2d104ec58a"

# Test 11
run_test "Complex: -r -p -s and file with error" \
	"echo 'one more thing' | $FT_SSL md5 -r -p -s 'foo' file -s 'bar' 2>&1" \
	"(\"one more thing\")= a0bd1876c6f011dd50fae52827f445f5
acbd18db4cc2f85cedef654fccc4a4d8 \"foo\"
53d53ea94217b259c11a5a2d104ec58a file
ft_ssl: md5: -s: No such file or directory
ft_ssl: md5: bar: No such file or directory"

# Test 12
run_test "Quiet mode with -r -q -p and multiple inputs" \
	"echo 'just to be extra clear' | $FT_SSL md5 -r -q -p -s 'foo' file" \
	"just to be extra clear
3ba35f1ea0d170cb3b9a752e3360286c
acbd18db4cc2f85cedef654fccc4a4d8
53d53ea94217b259c11a5a2d104ec58a"

# Summary
echo -e "${BLUE}=== SUMMARY ===${NC}"
echo -e "Total tests: ${YELLOW}$TOTAL${NC}"
echo -e "${GREEN}Passed: $PASSED${NC}"
echo -e "${RED}Failed: $FAILED${NC}"

# Return to original directory and cleanup
cd - > /dev/null
rm -rf "$TEST_DIR"

# Exit with appropriate status
if [ $FAILED -eq 0 ]; then
	echo -e "\n${GREEN}✓ ALL TESTS PASSED${NC}"
	exit 0
else
	echo -e "\n${RED}✗ SOME TESTS FAILED${NC}"
	exit 1
fi
