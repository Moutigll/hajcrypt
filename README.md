# Hajcrypt

Hajcrypt is a high-performance cryptographic hash library written in C, designed for both integration as a library and usage through a command-line interface (CLI). It provides optimized implementations of

- **MD5**
- **SHA-256**
- **Whirlpool**

with support for streaming data, large files, and multiple input sources.

## Features

### Library

- Fully modular C library exposing a clean hash API:
  - `init`, `update`, `final` functions for MD5, SHA-256, and Whirlpool.
  - Streaming hash support for large or incremental data.
  - Optimized transforms using precomputed tables for speed.
  - Generic padding and endian handling for different hash algorithms.
- Optimized for performance:
  - MD5 fully unrolled 64-round transform.
  - SHA-256 with ARMv8 crypto instruction acceleration (conditional).
  - Whirlpool T-table optimization for rapid block processing.
- Clean separation of constants and algorithm logic.
- Minimal dynamic memory usage; mostly stack-allocated buffers.

### Command-Line Interface (CLI)

- Executable: `ft_ssl`
- Supports the following algorithms:
  - `md5`
  - `sha256`
  - `whirlpool`
- Flexible input options:
  - Standard input (`stdin`) with streaming.
  - File inputs.
  - Direct string input with `-s`.
- Flags:
  - `-p` : Echo STDIN to STDOUT and append checksum.
  - `-q` : Quiet mode (only outputs digest).
  - `-r` : Reverse output format (`digest filename`).
  - `-s` : Hash the given string.
- Detailed and consistent error messages.
- Fully tested CLI with `cliTester.sh` script.

### Testing

- Comprehensive test suite included under `tests/`:
  - MD5, SHA-256, Whirlpool test vectors.
  - Streaming input, file input, string input.
  - Flag combinations (-p, -q, -r, -s) thoroughly tested.
  - Color-coded output and summary.
- Easy to run with:

```bash
make test
./cliTester.sh
```

### Performance Benchmark

- Benchmarks against:
  - OpenSSL for MD5 and SHA-256.
  - rhash for Whirlpool.
- Supports large files from 1 MB to multiple GBs.
- Generates an HTML report with interactive performance graphs.

## Installation

Clone the repository and build with `Makefile`:

```bash
git clone <repo_url>
cd hajcrypt
make
```

This will build:

- `libhajcrypt.a` : the static library.
- `ft_ssl` : the CLI executable.

Optional flags in the Makefile:

- `test` to run the tests for the lib.
- `leak` to add flags to monitor leaks.

## Usage

### As a library

```C
#include "md5.h"
#include "sha256.h"
#include "whirlpool.h"

uint8_t digest[32];
t_md5Ctx ctx;

md5Init(&ctx);
md5Update(&ctx, input, length);
md5Final(digest, &ctx);
```

### CLI

```bash
./ft_ssl md5 -p -s "Hello, world!" file.txt
```

- Multiple flags can be combined for flexible formatting.
- Default reads from STDIN if no input files or strings are provided, submit with ctr+d.

## Project Structure

```bash
hajcrypt/
├── includes/
│   ├── cli/            # CLI structs and parser
│   ├── hash/           # Hash API headers
│   └── consts/         # Header generation for constants most of them are generated at compile time
├── src/
│   ├── cli/            # CLI implementation
│   ├── hash/           # Hash function implementations
│   └── consts/         # Constant generation sources
├── tests/              # Test framework and vectors
├── cliTester.sh        # Automated CLI tests
├── Makefile
└── sources.mk
```

## Contributing

- Try to follow 42 norms: small functions, camelCase for C functions, clear comments in English.
- Submit pull requests for new hash algorithms or optimizations.
- Include tests for all new features.

## License

GPL 3 – free to use, modify, and distribute.
