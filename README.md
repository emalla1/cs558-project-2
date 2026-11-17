# [CS 558] Project 2

**Author:** Eric Malla\
**B-Number:** B00945592

**Project 2** implements a buffer overflow attack string generator. The
program generates a binary payload and writes it to a file, which can then be
piped into a vulnerable target program to either redirect execution to a target
function or launch a shell via injected shellcode.

The implementation of the program can be found in `src/main.rs`.

## Getting Started

### Prerequisites

The Rust programming language and its package manager Cargo must be installed
in order to build and run this program. More information on doing so in your
specific environment can be found on the Rust website's "[Install
Rust](https://rust-lang.org/tools/install/)" page.

In addition, the vulnerable program must be compiled using the following
command:

```bash
gcc -fno-stack-protector -z execstack -fno-pie -no-pie -m32 \
    -O0 -g vuln_program.c -o vuln_program
```

### Building

To build the program, run the following command:

```bash
cargo build
```

This produces an executable at `./target/debug/cs558-project-2` (or
`.\target\debug\cs558-project-2.exe` on Windows).

## Usage

To execute the program, run the command corresponding to your specific
operating system:

- **Windows**: `.\target\debug\cs558-project-2.exe <mode> [args]`
- **macOS**: `./target/debug/cs558-project-2 <mode> [args]`
- **Linux**: `./target/debug/cs558-project-2 <mode> [args]`

Alternatively, you can build and run in a single step with Cargo:

```bash
cargo run -- <mode> [args]
```

> [!NOTE]
> `<mode>` and `[args]` should be substituted with actual values, as described
> in [Input](#input) below.

### Input

The program supports two modes of operation:

**Part 1: redirect execution to a target function:**

```bash
cargo run -- <target_addr>
```

- **`target_addr`**: the address of the target function as a hexadecimal
  string (with or without a `0x` prefix).

This writes the payload to a file named `attack_string`. Verify with:

```bash
./vuln_program < attack_string
```

**Part 2: inject shellcode to launch a shell:**

```bash
cargo run -- shellcode <guessed_addr>
```

- **`guessed_addr`**: a guessed stack address pointing into the NOP sled, as a
  hexadecimal string. Use GDB to find a suitable value.

This writes the payload to a file named `shell_string`. Verify with:

```bash
setarch $(uname -m) -R ./vuln_program < shell_string
```

For example, running:

```bash
cargo run -- 080491a6
```

produces the file `attack_string`, and piping it into the vulnerable program:

```bash
./vuln_program < attack_string
```

produces the output:

```text
"You have entered the correct passwd"
```
