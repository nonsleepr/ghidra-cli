//! Generate a stripped ELF fixture with known strings, FDEs and vtable slots.
//! rustc --edition 2021 tests/fixtures/discovery_fixture.rs -o /tmp/discovery-fixture
//! /tmp/discovery-fixture /tmp/discovery.elf [--big-endian]
#![allow(dead_code)]
use std::path::Path;

fn put(bytes: &mut [u8], at: usize, value: u64, width: usize) {
    bytes[at..at + width].copy_from_slice(&value.to_le_bytes()[..width]);
}

fn fixture(path: &Path) {
    let mut b = vec![0u8; 0x6300];
    b[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    for (at, value, width) in [
        (16, 2, 2),
        (18, 62, 2),
        (20, 1, 4),
        (24, 0x401000, 8),
        (32, 64, 8),
        (40, 0x6100, 8),
        (52, 64, 2),
        (54, 56, 2),
        (56, 1, 2),
        (58, 64, 2),
        (60, 7, 2),
        (62, 6, 2),
        (64, 1, 4),
        (68, 7, 4),
        (72, 0x1000, 8),
        (80, 0x401000, 8),
        (88, 0x401000, 8),
        (96, 0x5000, 8),
        (104, 0x5000, 8),
        (112, 0x1000, 8),
    ] {
        put(&mut b, at, value, width);
    }
    b[0x1000..0x1040].fill(0x90);
    for (at, target) in [
        (0x1000, 0x402000u64),
        (0x1010, 0x402040),
        (0x1020, 0x402007),
    ] {
        b[at..at + 3].copy_from_slice(&[0x48, 0x8d, 0x15]);
        put(
            &mut b,
            at + 3,
            target.wrapping_sub(0x400000 + at as u64 + 7),
            4,
        );
        b[at + 7] = 0xc3;
    }
    for (at, value) in [
        (0x2000, "Prefix DiscoveryNeedle Tail\0"),
        (0x2040, "another discoveryneedle café\0"),
        (0x2080, "Prefix DiscoveryNeedle Tail\0"),
        (0x20c0, "12FixtureClass\0"),
    ] {
        b[at..at + value.len()].copy_from_slice(value.as_bytes());
    }
    // CIE zR, pcrel sdata4, followed by two FDEs with genuine eight-byte ranges.
    put(&mut b, 0x3000, 16, 4);
    b[0x3008..0x3011].copy_from_slice(&[1, b'z', b'R', 0, 1, 0x78, 16, 1, 0x1b]);
    for (off, start) in [(20, 0x401000u64), (40, 0x401020)] {
        put(&mut b, 0x3000 + off, 16, 4);
        put(&mut b, 0x3004 + off, (off + 4) as u64, 4);
        put(
            &mut b,
            0x3008 + off,
            start.wrapping_sub(0x403008 + off as u64),
            4,
        );
        put(&mut b, 0x300c + off, 8, 4);
    }
    b[0x4000..0x4004].copy_from_slice(&[1, 0x1b, 3, 0x3b]);
    put(&mut b, 0x4004, 0x403000u64.wrapping_sub(0x404004), 4);
    put(&mut b, 0x4008, 2, 4);
    for (off, target) in [
        (12, 0x401000u64),
        (16, 0x403014),
        (20, 0x401020),
        (24, 0x403028),
    ] {
        put(&mut b, 0x4000 + off, target.wrapping_sub(0x404000), 4);
    }
    put(&mut b, 0x5008, 0x4020c0, 8); // typeinfo name
    for (off, value) in [
        (0x5048, 0x405000),
        (0x5050, 0x401000),
        (0x5058, 0x401020),
        (0x5060, 0),
        (0x5068, 0x402000),
        (0x5070, 0xdeadbeef),
        (0x5080, (-16i64) as u64),
        (0x5088, 0x405000),
        (0x5090, 0x401020),
    ] {
        put(&mut b, off, value, 8);
    }
    let names = b"\0.text\0.rodata\0.eh_frame\0.eh_frame_hdr\0.data\0.shstrtab\0";
    b[0x6000..0x6000 + names.len()].copy_from_slice(names);
    for (i, name, flags, offset, size) in [
        (1, 1, 6, 0x1000, 64),
        (2, 7, 2, 0x2000, 256),
        (3, 15, 2, 0x3000, 60),
        (4, 25, 2, 0x4000, 28),
        (5, 39, 3, 0x5000, 160),
        (6, 45, 0, 0x6000, names.len()),
    ] {
        let at = 0x6100 + i * 64;
        for (field, value, width) in [
            (0, name, 4),
            (4, if i == 6 { 3 } else { 1 }, 4),
            (8, flags, 8),
            (16, if i == 6 { 0 } else { 0x400000 + offset }, 8),
            (24, offset, 8),
            (32, size, 8),
            (48, 8, 8),
        ] {
            put(&mut b, at + field, value as u64, width);
        }
    }
    std::fs::write(path, b).unwrap();
}

pub fn write(path: &Path, big_endian: bool) {
    fixture(path);
    if big_endian {
        let mut bytes = std::fs::read(path).unwrap();
        bytes[5] = 2;
        for (at, size) in [
            (16, 2),
            (18, 2),
            (20, 4),
            (24, 8),
            (32, 8),
            (40, 8),
            (48, 4),
            (52, 2),
            (54, 2),
            (56, 2),
            (58, 2),
            (60, 2),
            (62, 2),
            (64, 4),
            (68, 4),
            (72, 8),
            (80, 8),
            (88, 8),
            (96, 8),
            (104, 8),
            (112, 8),
        ] {
            bytes[at..at + size].reverse();
        }
        bytes[18..20].copy_from_slice(&21u16.to_be_bytes()); // PowerPC64
        for i in 0..7 {
            for (field, size) in [
                (0, 4),
                (4, 4),
                (8, 8),
                (16, 8),
                (24, 8),
                (32, 8),
                (40, 4),
                (44, 4),
                (48, 8),
                (56, 8),
            ] {
                let at = 0x6100 + i * 64 + field;
                bytes[at..at + size].reverse();
            }
        }
        for at in [
            0x3000, 0x3004, 0x3014, 0x3018, 0x301c, 0x3020, 0x3028, 0x302c, 0x3030, 0x3034, 0x4004,
            0x4008, 0x400c, 0x4010, 0x4014, 0x4018,
        ] {
            bytes[at..at + 4].reverse();
        }
        for at in [
            0x5008, 0x5048, 0x5050, 0x5058, 0x5060, 0x5068, 0x5070, 0x5080, 0x5088, 0x5090,
        ] {
            bytes[at..at + 8].reverse();
        }
        std::fs::write(path, bytes).unwrap();
    }
}

fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert!(
        (2..=3).contains(&args.len()),
        "Usage: discovery-fixture PATH [--big-endian]"
    );
    if args.len() == 3 {
        assert_eq!(args[2], "--big-endian");
    }
    write(Path::new(&args[1]), args.len() == 3);
}
