//! Build script for ghidra-cli.
//!
//! Regenerates `.claude/skills/ghidra-cli/SKILL.fallback.md` whenever
//! `docs/ghidra-cli.1` or `src/cli.rs` changes.  The fallback skill is
//! committed to the repository and used by agents when `man ghidra-cli`
//! is not available (package not installed globally).

use std::io::Write;
use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());

    println!("cargo:rerun-if-changed=docs/ghidra-cli.1");
    println!("cargo:rerun-if-changed=src/cli.rs");

    let man_page = manifest_dir.join("docs").join("ghidra-cli.1");
    let fallback_path = manifest_dir
        .join(".claude")
        .join("skills")
        .join("ghidra-cli")
        .join("SKILL.fallback.md");

    if let Ok(man_content) = std::fs::read_to_string(&man_page) {
        generate_fallback_skill(&man_content, &fallback_path);
    }
}

fn generate_fallback_skill(man: &str, dest: &PathBuf) {
    let plain = man_to_text(man);
    let mut out = Vec::new();

    writeln!(out, "---").unwrap();
    writeln!(out, "name: ghidra-cli").unwrap();
    writeln!(out, "description: >").unwrap();
    writeln!(
        out,
        "    Use ghidra-cli for reverse engineering tasks: binary analysis,"
    )
    .unwrap();
    writeln!(
        out,
        "    decompilation, function inspection, cross-reference analysis,"
    )
    .unwrap();
    writeln!(
        out,
        "    pattern discovery, binary patching, and type system management."
    )
    .unwrap();
    writeln!(
        out,
        "    Activate when the user requests binary analysis, decompilation,"
    )
    .unwrap();
    writeln!(
        out,
        "    function/symbol/xref inspection, patching, or type annotation."
    )
    .unwrap();
    writeln!(out, "---").unwrap();
    writeln!(out).unwrap();
    writeln!(
        out,
        "<!-- AUTO-GENERATED from docs/ghidra-cli.1 by build.rs -->"
    )
    .unwrap();
    writeln!(
        out,
        "<!-- Do not edit by hand. Run `cargo build` or `scripts/regen-skill.sh`. -->"
    )
    .unwrap();
    writeln!(out).unwrap();
    writeln!(out, "# ghidra-cli \u{2014} Fallback Reference").unwrap();
    writeln!(out).unwrap();
    writeln!(
        out,
        "This file is auto-generated for use when `man ghidra-cli` is not available."
    )
    .unwrap();
    writeln!(
        out,
        "For the full reference run `man ghidra-cli` or `ghidra-cli --help`."
    )
    .unwrap();
    writeln!(out).unwrap();

    let sections = [
        ("DESCRIPTION", "Description"),
        ("COMMANDS", "Commands"),
        ("OPTIONS", "Options"),
        ("FILTER EXPRESSIONS", "Filter Expressions"),
        ("FUNCTION TARGETS", "Function Targets"),
        ("EXAMPLES", "Examples"),
        ("ENVIRONMENT", "Environment"),
        ("DIAGNOSTICS", "Diagnostics"),
        ("BUGS", "Known Bugs"),
    ];

    for (troff_name, md_name) in &sections {
        if let Some(body) = extract_section(&plain, troff_name) {
            let trimmed = body.trim();
            if !trimmed.is_empty() {
                writeln!(out, "## {}", md_name).unwrap();
                writeln!(out).unwrap();
                writeln!(out, "{}", trimmed).unwrap();
                writeln!(out).unwrap();
            }
        }
    }

    let tmp = dest.with_extension("md.tmp");
    std::fs::write(&tmp, &out).expect("write SKILL.fallback.md.tmp");
    std::fs::rename(&tmp, dest).expect("rename SKILL.fallback.md");
}

// ---------------------------------------------------------------------------
// Minimal troff -> plain-text converter for the subset used in ghidra-cli.1
// ---------------------------------------------------------------------------

fn man_to_text(troff: &str) -> String {
    let mut out = String::new();
    let mut in_example = false;

    for line in troff.lines() {
        let t = line.trim_start();

        if t.starts_with('.') {
            let tok: Vec<&str> = t.splitn(3, ' ').collect();
            match tok[0] {
                ".TH" => {}
                ".SH" => {
                    let h = strip_esc(
                        tok.get(1..)
                            .map(|p| p.join(" "))
                            .unwrap_or_default()
                            .as_str(),
                    );
                    out.push('\n');
                    out.push_str(&h);
                    out.push('\n');
                    out.push_str(&"-".repeat(h.len()));
                    out.push('\n');
                    in_example = false;
                }
                ".SS" => {
                    let h = strip_esc(
                        tok.get(1..)
                            .map(|p| p.join(" "))
                            .unwrap_or_default()
                            .as_str(),
                    );
                    out.push_str(&format!("\n### {}\n", h));
                }
                ".TP" | ".PP" | ".IP" => out.push('\n'),
                ".EX" => {
                    in_example = true;
                    out.push_str("```\n");
                }
                ".EE" => {
                    in_example = false;
                    out.push_str("```\n");
                }
                ".RS" | ".RE" | ".TS" | ".TE" => {}
                ".B" | ".I" | ".BI" | ".BR" => {
                    let c = strip_esc(
                        tok.get(1..)
                            .map(|p| p.join(" "))
                            .unwrap_or_default()
                            .as_str(),
                    );
                    if !c.is_empty() {
                        out.push_str(&c);
                        out.push('\n');
                    }
                }
                _ => {}
            }
            continue;
        }

        let clean = strip_esc(t);
        if clean.is_empty() {
            if !out.ends_with("\n\n") {
                out.push('\n');
            }
        } else {
            out.push_str(&clean);
            out.push('\n');
        }
    }
    out
}

fn extract_section<'a>(plain: &'a str, name: &str) -> Option<&'a str> {
    let needle = format!("\n{}\n", name);
    let start = plain.find(&needle)?;
    let after_header = start + needle.len();
    // skip underline row
    let underline_end = plain[after_header..]
        .find('\n')
        .map(|i| after_header + i + 1)?;
    let rest = &plain[underline_end..];

    // Find the next section underline (a line of all dashes, len > 2)
    let mut pos: usize = 0;
    let mut prev_newline: usize = 0;
    for line in rest.lines() {
        if line.len() > 2 && line.chars().all(|c| c == '-') && pos > 0 {
            // section ends before the line that was the heading for this new section
            let end = prev_newline.saturating_sub(line.len() + 2);
            return Some(rest[..end].trim_end());
        }
        prev_newline = pos;
        pos += line.len() + 1;
    }
    Some(rest.trim_end())
}

fn strip_esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let b = s.as_bytes();
    let mut i = 0usize;
    while i < b.len() {
        if b[i] == b'\\' && i + 1 < b.len() {
            match b[i + 1] {
                b'f' => {
                    i += 2;
                    if i < b.len() && b[i] == b'[' {
                        while i < b.len() && b[i] != b']' {
                            i += 1;
                        }
                        i += 1;
                    } else {
                        i += 1;
                    }
                }
                b'c' | b'&' => {
                    i += 2;
                }
                b'-' => {
                    out.push('-');
                    i += 2;
                }
                b'(' => {
                    if i + 3 < b.len() {
                        let g = &s[i..i + 4];
                        match g {
                            r"\(bu" => out.push('\u{2022}'),
                            _ => {}
                        }
                        i += 4;
                    } else {
                        i += 1;
                    }
                }
                _ => {
                    out.push('\\');
                    i += 1;
                }
            }
        } else {
            out.push(b[i] as char);
            i += 1;
        }
    }
    out
}
