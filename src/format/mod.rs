use crate::error::{GhidraError, Result};
use serde::Serialize;
use serde_json::Value as JsonValue;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Compact,
    Json,
    Count,
}

impl OutputFormat {
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "compact" => Ok(Self::Compact),
            "json" | "jsonl" | "ndjson" | "json-stream" => Ok(Self::Json),
            "count" => Ok(Self::Count),
            _ => Err(GhidraError::InvalidFormat(format!(
                "Unknown format: {}. Valid formats: compact, json, count",
                s
            ))),
        }
    }
}

pub trait Formatter {
    fn format<T: Serialize>(&self, data: &[T], format: OutputFormat) -> Result<String>;
}

pub struct DefaultFormatter;

impl Formatter for DefaultFormatter {
    fn format<T: Serialize>(&self, data: &[T], format: OutputFormat) -> Result<String> {
        match format {
            OutputFormat::Json => {
                let mut result = String::new();
                for item in data {
                    let json = serde_json::to_string(item)?;
                    result.push_str(&json);
                    result.push('\n');
                }
                Ok(result)
            }
            OutputFormat::Count => Ok(format!("{}", data.len())),
            OutputFormat::Compact => format_compact(data),
        }
    }
}

/// Compact human-readable format: one line per item with key fields.
fn format_compact<T: Serialize>(data: &[T]) -> Result<String> {
    let json_data: Vec<JsonValue> = data
        .iter()
        .map(serde_json::to_value)
        .collect::<std::result::Result<Vec<_>, _>>()?;

    if json_data.is_empty() {
        return Ok("No results".to_string());
    }

    let mut result = String::new();

    for item in &json_data {
        match item {
            JsonValue::Object(map) => {
                // Both successful and failed decompilation carry evidence, even without C code.
                if map.contains_key("code") || map.contains_key("diagnostics") {
                    if let Some(diagnostics) = map.get("diagnostics") {
                        format_decompile_diagnostics(&mut result, diagnostics);
                    } else if let Some(warnings) = map.get("warnings").and_then(|v| v.as_str()) {
                        result.push_str(&format!("Decompiler message: {warnings}\n"));
                    }
                    if let Some(sig) = map.get("signature").and_then(|v| v.as_str()) {
                        result.push_str(sig);
                        result.push('\n');
                    }
                    if let Some(code) = map.get("code").and_then(|v| v.as_str()) {
                        result.push_str(code);
                        if !code.ends_with('\n') {
                            result.push('\n');
                        }
                    }
                    continue;
                }

                // Special case: disasm instruction with mnemonic
                if let (Some(addr), Some(mnem)) = (
                    map.get("address").and_then(|v| v.as_str()),
                    map.get("mnemonic").and_then(|v| v.as_str()),
                ) {
                    let bytes = map.get("bytes").and_then(|v| v.as_str()).unwrap_or("");
                    let operands = match map.get("operands") {
                        Some(JsonValue::Array(ops)) => ops
                            .iter()
                            .map(format_json_value)
                            .collect::<Vec<_>>()
                            .join(", "),
                        _ => String::new(),
                    };
                    let previews = map
                        .get("references")
                        .and_then(|v| v.as_array())
                        .map(|refs| {
                            refs.iter()
                                .filter_map(|r| r.get("string_preview")?.get("value")?.as_str())
                                .map(|s| serde_json::to_string(s).unwrap_or_default())
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default();
                    let annotation = if previews.is_empty() {
                        String::new()
                    } else {
                        format!(" ; {}", previews.join(", "))
                    };
                    result.push_str(&format!(
                        "{:<12} {:<16} {} {}{}\n",
                        addr, bytes, mnem, operands, annotation
                    ));
                    continue;
                }

                // General object: render primary fields in a compact line
                let address = map.get("address").and_then(|v| v.as_str());
                let name = map.get("name").and_then(|v| v.as_str());
                let size = map.get("size").and_then(|v| v.as_u64());
                let value_str = map.get("value").and_then(|v| v.as_str());

                let mut parts: Vec<String> = Vec::new();

                if let Some(addr) = address {
                    parts.push(addr.to_string());
                }
                if let Some(n) = name {
                    parts.push(n.to_string());
                }
                if let Some(s) = size {
                    parts.push(format!("({})", s));
                }
                if let Some(v) = value_str {
                    let preview = if v.chars().take(81).count() > 80 {
                        format!("{}...", v.chars().take(77).collect::<String>())
                    } else {
                        v.to_string()
                    };
                    parts.push(serde_json::to_string(&preview)?);
                }

                if parts.is_empty() {
                    let kv: Vec<String> = map
                        .iter()
                        .map(|(k, v)| format!("{}={}", k, format_json_value(v)))
                        .collect();
                    result.push_str(&kv.join("  "));
                } else {
                    result.push_str(&parts.join("  "));
                }

                let secondary: Vec<String> = map
                    .iter()
                    .filter(|(k, _)| {
                        !matches!(
                            k.as_str(),
                            "address"
                                | "name"
                                | "size"
                                | "value"
                                | "mnemonic"
                                | "bytes"
                                | "operands"
                                | "code"
                                | "signature"
                        )
                    })
                    .filter_map(|(k, v)| {
                        let s = format_json_value(v);
                        if s.is_empty() || s == "null" || s == "\"\"" {
                            None
                        } else {
                            Some(format!("{}={}", k, s))
                        }
                    })
                    .collect();

                if !secondary.is_empty() {
                    result.push_str("  ");
                    result.push_str(&secondary.join("  "));
                }

                result.push('\n');
            }
            _ => {
                result.push_str(&format_json_value(item));
                result.push('\n');
            }
        }
    }

    Ok(result)
}

fn format_decompile_diagnostics(output: &mut String, diagnostics: &JsonValue) {
    let text = |v: &JsonValue| format_json_value(v);
    let decompiler = &diagnostics["decompiler"];
    output.push_str(&format!(
        "Decompiler: {}; semantic completeness: not established\n",
        text(&decompiler["status"])
    ));
    if let Some(message) = decompiler["raw_message"].as_str().filter(|s| !s.is_empty()) {
        output.push_str(&format!("Decompiler message: {message}\n"));
    }
    if let Some(comments) = decompiler["warning_comments"].as_array() {
        for comment in comments {
            output.push_str(&format!("Warning comment: {}\n", text(comment)));
        }
    }
    let database = &diagnostics["database"];
    output.push_str(&format!(
        "Database: {} [source={}, convention={}, custom storage={}, no-return={}, varargs={}]\n",
        text(&database["signature"]),
        text(&database["signature_source"]),
        text(&database["calling_convention"]),
        text(&database["custom_variable_storage"]),
        text(&database["no_return"]),
        text(&database["varargs"])
    ));
    for (label, model) in [
        ("Saved", database),
        ("Recovered", &diagnostics["recovered"]),
    ] {
        if let Some(parameters) = model["parameters"].as_array() {
            output.push_str(&format!("{label} parameters: {}\n", parameters.len()));
            for parameter in parameters {
                let provenance = if label == "Saved" {
                    format!("source={}", text(&parameter["source"]))
                } else {
                    format!(
                        "name locked={}, type locked={}",
                        text(&parameter["name_locked"]),
                        text(&parameter["type_locked"])
                    )
                };
                output.push_str(&format!(
                    "  {} {} @ {} [{provenance}]\n",
                    text(&parameter["type"]),
                    text(&parameter["name"]),
                    text(&parameter["storage"])
                ));
            }
        }
    }
    let body = &diagnostics["body"];
    output.push_str(&format!(
        "Body: {} ranges, {} bytes, contiguous={}\n",
        text(&body["range_count"]),
        text(&body["total_size"]),
        text(&body["is_contiguous"])
    ));
    if let Some(ranges) = body["ranges"].as_array() {
        for range in ranges {
            output.push_str(&format!(
                "  {}..{}\n",
                text(&range["min_address"]),
                text(&range["max_address"])
            ));
        }
    }
    if let Some(hints) = diagnostics["inspection_hints"].as_object() {
        output.push_str("Inspect (same project/program): ");
        output.push_str(&hints.values().map(text).collect::<Vec<_>>().join("; "));
        output.push('\n');
    }
}

fn format_json_value(value: &JsonValue) -> String {
    match value {
        JsonValue::Null => "null".to_string(),
        JsonValue::Bool(b) => b.to_string(),
        JsonValue::Number(n) => n.to_string(),
        JsonValue::String(s) => s.clone(),
        JsonValue::Array(arr) => {
            format!(
                "[{}]",
                arr.iter()
                    .map(format_json_value)
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }
        JsonValue::Object(_) => serde_json::to_string(value).unwrap_or_else(|_| "{}".to_string()),
    }
}

pub fn auto_detect_format(is_tty: bool) -> OutputFormat {
    if is_tty {
        OutputFormat::Compact
    } else {
        OutputFormat::Json
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_format_json() {
        let data = vec![json!({"name": "test", "value": 123})];
        let formatter = DefaultFormatter;
        let result = formatter.format(&data, OutputFormat::Json).unwrap();
        assert!(result.contains("test"));
    }

    #[test]
    fn string_rows_truncate_on_character_boundaries_and_escape_controls() {
        let data = vec![json!({"address":"00402000", "value":format!("é\n{}", "é".repeat(90))})];
        let output = DefaultFormatter
            .format(&data, OutputFormat::Compact)
            .unwrap();
        assert_eq!(output.lines().count(), 1);
        assert!(output.contains(r"é\n"));
        assert!(output.contains("..."));
    }

    #[test]
    fn disassembly_previews_escape_control_characters() {
        let data = vec![
            json!({"address":"00401000", "mnemonic":"LEA", "bytes":"488d15", "operands":["RDX"], "references":[{"string_preview":{"value":"line\n\"quoted\" café"}}]}),
        ];
        let output = DefaultFormatter
            .format(&data, OutputFormat::Compact)
            .unwrap();
        assert_eq!(output.lines().count(), 1);
        assert!(output.contains(r#"; "line\n\"quoted\" café""#));
    }

    #[test]
    fn compact_decompile_keeps_raw_messages_and_legacy_warnings() {
        let warning = "WARNING: incomplete recovery\nraw second line";
        let legacy = serde_json::json!({"code":"int f(void) { return 0; }", "warnings":warning});
        let output = DefaultFormatter
            .format(&[legacy], OutputFormat::Compact)
            .unwrap();
        assert!(output.contains(warning));
        assert!(output.contains("int f(void)"));
        let value = serde_json::json!({"code":"int f(void) { return 0; }", "diagnostics":{
            "decompiler":{"status":"completed","raw_message":warning},
            "database":{"signature":"int f(void)","parameters":[]},
            "recovered":{"parameters":[{"name":"value","type":"int","storage":"EDI:4",
                "name_locked":true,"type_locked":true}]},
            "body":{"range_count":2,"total_size":3,"is_contiguous":false,
                "ranges":[{"min_address":"00401000","max_address":"00401001"},
                          {"min_address":"00401008","max_address":"00401008"}]}
        }});
        let output = DefaultFormatter
            .format(&[value], OutputFormat::Compact)
            .unwrap();
        assert!(output.contains(warning));
        assert!(output.contains("contiguous=false"));
        assert!(output.contains("00401008..00401008"));
        assert!(output.contains("int value @ EDI:4"));
        assert!(output.contains("type locked=true"));
        assert!(output.contains("semantic completeness: not established"));
    }

    #[test]
    fn test_format_count() {
        let data = vec![json!({"name": "test1"}), json!({"name": "test2"})];
        let formatter = DefaultFormatter;
        let result = formatter.format(&data, OutputFormat::Count).unwrap();
        assert_eq!(result, "2");
    }
}
