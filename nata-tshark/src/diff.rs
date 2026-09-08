use serde_json::{json, Value};
use std::{collections::BTreeSet, io::Write};

pub(crate) fn write_json_value<W: Write>(output: &mut W, value: &Value) -> Result<i32, String> {
    serde_json::to_writer_pretty(&mut *output, value)
        .map_err(|error| format!("could not write JSON: {error}"))?;
    output
        .write_all(b"\n")
        .map_err(|error| format!("could not write JSON: {error}"))?;
    Ok(0)
}

pub(crate) fn write_json_section<W: Write>(
    output: &mut W,
    title: &str,
    result: &Result<Value, String>,
) -> Result<(), String> {
    write_json_value_section(output, title, &result_json(result))
}

pub(crate) fn write_json_value_section<W: Write>(
    output: &mut W,
    title: &str,
    value: &Value,
) -> Result<(), String> {
    writeln!(output, "=== {title} ===")
        .map_err(|error| format!("could not write comparison heading: {error}"))?;
    serde_json::to_writer_pretty(&mut *output, value)
        .map_err(|error| format!("could not write comparison JSON: {error}"))?;
    output
        .write_all(b"\n")
        .map_err(|error| format!("could not terminate comparison JSON: {error}"))?;
    Ok(())
}

fn result_json(result: &Result<Value, String>) -> Value {
    match result {
        Ok(value) => value.clone(),
        Err(error) => json!({ "error": error }),
    }
}

pub(crate) fn json_diff(nata: &Result<Value, String>, tshark: &Result<Value, String>) -> Value {
    match (nata, tshark) {
        (Ok(nata), Ok(tshark)) => json_value_diff(nata, tshark),
        _ => json!([{
            "kind": "result",
            "nata": result_json(nata),
            "tshark": result_json(tshark),
        }]),
    }
}

fn json_value_diff(nata: &Value, tshark: &Value) -> Value {
    let (Some(nata_packets), Some(tshark_packets)) = (nata.as_array(), tshark.as_array()) else {
        return if nata == tshark {
            json!([])
        } else {
            json!([{
                "kind": "root",
                "nata": nata,
                "tshark": tshark,
            }])
        };
    };

    let mut differences = Vec::new();
    if nata_packets.len() != tshark_packets.len() {
        differences.push(json!({
            "kind": "packet_count",
            "nata": nata_packets.len(),
            "tshark": tshark_packets.len(),
        }));
    }

    for (packet_index, (nata_packet, tshark_packet)) in
        nata_packets.iter().zip(tshark_packets).enumerate()
    {
        let (Some(nata_fields), Some(tshark_fields)) =
            (nata_packet.as_object(), tshark_packet.as_object())
        else {
            if nata_packet != tshark_packet {
                differences.push(json!({
                    "kind": "packet",
                    "packet": packet_index + 1,
                    "nata": nata_packet,
                    "tshark": tshark_packet,
                }));
            }
            continue;
        };

        let mut field_names = BTreeSet::new();
        field_names.extend(nata_fields.keys());
        field_names.extend(tshark_fields.keys());

        for field_name in field_names {
            let nata_value = nata_fields.get(field_name);
            let tshark_value = tshark_fields.get(field_name);
            if nata_value != tshark_value {
                differences.push(json!({
                    "kind": "field",
                    "packet": packet_index + 1,
                    "field": field_name,
                    "nata": nata_value.cloned().unwrap_or(Value::Null),
                    "tshark": tshark_value.cloned().unwrap_or(Value::Null),
                }));
            }
        }
    }

    Value::Array(differences)
}

pub(crate) fn write_readable_diff_section<W: Write>(
    output: &mut W,
    title: &str,
    diff: &Value,
    color: bool,
) -> Result<(), String> {
    writeln!(output, "=== {title} ===")
        .map_err(|error| format!("could not write readable diff heading: {error}"))?;

    let Some(differences) = diff.as_array() else {
        writeln!(output, "@@ root @@")
            .map_err(|error| format!("could not write readable diff: {error}"))?;
        return write_readable_diff_values(output, diff, color);
    };

    for difference in differences {
        let kind = difference
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or("difference");
        let heading = match kind {
            "field" => {
                let packet = difference
                    .get("packet")
                    .and_then(Value::as_u64)
                    .unwrap_or_default();
                let field = difference
                    .get("field")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                format!("packet {packet}, field {field}")
            }
            "packet_count" => "packet count".to_string(),
            "packet" => {
                let packet = difference
                    .get("packet")
                    .and_then(Value::as_u64)
                    .unwrap_or_default();
                format!("packet {packet}")
            }
            _ => kind.to_string(),
        };
        writeln!(output, "@@ {heading} @@")
            .map_err(|error| format!("could not write readable diff: {error}"))?;
        write_readable_diff_values(output, difference, color)?;
    }

    Ok(())
}

fn write_readable_diff_values<W: Write>(
    output: &mut W,
    difference: &Value,
    color: bool,
) -> Result<(), String> {
    let nata = difference.get("nata").unwrap_or(&Value::Null);
    let tshark = difference.get("tshark").unwrap_or(&Value::Null);
    write_readable_diff_value(output, '-', "Nata", nata, color, "\x1b[31m")?;
    write_readable_diff_value(output, '+', "TShark", tshark, color, "\x1b[32m")
}

fn write_readable_diff_value<W: Write>(
    output: &mut W,
    marker: char,
    label: &str,
    value: &Value,
    color: bool,
    color_code: &str,
) -> Result<(), String> {
    let value = serde_json::to_string(value)
        .map_err(|error| format!("could not serialize readable diff value: {error}"))?;
    let line = format!("{marker} {label:6}: {value}");
    if color {
        write!(output, "{color_code}{line}\x1b[0m")
            .map_err(|error| format!("could not write readable diff: {error}"))?;
    } else {
        output
            .write_all(line.as_bytes())
            .map_err(|error| format!("could not write readable diff: {error}"))?;
    }
    output
        .write_all(b"\n")
        .map_err(|error| format!("could not write readable diff: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn json_diff_reports_packet_field_changes() {
        let nata = json!([{
            "frame.number": ["1"],
            "ip.src": ["192.0.2.1"]
        }]);
        let tshark = json!([{
            "frame.number": ["1"],
            "ip.src": ["192.0.2.2"],
            "ip.dst": ["192.0.2.3"]
        }]);

        assert_eq!(
            json!([
                {
                    "kind": "field",
                    "packet": 1,
                    "field": "ip.dst",
                    "nata": null,
                    "tshark": ["192.0.2.3"]
                },
                {
                    "kind": "field",
                    "packet": 1,
                    "field": "ip.src",
                    "nata": ["192.0.2.1"],
                    "tshark": ["192.0.2.2"]
                }
            ]),
            json_value_diff(&nata, &tshark)
        );
    }

    #[test]
    fn json_diff_reports_packet_count_changes() {
        assert_eq!(
            json!([{
                "kind": "packet_count",
                "nata": 0,
                "tshark": 2
            }]),
            json_value_diff(&json!([]), &json!([{}, {}]))
        );
    }
}
