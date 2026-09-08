use crate::layer_fields::{set_field, JsonFields};
use serde_json::Value;
use std::{env, path::Path, process::Command};

const TSHARK_PROGRAM_ENV: &str = "NATA_TSHARK";

// Compare every field in the protocol trees represented by Nata. This is a
// protocol-level boundary, not a field allowlist: newly emitted fields under
// one of these trees will be reported until they are handled or deliberately
// ignored below.
const TSHARK_COMPARE_LAYERS: &[&str] = &["frame", "eth", "ip", "ipv6", "tcp", "udp", "icmp"];

// TShark reports useful protocol fields alongside capture metadata, derived
// values, and dissector details that Nata does not currently represent. These
// patterns are intentionally an ignore list rather than a list of fields to
// include. A new field outside this list appears in the JSON diff.
const TSHARK_IGNORE_FIELDS: &[&str] = &[
    "_ws*",
    "data*",
    "frame.section_number",
    "frame.interface_id*",
    "frame.interface_description",
    "frame.encap_type",
    "frame.time*",
    "frame.offset_shift",
    "frame.marked",
    "frame.ignored",
    "frame.protocols",
    "frame.p2p_dir",
    "frame.packet_flags*",
    "eth.addr*",
    "eth.dst.*",
    "eth.dst_resolved",
    "eth.ig",
    "eth.len",
    "eth.lg",
    "eth.padding*",
    "eth.src.*",
    "eth.src_resolved",
    "eth.trailer",
    "ip.addr",
    "ip.checksum.status",
    "ip.dsfield.*",
    "ip.dst_host",
    "ip.flags.*",
    "ip.host",
    "ip.opt*",
    "ip.src_host",
    "ip.ttl.lncb",
    "ipv6.dst_host",
    "ipv6.dst_slaac_mac",
    "ipv6.dstopts*",
    "ipv6.hopopts*",
    "ipv6.opt*",
    "ipv6.addr",
    "ipv6.host",
    "ipv6.slaac_mac",
    "ipv6.src_host",
    "ipv6.src_slaac_mac",
    "ipv6.tclass.*",
    "tcp.ack_raw",
    "tcp.analysis*",
    "tcp.checksum.status",
    "tcp.completeness*",
    "tcp.connection*",
    "tcp.flags.*",
    "tcp.len",
    "tcp.nxtseq",
    "tcp.option*",
    "tcp.options*",
    "tcp.payload",
    "tcp.port",
    "tcp.pdu.size",
    "tcp.reassembled_in",
    "tcp.reset_cause",
    "tcp.segment_data",
    "tcp.seq_raw",
    "tcp.stream",
    "tcp.time*",
    "tcp.window_size",
    "tcp.window_size_scalefactor",
    "udp.checksum.status",
    "udp.payload",
    "udp.port",
    "udp.pdu.size",
    "udp.stream",
    "udp.time*",
    "icmp.checksum.status",
    "icmp.data_time*",
    "icmp.ident_le",
    "icmp.resp_to",
    "icmp.resptime",
    "icmp.seq_le",
    "icmp.unused",
];

pub(crate) fn run_tshark_json(path: &Path) -> Result<Value, String> {
    let program = env::var_os(TSHARK_PROGRAM_ENV).unwrap_or_else(|| "tshark".into());
    let mut command = Command::new(program);
    command
        .arg("-n")
        .arg("-o")
        .arg("tcp.relative_sequence_numbers:FALSE")
        .arg("--no-duplicate-keys")
        .arg("-r")
        .arg(path)
        .arg("-T")
        .arg("json");

    let output = command
        .output()
        .map_err(|error| format!("could not run TShark: {error}"))?;
    if !output.status.success() {
        let status = output
            .status
            .code()
            .map_or_else(|| "signal".to_string(), |code| code.to_string());
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let detail = if stderr.is_empty() {
            String::new()
        } else {
            format!(": {stderr}")
        };
        return Err(format!("TShark exited with status {status}{detail}"));
    }

    let value: Value = serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("could not parse TShark JSON: {error}"))?;
    normalize_tshark_json(value)
}

fn normalize_tshark_json(value: Value) -> Result<Value, String> {
    let packets = value
        .as_array()
        .ok_or_else(|| "TShark JSON root is not an array".to_string())?;
    let mut normalized = Vec::with_capacity(packets.len());

    for (index, packet) in packets.iter().enumerate() {
        let layers = packet
            .get("_source")
            .and_then(|source| source.get("layers"))
            .and_then(Value::as_object)
            .ok_or_else(|| format!("TShark JSON packet {} has no _source.layers", index + 1))?;
        let mut fields = JsonFields::new();
        for (layer_name, layer) in layers {
            if TSHARK_COMPARE_LAYERS.contains(&layer_name.as_str()) {
                flatten_tshark_fields(layer, &mut fields)?;
            }
        }
        normalized.push(fields);
    }

    serde_json::to_value(normalized)
        .map_err(|error| format!("could not normalize TShark JSON: {error}"))
}

fn flatten_tshark_fields(value: &Value, fields: &mut JsonFields) -> Result<(), String> {
    match value {
        Value::Object(object) => {
            for (name, value) in object {
                if is_ignored_tshark_field(name) {
                    continue;
                }

                match value {
                    Value::Object(_) => flatten_tshark_fields(value, fields)?,
                    Value::Array(values) => {
                        if values.iter().all(Value::is_object) {
                            for value in values {
                                flatten_tshark_fields(value, fields)?;
                            }
                        } else {
                            for value in values {
                                set_field(fields, name, json_field_value(value)?);
                            }
                        }
                    }
                    value => {
                        set_field(fields, name, json_field_value(value)?);
                    }
                }
            }
        }
        Value::Array(values) if values.iter().all(Value::is_object) => {
            for value in values {
                flatten_tshark_fields(value, fields)?;
            }
        }
        _ => return Err(format!("TShark protocol tree is not an object: {value}")),
    }

    Ok(())
}

fn is_ignored_tshark_field(name: &str) -> bool {
    name.ends_with("_tree")
        || TSHARK_IGNORE_FIELDS.iter().any(|pattern| {
            pattern
                .strip_suffix('*')
                .map_or(name == *pattern, |prefix| name.starts_with(prefix))
        })
}

fn json_field_value(value: &Value) -> Result<String, String> {
    match value {
        Value::String(value) => Ok(value.clone()),
        Value::Number(value) => Ok(value.to_string()),
        Value::Bool(value) => Ok(value.to_string()),
        Value::Null => Ok("null".to_string()),
        Value::Array(_) | Value::Object(_) => {
            Err(format!("TShark field value is not scalar: {value}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn normalized_tshark_json_flattens_layers_and_applies_ignore_list() {
        let input = json!([{
            "_index": "packets-2026-09-04",
            "_source": {
                "layers": {
                    "frame": {
                        "frame.number": "1",
                        "frame.len": "60",
                        "frame.time": "not comparable"
                    },
                    "ip": {
                        "ip.src": "192.0.2.1",
                        "ip.new_field": "visible",
                        "ip.flags_tree": {
                            "ip.flags.df": "1"
                        }
                    },
                    "tcp": [
                        {"tcp.srcport": "1234"},
                        {"tcp.srcport": "4321"},
                        {"tcp.dstport": "5678"}
                    ],
                    "http": {
                        "http.request.method": "GET"
                    }
                }
            }
        }]);

        assert_eq!(
            json!([{
                "frame.number": ["1"],
                "frame.len": ["60"],
                "ip.new_field": ["visible"],
                "ip.src": ["192.0.2.1"],
                "tcp.dstport": ["5678"],
                "tcp.srcport": ["1234", "4321"]
            }]),
            normalize_tshark_json(input).unwrap()
        );
    }
}
