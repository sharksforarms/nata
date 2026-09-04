mod layer_fields;

use clap::{Args, Parser, Subcommand};
use layer_fields::{set_field, set_layer_fields, JsonFields};
use nata::{
    datalink::pcapfile::{CapturePacket, PcapFileReader},
    layer::{
        ether::Ether,
        ip::{Ipv4, Ipv6},
    },
    packet::{Packet, PacketParser},
};
use pcap_file::DataLink;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    io::{IsTerminal, Write},
    path::{Path, PathBuf},
    process::{self, Command},
};

const WIRESHARK_TESTS_DIR: &str = "test/captures";
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExpectedStatus {
    Pass,
    Xfail,
    Skip,
}

#[derive(Debug)]
enum Observed {
    Pass,
    Fail(String),
}

#[derive(Default)]
struct SuiteCounts {
    pass: usize,
    xfail: usize,
    skip: usize,
    fail: usize,
    xpass: usize,
    unclassified: usize,
}

#[derive(Debug, Parser)]
#[command(
    name = "nata-tshark",
    about = "Compare Nata packet parsing with TShark JSON",
    arg_required_else_help = true
)]
struct Cli {
    #[command(subcommand)]
    command: CliCommand,
}

#[derive(Debug, Subcommand)]
enum CliCommand {
    /// Render Nata's common packet fields as JSON.
    Json(JsonArgs),
    /// Run the compatibility suite against a Wireshark checkout.
    Suite(SuiteArgs),
    /// Compare one capture's Nata and TShark JSON projections.
    Compare(CompareArgs),
}

#[derive(Debug, Args)]
struct JsonArgs {
    #[arg(value_name = "CAPTURE")]
    capture: PathBuf,
}

#[derive(Debug, Args)]
struct SuiteArgs {
    #[arg(value_name = "WIRESHARK_CHECKOUT")]
    corpus_dir: PathBuf,
    #[arg(value_name = "EXPECTATIONS_FILE")]
    expectations_file: PathBuf,
    #[arg(long, value_name = "CAPTURE")]
    only: Option<String>,
}

#[derive(Debug, Args)]
struct CompareArgs {
    #[arg(value_name = "WIRESHARK_CHECKOUT")]
    corpus_dir: PathBuf,
    #[arg(value_name = "CAPTURE")]
    capture: String,
}

fn main() {
    match run(Cli::parse()) {
        Ok(exit_code) => process::exit(exit_code),
        Err(error) => {
            eprintln!("error: {error}");
            process::exit(2);
        }
    }
}

fn run(cli: Cli) -> Result<i32, String> {
    match cli.command {
        CliCommand::Json(args) => run_json_command(&args.capture),
        CliCommand::Suite(args) => run_suite_command(
            &args.corpus_dir,
            &args.expectations_file,
            args.only.as_deref(),
        ),
        CliCommand::Compare(args) => run_compare_command(&args.corpus_dir, &args.capture),
    }
}

fn run_json_command(capture_path: &Path) -> Result<i32, String> {
    let capture = read_capture(capture_path)?;
    let value = render_json(&capture)?;
    let mut stdout = std::io::stdout();
    write_json_value(&mut stdout, &value)
}

fn run_suite_command(
    corpus_dir: &Path,
    expectations_file: &Path,
    only: Option<&str>,
) -> Result<i32, String> {
    run_suite(corpus_dir, expectations_file, only)
}

fn run_compare_command(corpus_dir: &Path, capture_name: &str) -> Result<i32, String> {
    let capture_path = capture_path(corpus_dir, capture_name)?;
    let nata = read_capture(&capture_path).and_then(|capture| render_json(&capture));
    let tshark = run_tshark_json(&capture_path);
    let matches = match (&nata, &tshark) {
        (Ok(nata), Ok(tshark)) => nata == tshark,
        _ => false,
    };

    let mut stdout = std::io::stdout();
    write_json_section(&mut stdout, &format!("Nata JSON: {capture_name}"), &nata)?;
    write_json_section(
        &mut stdout,
        &format!("TShark JSON: {capture_name}"),
        &tshark,
    )?;

    if !matches {
        let diff = json_diff(&nata, &tshark);
        let color = stdout.is_terminal();
        write_json_value_section(&mut stdout, &format!("JSON diff: {capture_name}"), &diff)?;
        write_readable_diff_section(
            &mut stdout,
            &format!("Readable JSON diff: {capture_name}"),
            &diff,
            color,
        )?;
    }
    println!("comparison: {}", if matches { "MATCH" } else { "MISMATCH" });

    Ok(if matches { 0 } else { 1 })
}

fn run_suite(
    corpus_dir: &Path,
    expectations_file: &Path,
    only: Option<&str>,
) -> Result<i32, String> {
    let expectations = read_expectations(expectations_file)?;
    validate_expectations(corpus_dir, &expectations)?;

    let selected: Vec<(&String, &ExpectedStatus)> = expectations
        .iter()
        .filter(|(name, _)| only.is_none_or(|only| only == name.as_str()))
        .collect();

    if selected.is_empty() {
        return Err(match only {
            Some(name) => format!("unknown capture {name}"),
            None => "expectations file contains no captures".to_string(),
        });
    }

    println!(
        "TShark JSON compatibility suite: {} capture(s)",
        selected.len()
    );

    let mut counts = SuiteCounts::default();
    for (name, expected_status) in selected {
        if *expected_status == ExpectedStatus::Skip {
            counts.skip += 1;
            println!("SKIP  {name}");
            continue;
        }

        let observed = run_case(&capture_path(corpus_dir, name)?);
        match expected_status {
            ExpectedStatus::Pass => match observed {
                Observed::Pass => {
                    counts.pass += 1;
                    println!("PASS  {name}");
                }
                Observed::Fail(reason) => {
                    counts.fail += 1;
                    println!("FAIL  {name}: {reason}");
                }
            },
            ExpectedStatus::Xfail => match observed {
                Observed::Pass => {
                    counts.xpass += 1;
                    println!("XPASS {name}");
                }
                Observed::Fail(reason) => {
                    counts.xfail += 1;
                    println!("XFAIL {name}: {reason}");
                }
            },
            ExpectedStatus::Skip => unreachable!(),
        }
    }

    println!();
    println!(
        "summary: {} pass, {} expected failure, {} skipped, {} failure, {} unexpected pass, {} unclassified",
        counts.pass,
        counts.xfail,
        counts.skip,
        counts.fail,
        counts.xpass,
        counts.unclassified
    );

    if counts.fail == 0 && counts.xpass == 0 && counts.unclassified == 0 {
        Ok(0)
    } else {
        Ok(1)
    }
}

fn run_case(path: &Path) -> Observed {
    let nata = read_capture(path).and_then(|capture| render_json(&capture));
    let tshark = run_tshark_json(path);

    match (nata, tshark) {
        (Ok(nata), Ok(tshark)) if nata == tshark => Observed::Pass,
        (Err(error), _) => Observed::Fail(format!("Nata JSON generation failed: {error}")),
        (_, Err(error)) => Observed::Fail(format!("TShark JSON generation failed: {error}")),
        (Ok(_), Ok(_)) => Observed::Fail("JSON mismatch".to_string()),
    }
}

fn read_expectations(path: &Path) -> Result<BTreeMap<String, ExpectedStatus>, String> {
    let contents = fs::read_to_string(path)
        .map_err(|error| format!("could not read {}: {error}", path.display()))?;
    let mut expectations = BTreeMap::new();

    for (line_number, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() != 2 {
            return Err(format!(
                "invalid expectations line {}: expected exactly capture name and pass/xfail/skip status",
                line_number + 1
            ));
        }

        let status = match fields[1] {
            "pass" => ExpectedStatus::Pass,
            "xfail" => ExpectedStatus::Xfail,
            "skip" => ExpectedStatus::Skip,
            status => {
                return Err(format!(
                    "invalid expectations status {status} on line {}",
                    line_number + 1
                ));
            }
        };

        let name = fields[0].to_string();
        if expectations.insert(name.clone(), status).is_some() {
            return Err(format!("duplicate expectation for {name}"));
        }
    }

    Ok(expectations)
}

fn validate_expectations(
    corpus_dir: &Path,
    expectations: &BTreeMap<String, ExpectedStatus>,
) -> Result<(), String> {
    for name in expectations.keys() {
        let path = capture_path(corpus_dir, name)?;
        if !path.is_file() {
            return Err(format!(
                "expectations contain capture absent from Wireshark checkout: {}",
                path.display()
            ));
        }
    }
    Ok(())
}

fn capture_path(corpus_dir: &Path, name: &str) -> Result<PathBuf, String> {
    if name.is_empty() || Path::new(name).is_absolute() {
        return Err(format!("invalid capture name {name:?}"));
    }
    let path = corpus_dir.join(WIRESHARK_TESTS_DIR).join(name);
    if path
        .components()
        .any(|component| component == std::path::Component::ParentDir)
    {
        return Err(format!("capture name escapes test/captures: {name}"));
    }
    Ok(path)
}

fn read_capture(path: &Path) -> Result<Vec<CapturePacket>, String> {
    let filename = path
        .to_str()
        .ok_or_else(|| format!("capture path is not valid UTF-8: {}", path.display()))?;
    let mut reader = PcapFileReader::new(filename, PacketParser::new())
        .map_err(|error| format!("could not open capture {}: {error:?}", path.display()))?;
    let mut packets = Vec::new();

    while let Some(packet) = reader
        .next_capture_packet()
        .map_err(|error| format!("could not read capture {}: {error:?}", path.display()))?
    {
        packets.push(packet);
    }

    Ok(packets)
}

fn parse_packet(parser: &PacketParser, capture_packet: &CapturePacket) -> Result<Packet, String> {
    let data = capture_packet.data.as_slice();
    let parsed = match capture_packet.link_type {
        DataLink::ETHERNET => parser.parse_packet::<Ether>(data).map(|(_, packet)| packet),
        DataLink::IPV4 => parser.parse_packet::<Ipv4>(data).map(|(_, packet)| packet),
        DataLink::IPV6 => parser.parse_packet::<Ipv6>(data).map(|(_, packet)| packet),
        DataLink::RAW => match data.first().map(|byte| byte >> 4) {
            Some(4) => parser.parse_packet::<Ipv4>(data).map(|(_, packet)| packet),
            Some(6) => parser.parse_packet::<Ipv6>(data).map(|(_, packet)| packet),
            Some(version) => return Err(format!("unsupported raw IP version {version}")),
            None => return Err("empty raw packet".to_string()),
        },
        link_type => return Err(format!("unsupported link type {link_type:?}")),
    };

    parsed.map_err(|error| format!("Nata packet parse failed: {error:?}"))
}

fn render_json(capture: &[CapturePacket]) -> Result<Value, String> {
    let parser = PacketParser::new();
    let mut packets = Vec::with_capacity(capture.len());

    for (index, capture_packet) in capture.iter().enumerate() {
        let packet = parse_packet(&parser, capture_packet)?;
        packets.push(packet_fields(&packet, capture_packet, index + 1)?);
    }

    serde_json::to_value(packets).map_err(|error| format!("could not serialize Nata JSON: {error}"))
}

fn packet_fields(
    packet: &Packet,
    capture_packet: &CapturePacket,
    packet_number: usize,
) -> Result<JsonFields, String> {
    let mut fields = JsonFields::new();
    set_field(&mut fields, "frame.number", packet_number.to_string());
    set_field(
        &mut fields,
        "frame.len",
        capture_packet.original_len.to_string(),
    );
    set_field(
        &mut fields,
        "frame.cap_len",
        capture_packet.data.len().to_string(),
    );

    for layer in packet.layers() {
        set_layer_fields(layer.as_ref(), &mut fields)?;
    }

    Ok(fields)
}

fn run_tshark_json(path: &Path) -> Result<Value, String> {
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
                            let values = values
                                .iter()
                                .map(json_field_value)
                                .collect::<Result<Vec<_>, _>>()?;
                            fields.insert(name.clone(), values);
                        }
                    }
                    value => {
                        fields.insert(name.clone(), vec![json_field_value(value)?]);
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

fn write_json_value<W: Write>(output: &mut W, value: &Value) -> Result<i32, String> {
    serde_json::to_writer_pretty(&mut *output, value)
        .map_err(|error| format!("could not write JSON: {error}"))?;
    output
        .write_all(b"\n")
        .map_err(|error| format!("could not write JSON: {error}"))?;
    Ok(0)
}

fn write_json_section<W: Write>(
    output: &mut W,
    title: &str,
    result: &Result<Value, String>,
) -> Result<(), String> {
    write_json_value_section(output, title, &result_json(result))
}

fn write_json_value_section<W: Write>(
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

fn json_diff(nata: &Result<Value, String>, tshark: &Result<Value, String>) -> Value {
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

fn write_readable_diff_section<W: Write>(
    output: &mut W,
    title: &str,
    diff: &Value,
    color: bool,
) -> Result<(), String> {
    writeln!(output, "=== {title} ===")
        .map_err(|error| format!("could not write readable diff heading: {error}"))?;

    let Some(differences) = diff.as_array() else {
        return write_readable_diff_entry(output, "root", diff, color);
    };

    for difference in differences {
        let kind = difference
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or("difference");
        match kind {
            "field" => {
                let packet = difference
                    .get("packet")
                    .and_then(Value::as_u64)
                    .unwrap_or_default();
                let field = difference
                    .get("field")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                writeln!(output, "@@ packet {packet}, field {field} @@")
                    .map_err(|error| format!("could not write readable diff: {error}"))?;
                write_readable_diff_values(output, difference, color)?;
            }
            "packet_count" => {
                writeln!(output, "@@ packet count @@")
                    .map_err(|error| format!("could not write readable diff: {error}"))?;
                write_readable_diff_values(output, difference, color)?;
            }
            "packet" => {
                let packet = difference
                    .get("packet")
                    .and_then(Value::as_u64)
                    .unwrap_or_default();
                writeln!(output, "@@ packet {packet} @@")
                    .map_err(|error| format!("could not write readable diff: {error}"))?;
                write_readable_diff_values(output, difference, color)?;
            }
            "result" | "root" | "difference" => {
                writeln!(output, "@@ {kind} @@")
                    .map_err(|error| format!("could not write readable diff: {error}"))?;
                write_readable_diff_values(output, difference, color)?;
            }
            _ => write_readable_diff_entry(output, kind, difference, color)?,
        }
    }

    Ok(())
}

fn write_readable_diff_entry<W: Write>(
    output: &mut W,
    label: &str,
    difference: &Value,
    color: bool,
) -> Result<(), String> {
    writeln!(output, "@@ {label} @@")
        .map_err(|error| format!("could not write readable diff: {error}"))?;
    write_readable_diff_values(output, difference, color)
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
                "tcp.srcport": ["1234"]
            }]),
            normalize_tshark_json(input).unwrap()
        );
    }

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
