use crate::{diff, nata_json, suite, tshark_json};
use clap::{Args, Parser, Subcommand};
use std::{
    io::IsTerminal,
    path::{Path, PathBuf},
};

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

pub(crate) fn run() -> Result<i32, String> {
    match Cli::parse().command {
        CliCommand::Json(args) => run_json_command(&args.capture),
        CliCommand::Suite(args) => suite::run_suite(
            &args.corpus_dir,
            &args.expectations_file,
            args.only.as_deref(),
        ),
        CliCommand::Compare(args) => run_compare_command(&args.corpus_dir, &args.capture),
    }
}

fn run_json_command(capture_path: &Path) -> Result<i32, String> {
    let capture = nata_json::read_capture(capture_path)?;
    let value = nata_json::render_json(&capture)?;
    let mut stdout = std::io::stdout();
    diff::write_json_value(&mut stdout, &value)
}

fn run_compare_command(corpus_dir: &Path, capture_name: &str) -> Result<i32, String> {
    let capture_path = suite::capture_path(corpus_dir, capture_name)?;
    let nata =
        nata_json::read_capture(&capture_path).and_then(|capture| nata_json::render_json(&capture));
    let tshark = tshark_json::run_tshark_json(&capture_path);
    let matches = match (&nata, &tshark) {
        (Ok(nata), Ok(tshark)) => nata == tshark,
        _ => false,
    };

    let mut stdout = std::io::stdout();
    diff::write_json_section(&mut stdout, &format!("Nata JSON: {capture_name}"), &nata)?;
    diff::write_json_section(
        &mut stdout,
        &format!("TShark JSON: {capture_name}"),
        &tshark,
    )?;

    if !matches {
        let diff = diff::json_diff(&nata, &tshark);
        let color = stdout.is_terminal();
        diff::write_json_value_section(&mut stdout, &format!("JSON diff: {capture_name}"), &diff)?;
        diff::write_readable_diff_section(
            &mut stdout,
            &format!("Readable JSON diff: {capture_name}"),
            &diff,
            color,
        )?;
    }
    println!("comparison: {}", if matches { "MATCH" } else { "MISMATCH" });

    Ok(if matches { 0 } else { 1 })
}
