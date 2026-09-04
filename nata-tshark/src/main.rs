mod cli;
mod diff;
mod layer_fields;
mod nata_json;
mod suite;
mod tshark_json;

fn main() {
    match cli::run() {
        Ok(exit_code) => std::process::exit(exit_code),
        Err(error) => {
            eprintln!("error: {error}");
            std::process::exit(2);
        }
    }
}
