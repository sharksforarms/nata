use crate::{nata_json, tshark_json};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

const WIRESHARK_TESTS_DIR: &str = "test/captures";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExpectedStatus {
    Pass,
    Xfail,
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
    fail: usize,
    xpass: usize,
    unclassified: usize,
}

pub(crate) fn run_suite(
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

    let unclassified = if only.is_none() {
        unclassified_captures(corpus_dir, &expectations)?
    } else {
        Vec::new()
    };

    let mut counts = SuiteCounts::default();
    for (name, expected_status) in selected {
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
        }
    }

    counts.unclassified = unclassified.len();
    for name in &unclassified {
        println!("UNCLASSIFIED {name}");
    }

    println!();
    println!(
        "summary: {} pass, {} expected failure, {} failure, {} unexpected pass, {} unclassified",
        counts.pass, counts.xfail, counts.fail, counts.xpass, counts.unclassified
    );

    if counts.fail == 0 && counts.xpass == 0 && counts.unclassified == 0 {
        Ok(0)
    } else {
        Ok(1)
    }
}

fn run_case(path: &Path) -> Observed {
    let nata = nata_json::read_capture(path).and_then(|capture| nata_json::render_json(&capture));
    let tshark = tshark_json::run_tshark_json(path);

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
                "invalid expectations line {}: expected exactly capture name and pass/xfail status",
                line_number + 1
            ));
        }

        let status = match fields[1] {
            "pass" => ExpectedStatus::Pass,
            "xfail" => ExpectedStatus::Xfail,
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

fn unclassified_captures(
    corpus_dir: &Path,
    expectations: &BTreeMap<String, ExpectedStatus>,
) -> Result<Vec<String>, String> {
    let captures_dir = corpus_dir.join(WIRESHARK_TESTS_DIR);
    let mut captures = Vec::new();
    collect_capture_names(&captures_dir, Path::new(""), &mut captures)?;
    captures.retain(|name| !expectations.contains_key(name));
    captures.sort();
    Ok(captures)
}

fn collect_capture_names(
    directory: &Path,
    relative_directory: &Path,
    captures: &mut Vec<String>,
) -> Result<(), String> {
    let entries = fs::read_dir(directory)
        .map_err(|error| format!("could not read {}: {error}", directory.display()))?;
    for entry in entries {
        let entry = entry.map_err(|error| {
            format!(
                "could not read an entry in {}: {error}",
                directory.display()
            )
        })?;
        let file_type = entry
            .file_type()
            .map_err(|error| format!("could not inspect {}: {error}", entry.path().display()))?;
        let relative_path = relative_directory.join(entry.file_name());
        if file_type.is_dir() {
            collect_capture_names(&entry.path(), &relative_path, captures)?;
        } else if file_type.is_file() {
            let name = relative_path.to_str().ok_or_else(|| {
                format!(
                    "capture path is not valid UTF-8: {}",
                    relative_path.display()
                )
            })?;
            if is_capture_name(name) {
                captures.push(name.to_string());
            }
        }
    }
    Ok(())
}

fn is_capture_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name.ends_with(".pcap")
        || name.ends_with(".pcapng")
        || name.ends_with(".scap")
        || name.ends_with(".pcap.gz")
        || name.ends_with(".pcapng.gz")
        || name.ends_with(".scap.gz")
        || name.rsplit_once('.').is_some_and(|(base, suffix)| {
            base.ends_with(".pcapng")
                && !suffix.is_empty()
                && suffix.chars().all(|c| c.is_ascii_digit())
        })
}

pub(crate) fn capture_path(corpus_dir: &Path, name: &str) -> Result<PathBuf, String> {
    let capture_name = Path::new(name);
    if name.is_empty() || capture_name.is_absolute() {
        return Err(format!("invalid capture name {name:?}"));
    }
    if capture_name
        .components()
        .any(|component| component == std::path::Component::ParentDir)
    {
        return Err(format!("capture name escapes test/captures: {name}"));
    }
    Ok(corpus_dir.join(WIRESHARK_TESTS_DIR).join(capture_name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs::{self, File},
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn finds_nested_unclassified_captures() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let corpus_dir =
            std::env::temp_dir().join(format!("nata-tshark-suite-{}-{unique}", std::process::id()));
        let captures_dir = corpus_dir.join(WIRESHARK_TESTS_DIR).join("nested");
        fs::create_dir_all(&captures_dir).unwrap();
        File::create(captures_dir.join("known.pcap")).unwrap();
        File::create(captures_dir.join("new.pcapng.gz")).unwrap();
        File::create(captures_dir.join("notes.txt")).unwrap();

        let mut expectations = BTreeMap::new();
        expectations.insert("nested/known.pcap".to_string(), ExpectedStatus::Pass);

        assert_eq!(
            unclassified_captures(&corpus_dir, &expectations).unwrap(),
            vec!["nested/new.pcapng.gz"]
        );

        fs::remove_dir_all(corpus_dir).unwrap();
    }

    #[test]
    fn recognizes_numbered_pcapng_files() {
        assert!(is_capture_name("many_interfaces.pcapng.1"));
        assert!(is_capture_name("capture.PCAP.GZ"));
        assert!(!is_capture_name("capture.pcapng.backup"));
        assert!(!is_capture_name("notes.txt"));
    }

    #[test]
    fn allows_parent_components_in_corpus_path() {
        let corpus_dir = Path::new("target").join("wireshark").join("..");
        let expected = corpus_dir.join(WIRESHARK_TESTS_DIR).join("sample.pcap");

        assert_eq!(capture_path(&corpus_dir, "sample.pcap").unwrap(), expected);
    }
}
