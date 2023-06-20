use std::{error::Error, fs::File, io::{BufReader, self, Write, Read}, env};

use clap::{arg, Parser};
use xml::{reader::{EventReader, XmlEvent}};

#[derive(Parser, Debug)]
#[command(author, version, about)]
pub struct Config {
    /// The path to the OWASP Dependency Checker JSON report
    scan_results_path: String,

    /// What file name to use for the report
    #[arg(short, long, default_value = "processed_report.txt")]
    report_file_name: String,

    /// Bypass overwrite protection
    #[arg(short, long)]
    force_overwrite: bool,

    /// Generates and a saves a machine readable report for later processing.
    /// If not present, will just print results to terminal.
    #[arg(short, long)]
    generate_report: bool,
}

struct ProcessingResults {
    total_bugs: usize,
    high_bugs: usize,
    medium_bugs: usize,
    low_bugs: usize,
    security_bugs: usize,
}

fn directory_check(report_file_name: &str) {
    if let Ok(current_dir) = env::current_dir() {
        let file_path = current_dir.join(report_file_name);
        if file_path.exists() && file_path.is_file() {
            println!("'{0}' exists in the current directory. It will be overwritten by this command. If you are ok with this then", report_file_name);
            press_any_key();
        }
    } else {
        println!("Overwrite protection check failed. Please manually check that the file '{0}' will not be overwritten by this program.", report_file_name);
        press_any_key();
    }
}

pub fn run(config: Config) -> Result<(), Box<dyn Error>> {
    if config.generate_report && !config.force_overwrite {
        directory_check(&config.report_file_name);
    }

    let file = BufReader::new(File::open(config.scan_results_path)?);

    let parser = EventReader::new(file);
    let mut bug_instances = 0;
    let mut high_bug_instances = 0;
    let mut medium_bug_instances = 0;
    let mut low_bug_instances = 0;
    let mut security_bug_instances = 0;
    for e in parser {
        match e { 
            Ok(XmlEvent::StartElement { name, attributes, .. }) => {
                if name.to_string() == "BugInstance" {
                    bug_instances += 1;
                    for attribute in attributes {
                        if attribute.name.to_string() == "priority" {
                            if attribute.value == "1" {
                                 high_bug_instances += 1
                            }
                            if attribute.value == "2" {
                                 medium_bug_instances += 1
                            }
                            if attribute.value == "3" {
                                 low_bug_instances += 1
                            }
                        }
                        if attribute.value == "SECURITY" {
                            security_bug_instances += 1;
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("Error: {e}");
                break;
            }
            _ => {}
        }
    }

    let results = ProcessingResults { total_bugs: (bug_instances), high_bugs: (high_bug_instances), medium_bugs: (medium_bug_instances), low_bugs: (low_bug_instances), security_bugs: (security_bug_instances) };

    if config.generate_report {
        print!("✍️ Writing report...");
        if let Err(e) = save_processed_report(&results, &config.report_file_name) {
            println!("❌ Unable to write report!");
            println!("Error: {}", e.to_string());
        } else {
            print!(" Done! 💾 \n")
        }
    }

    if results.total_bugs > 0 {
        println!("Total Bugs: {0}", results.total_bugs);
        println!("Security Bugs: {0}", results.security_bugs);
        println!("High Bugs: {0}", results.high_bugs);
        println!("Medium Bugs: {0}", results.medium_bugs);
        println!("Low Bugs: {0}", results.low_bugs);
    } else {
        println!("🎉 All clear!")
    }

    Ok(())
}

fn save_processed_report(results: &ProcessingResults, report_file_name: &str) -> Result<(), Box<dyn Error>> {
    let current_dir = env::current_dir()?;
    let file_path = current_dir.join(report_file_name);
    let mut file = File::create(file_path)?;
    let content = format!("{0}
{1}
{2}
{3}
{4}", results.total_bugs, results.high_bugs, results.medium_bugs, results.low_bugs, results.security_bugs);
    file.write_all(content.as_bytes())?;

    Ok(())
}

fn press_any_key() {
    println!("Press any key to continue...");
    io::stdin().read_exact(&mut [0]).unwrap();
}