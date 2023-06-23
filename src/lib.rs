use std::{error::Error, fs::File, io::{BufReader, self, Write, Read}, env};

use clap::{arg, Parser};
use xml::{reader::{EventReader, XmlEvent}, attribute::OwnedAttribute, name::OwnedName};

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
    total_bugs: i32,
    high_bugs: i32,
    medium_bugs: i32,
    low_bugs: i32,
    security_bugs: i32,
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

    let mut bug_array: [i32; 5] = [0, 0, 0, 0, 0];

    for result in parser {
        match result { 
            Ok(XmlEvent::StartElement { name, attributes, .. }) => handle_element(&name, &attributes, &mut bug_array),
            Err(e) => {
                eprintln!("Error: {e}");
                break;
            }
            _ => {}
        }
    }

    let results = ProcessingResults { 
        total_bugs: (bug_array[0]), 
        high_bugs: (bug_array[1]), 
        medium_bugs: (bug_array[2]), 
        low_bugs: (bug_array[3]), 
        security_bugs: (bug_array[4]) 
    };

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

fn handle_element(name: &OwnedName, attributes: &Vec<OwnedAttribute>, bug_array: &mut [i32; 5]) {
    if name.to_string() == "BugInstance" {
        bug_array[0] += 1;
        for attribute in attributes {
            handle_attribute(attribute, bug_array);
        }
    }
}

fn handle_attribute(attribute: &OwnedAttribute, bug_array: &mut [i32; 5]) {
    if attribute.name.to_string() == "priority" {
        match attribute.value.as_str() {
            "1" => bug_array[1] += 1,
            "2" => bug_array[2] += 1,
            "3" => bug_array[3] += 1,
            _ => {}
        }
    }
    if attribute.value == "SECURITY" {
        bug_array[4] += 1;
    }
}

fn save_processed_report(results: &ProcessingResults, report_file_name: &str) -> Result<(), Box<dyn Error>> {
    let current_dir = env::current_dir()?;
    let file_path = current_dir.join(report_file_name);
    let mut file = File::create(file_path)?;
    let content = format!("{0} total bugs
{1} high danger bugs
{2} medium danger bugs
{3} low danger bugs
{4} security related bugs", results.total_bugs, results.high_bugs, results.medium_bugs, results.low_bugs, results.security_bugs);
    file.write_all(content.as_bytes())?;

    Ok(())
}

fn press_any_key() {
    println!("Press any key to continue...");
    io::stdin().read_exact(&mut [0]).unwrap();
}