use std::process;

use clap::Parser;

fn main() {
    let args = spotbugs_xml_parser::Config::parse();

    if let Err(e) = spotbugs_xml_parser::run(args) {
        println!("Error: {0}", e.to_string());
        println!("Use the -h (or --help) option to see usage.");

        process::exit(1)
    }
}