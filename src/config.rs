/*
 * Copyright 2023 Arthur Ivanets, arthur.ivanets.work@gmail.com
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use rpassword::read_password;
use std::io::{Write};
use std::str::FromStr;
use std::path::{Path, PathBuf};
use clap::{
    Command, 
    Arg, 
    ArgAction, 
    ArgGroup,
    crate_name, 
    crate_authors, 
    crate_version, 
    crate_description
};

const ARG_ID_ENCRYPTION: &str = "encryption";
const ARG_ID_DECRYPTION: &str = "decryption";
const ARG_ID_INPUT_FILE: &str = "input_file";
const ARG_ID_OUTPUT_FILE: &str = "output_file";
const ARG_ID_FILE_CONFLICT_RESOLUTION_STRATEGY: &str = "file_conflict_resolution_strategy";
const ARG_ID_VERBOSE_MODE: &str = "verbose";
const ARG_ID_STRICT_MODE: &str = "strict";

pub struct Config {
    pub operation_type: OperationType,
    pub input_file: PathBuf,
    pub output_file: PathBuf,
    pub password: String,
    pub file_conflict_resolution_strategy: FileConflictResolutionStrategy,
    pub is_strict_mode_enabled: bool,
    pub is_verbose_mode_enabled: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum OperationType {
    Encryption,
    Decryption,
}

#[derive(Debug, PartialEq, Eq)]
pub enum FileConflictResolutionStrategy {
    Skip,
    Overwrite,
    ErrorOut
}

impl FromStr for FileConflictResolutionStrategy {

    type Err = ();

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input {
            "skip" => Ok(FileConflictResolutionStrategy::Skip),
            "overwrite" => Ok(FileConflictResolutionStrategy::Overwrite),
            "error_out" => Ok(FileConflictResolutionStrategy::ErrorOut),
            _ => Err(()),
        }
    }

}

pub fn parse_config() -> Config {
    let matched_args = create_cli_menu().get_matches();

    let operation_type = if matched_args.get_flag(ARG_ID_ENCRYPTION) {
        OperationType::Encryption
    } else if matched_args.get_flag(ARG_ID_DECRYPTION) {
        OperationType::Decryption
    } else {
        panic!("Was unable to resolve the operation type.")
    };

    let conflict_resolution_strategy = if let Some(raw_strategy) = matched_args.get_one::<String>(ARG_ID_FILE_CONFLICT_RESOLUTION_STRATEGY) {
        FileConflictResolutionStrategy::from_str(raw_strategy).expect(&format!("Unsupported strategy: {:?}", raw_strategy))
    } else {
        FileConflictResolutionStrategy::Overwrite
    };
    
    let input_file = Path::new(matched_args.get_one::<String>(ARG_ID_INPUT_FILE).unwrap());
    let output_file = Path::new(matched_args.get_one::<String>(ARG_ID_OUTPUT_FILE).unwrap());
    let password = parse_password();
    let is_strict_mode_enabled = matched_args.get_flag(ARG_ID_STRICT_MODE);
    let is_verbose_mode_enabled = matched_args.get_flag(ARG_ID_VERBOSE_MODE);

    if !input_file.exists() {
        panic!("Invalid input file. File does not exist.");
    }

    Config {
        operation_type: operation_type,
        input_file: input_file.to_owned(),
        output_file: output_file.to_owned(),
        password: password,
        file_conflict_resolution_strategy: conflict_resolution_strategy,
        is_strict_mode_enabled: is_strict_mode_enabled,
        is_verbose_mode_enabled: is_verbose_mode_enabled,
    }
}

fn parse_password() -> String {
    let mut password: Option<String> = None;

    while password.is_none() {
        print!("Enter your password: ");
        std::io::stdout().flush().unwrap();
    
        let raw_pwd = read_password().unwrap();

        if raw_pwd.len() > 0 {
            password = Some(raw_pwd);
        } else {
            println!("Invalid password.");
            std::io::stdout().flush().unwrap();
        }
    }
    
    password.unwrap()
}

fn create_cli_menu() -> Command {
    Command::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!("\n"))
        .about(crate_description!())
        .arg(
            Arg::new(ARG_ID_ENCRYPTION)
                .short('e')
                .long("encrypt")
                .help("Enable file encryption mode.")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new(ARG_ID_DECRYPTION)
                .short('d')
                .long("decrypt")
                .help("Enable file decryption mode.")
                .action(ArgAction::SetTrue),
        )
        .group(
            ArgGroup::new("operation_type")
                .args(&[ARG_ID_ENCRYPTION, ARG_ID_DECRYPTION])
                .required(true),
        )
        .arg(
            Arg::new(ARG_ID_INPUT_FILE)
                .short('i')
                .long("input")
                .value_name("FILE")
                .help("A pointer to a file or a directory that must be encrypted/decrypted.")
                .required(true)
                .action(ArgAction::Set),
        )
        .arg(
            Arg::new(ARG_ID_OUTPUT_FILE)
                .short('o')
                .long("output")
                .value_name("FILE")
                .help("A pointer to a directory into which the results must be saved")
                .required(true)
                .action(ArgAction::Set),
        )
        .arg(
            Arg::new(ARG_ID_FILE_CONFLICT_RESOLUTION_STRATEGY)
                .long("file-conflict-resolution-strategy")
                .value_name("STRATEGY")
                .help("A strategy that determines how encountered file conflicts must be resolved. Possible values: [ skip, overwrite, error_out ].")
                .required(false)
                .action(ArgAction::Set),
        )
        .arg(
            Arg::new(ARG_ID_VERBOSE_MODE)
                .short('v')
                .long("verbose")
                .help("Enable verbose mode.")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new(ARG_ID_STRICT_MODE)
                .long("strict")
                .help("Enable strict mode. When strict mode is enabled, any error that gets encountered will abort the encryption/decryption process.")
                .action(ArgAction::SetTrue),
        )
}
