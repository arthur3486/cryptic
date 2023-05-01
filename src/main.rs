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

mod config;
mod fs_utils;
mod crypto;

use std::path::{Path};
use std::sync::{Arc};
use config::{Config, OperationType, FileConflictResolutionStrategy};
use fs_utils::{FileEntry};
use crypto::{CryptoAlg, AesGcmAlgorithm, ConflictResolutionStrategy};
use rayon::prelude::*;

fn main() {
    let parsed_config = config::parse_config();
    let input_file_path = parsed_config.input_file.as_path();
    let conflict_res_strategy = match parsed_config.file_conflict_resolution_strategy {
        FileConflictResolutionStrategy::Skip => ConflictResolutionStrategy::Skip,
        FileConflictResolutionStrategy::Overwrite => ConflictResolutionStrategy::Overwrite,
        FileConflictResolutionStrategy::ErrorOut => ConflictResolutionStrategy::ErrorOut,
    };
    let files = extract_files(input_file_path);

    match parsed_config.operation_type {
        OperationType::Encryption => encrypt_files(&parsed_config, conflict_res_strategy, &files),
        OperationType::Decryption => decrypt_files(&parsed_config, conflict_res_strategy, &files),
    }
}

fn extract_files(src_file: &Path) -> Vec<FileEntry> {
    if src_file.is_dir() {
        fs_utils::list_all_files(src_file)
    } else {
        let file_info = fs_utils::get_file_info(src_file);

        if file_info.is_none() {
            panic!("Failed to extract the info from the source file: {file:?}", file = src_file);
        }

        vec![file_info.unwrap()]
    }
}

fn encrypt_files(config: &Config, conflict_res_strategy: ConflictResolutionStrategy, files: &Vec<FileEntry>) {
    let alg = Arc::new(AesGcmAlgorithm::new(config.password.clone(), Some(conflict_res_strategy)));

    println!("Encrypting files...");

    files.par_iter()
        .map(|file| {
            log_file_operation_message(config, "Encrypting the file", file);

            match alg.encrypt(file, &config.output_file) {
                Ok(_) => log_file_operation_message(config, "Encryption success!", file),
                Err(e) => log_file_operation_message(config, &format!("Encryption failure! Error: {}", e), file),
            };

            file
        })
        .collect::<Vec<_>>();

    println!("Encryption success!");
}

fn decrypt_files(config: &Config, conflict_res_strategy: ConflictResolutionStrategy, files: &Vec<FileEntry>) {
    let alg = Arc::new(AesGcmAlgorithm::new(config.password.clone(), Some(conflict_res_strategy)));

    println!("Decrypting files...");

    files.par_iter()
        .map(|file| {
            log_file_operation_message(config, "Decrypting the file", file);

            match alg.decrypt(file, &config.output_file) {
                Ok(_) => log_file_operation_message(config, "Decryption success!", file),
                Err(e) => log_file_operation_message(config, &format!("Decryption failure! Error: {}", e), file),
            };

            file
        })
        .collect::<Vec<_>>();

    println!("Decryption success!");
}

fn log_file_operation_message(config: &Config, message: &str, file: &FileEntry) {
    if ((config.is_verbose_mode_enabled)) {
        println!("{}. File: {:?}", message, file.absolute_path)
    }
}