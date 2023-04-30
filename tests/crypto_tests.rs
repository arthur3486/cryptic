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

#[path = "../src/crypto.rs"] mod crypto;
#[path = "../src/fs_utils.rs"] mod fs_utils;

#[cfg(test)]
mod my_struct_tests {

    use std::fs;
    use std::env;
    use std::io::{BufReader, Read, Error, ErrorKind};
    use std::path::{Path, PathBuf};
    use rand::Rng;
    use crate::crypto::{CryptoAlg, AesGcmAlgorithm, ConflictResolutionStrategy};
    use crate::fs_utils;
    use crate::fs_utils::{FileEntry};

    fn init_test<F: Fn(&Path)>(action: F) {
        let test_dir_name = rand::thread_rng().gen_range(10000..99999).to_string();
        let test_files_dir = create_test_files_output_dir(Some(&test_dir_name));

        action(&test_files_dir);

        fs::remove_dir_all(&test_files_dir).expect("Failed to delete test output files");
    }

    #[test]
    fn test_encryption_of_a_small_file() {
        init_test(|test_files_output_dir| {
            let input_file = Path::new("tests/fixtures/small_text_file.txt");
            let alg = AesGcmAlgorithm::new(String::from("1234"), None);

            let input_file_info = fs_utils::get_file_info(&input_file).unwrap();
            let encrypted_file_path = alg.encrypt(&input_file_info, &test_files_output_dir).expect("Encryption resulted in error");

            let encrypted_file_info = fs_utils::get_file_info(&encrypted_file_path).unwrap();
            let decrypted_file_path = alg.decrypt(&encrypted_file_info, &test_files_output_dir).expect("Decryption resulted in error");

            let files_are_equal = are_files_equal_contentwise(&input_file, &decrypted_file_path);

            assert!(files_are_equal);
        });
    }

    #[test]
    fn test_decryption_of_a_small_file() {
        init_test(|test_files_output_dir| {
            let input_file = Path::new("tests/fixtures/encrypted_small_text_file_pwd_1234");
            let original_file = Path::new("tests/fixtures/small_text_file.txt");
            let alg = AesGcmAlgorithm::new(String::from("1234"), None);

            let input_file_info = fs_utils::get_file_info(&input_file).unwrap();
            let decrypted_file_path = alg.decrypt(&input_file_info, &test_files_output_dir).expect("Decryption resulted in error");
            
            let files_are_equal = are_files_equal_contentwise(&original_file, &decrypted_file_path);

            assert!(files_are_equal);
        });
    }

    #[test]
    fn test_encryption_of_a_large_file() {
        init_test(|test_files_output_dir| {
            let input_file = Path::new("tests/fixtures/large_image_file.jpg");
            let alg = AesGcmAlgorithm::new(String::from("123456"), None);

            let input_file_info = fs_utils::get_file_info(&input_file).unwrap();
            let encrypted_file_path = alg.encrypt(&input_file_info, &test_files_output_dir).expect("Encryption resulted in error");

            let encrypted_file_info = fs_utils::get_file_info(&encrypted_file_path).unwrap();
            let decrypted_file_path = alg.decrypt(&encrypted_file_info, &test_files_output_dir).expect("Decryption resulted in error");

            let files_are_equal = are_files_equal_contentwise(&input_file, &decrypted_file_path);

            assert!(files_are_equal);
        });
    }

    #[test]
    fn test_decryption_of_a_large_file() {
        init_test(|test_files_output_dir| {
            let input_file = Path::new("tests/fixtures/encrypted_large_image_file_pwd_123456");
            let original_file = Path::new("tests/fixtures/large_image_file.jpg");
            let alg = AesGcmAlgorithm::new(String::from("123456"), None);

            let input_file_info = fs_utils::get_file_info(&input_file).unwrap();
            let decrypted_file_path = alg.decrypt(&input_file_info, &test_files_output_dir).expect("Decryption resulted in error");
            
            let files_are_equal = are_files_equal_contentwise(&original_file, &decrypted_file_path);

            assert!(files_are_equal);
        });
    }

    #[test]
    fn test_decryption_using_incorrect_password() {
        init_test(|test_files_output_dir| {
            let input_file = Path::new("tests/fixtures/encrypted_small_text_file_pwd_1234");
            let alg = AesGcmAlgorithm::new(String::from("4321"), None);

            let input_file_info = fs_utils::get_file_info(&input_file).unwrap();
            let decryption_result = alg.decrypt(&input_file_info, &test_files_output_dir);
            
            assert!(decryption_result.is_err());
        });
    }

    #[test]
    fn test_encryption_parameter_validation_non_existent_src_file() {
        init_test(|test_files_output_dir| {
            let alg = AesGcmAlgorithm::new(String::from("1234"), None);

            let input_file_info = FileEntry {
                original_parent_dir: Path::new("tests/fixtures").to_path_buf(),
                absolute_path: Path::new("tests/fixtures/small_text_file_that_does_not_exist.txt").to_path_buf(),
                relative_path: Path::new("small_text_file_that_does_not_exist.txt").to_path_buf(),
            };
            let encryption_result = alg.encrypt(&input_file_info, &test_files_output_dir);

            assert!(encryption_result.is_err());
        });
    }

    #[test]
    fn test_decryption_parameter_validation_non_existent_src_file() {
        init_test(|test_files_output_dir| {
            let alg = AesGcmAlgorithm::new(String::from("1234"), None);

            let input_file_info = FileEntry {
                original_parent_dir: Path::new("tests/fixtures").to_path_buf(),
                absolute_path: Path::new("tests/fixtures/encrypted_small_text_file_that_does_not_exist").to_path_buf(),
                relative_path: Path::new("encrypted_small_text_file_that_does_not_exist").to_path_buf(),
            };
            let decryption_result = alg.decrypt(&input_file_info, &test_files_output_dir);
            
            assert!(decryption_result.is_err());
        });
    }

    #[test]
    fn test_encryption_parameter_validation_non_file_src_file() {
        init_test(|test_files_output_dir| {
            let alg = AesGcmAlgorithm::new(String::from("1234"), None);

            let input_file_info = FileEntry {
                original_parent_dir: Path::new("tests").to_path_buf(),
                absolute_path: Path::new("tests/fixtures").to_path_buf(),
                relative_path: Path::new("fixtures").to_path_buf(),
            };
            let encryption_result = alg.encrypt(&input_file_info, &test_files_output_dir);

            assert!(encryption_result.is_err());
            assert_eq!(ErrorKind::InvalidInput, encryption_result.unwrap_err().downcast_ref::<Error>().unwrap().kind());
        });
    }

    #[test]
    fn test_decryption_parameter_validation_non_file_src_file() {
        init_test(|test_files_output_dir| {
            let alg = AesGcmAlgorithm::new(String::from("1234"), None);

            let input_file_info = FileEntry {
                original_parent_dir: Path::new("tests").to_path_buf(),
                absolute_path: Path::new("tests/fixtures").to_path_buf(),
                relative_path: Path::new("fixtures").to_path_buf(),
            };
            let decryption_result = alg.decrypt(&input_file_info, &test_files_output_dir);
            
            assert!(decryption_result.is_err());
            assert_eq!(ErrorKind::InvalidInput, decryption_result.unwrap_err().downcast_ref::<Error>().unwrap().kind());
        });
    }

    #[test]
    fn test_encryption_conflict_resolution_strategy_skip() {
        init_test(|test_files_output_dir| {
            let input_file = Path::new("tests/fixtures/small_text_file.txt");
            let alg = AesGcmAlgorithm::new(String::from("1234"), None);
            let alg_with_strategy = AesGcmAlgorithm::new(String::from("1234"), Some(ConflictResolutionStrategy::Skip));

            let input_file_info = fs_utils::get_file_info(&input_file).unwrap();
            let encryption_res_1 = alg.encrypt(&input_file_info, &test_files_output_dir).expect("File encryption failed");
            let encryption_res_2 = alg_with_strategy.encrypt(&input_file_info, &test_files_output_dir).expect("File encryption failed");

            assert_eq!(encryption_res_1, encryption_res_2);
        });
    }

    #[test]
    fn test_encryption_conflict_resolution_strategy_error_out() {
        init_test(|test_files_output_dir| {
            let input_file = Path::new("tests/fixtures/small_text_file.txt");
            let alg = AesGcmAlgorithm::new(String::from("1234"), None);
            let alg_with_strategy = AesGcmAlgorithm::new(String::from("1234"), Some(ConflictResolutionStrategy::ErrorOut));

            let input_file_info = fs_utils::get_file_info(&input_file).unwrap();
            let encryption_res_1 = alg.encrypt(&input_file_info, &test_files_output_dir);
            let encryption_res_2 = alg_with_strategy.encrypt(&input_file_info, &test_files_output_dir);

            assert!(encryption_res_1.is_ok());
            assert!(encryption_res_2.is_err());
            assert_eq!(ErrorKind::AlreadyExists, encryption_res_2.unwrap_err().downcast_ref::<Error>().unwrap().kind());
        });
    }

    #[test]
    fn test_encryption_conflict_resolution_strategy_overwrite() {
        init_test(|test_files_output_dir| {
            let input_file = Path::new("tests/fixtures/small_text_file.txt");
            let alg = AesGcmAlgorithm::new(String::from("1234"), None);
            let alg_with_strategy = AesGcmAlgorithm::new(String::from("1234"), Some(ConflictResolutionStrategy::Overwrite));

            let input_file_info = fs_utils::get_file_info(&input_file).unwrap();
            let encryption_res_1 = alg.encrypt(&input_file_info, &test_files_output_dir).expect("File encryption failed");
            let encryption_res_2 = alg_with_strategy.encrypt(&input_file_info, &test_files_output_dir).expect("File encryption failed");

            assert_eq!(encryption_res_1, encryption_res_2);
        });
    }

    #[test]
    fn test_decryption_conflict_resolution_strategy_skip() {
        init_test(|test_files_output_dir| {
            let input_file = Path::new("tests/fixtures/encrypted_small_text_file_pwd_1234");
            let alg = AesGcmAlgorithm::new(String::from("1234"), None);
            let alg_with_strategy = AesGcmAlgorithm::new(String::from("1234"), Some(ConflictResolutionStrategy::Skip));

            let input_file_info = fs_utils::get_file_info(&input_file).unwrap();
            let decryption_res_1 = alg.decrypt(&input_file_info, &test_files_output_dir).expect("Decryption resulted in error");
            let decryption_res_2 = alg_with_strategy.decrypt(&input_file_info, &test_files_output_dir).expect("Decryption resulted in error");
            
            assert_eq!(decryption_res_1, decryption_res_2);
        });
    }

    #[test]
    fn test_decryption_conflict_resolution_strategy_error_out() {
        init_test(|test_files_output_dir| {
            let input_file = Path::new("tests/fixtures/encrypted_small_text_file_pwd_1234");
            let alg = AesGcmAlgorithm::new(String::from("1234"), None);
            let alg_with_strategy = AesGcmAlgorithm::new(String::from("1234"), Some(ConflictResolutionStrategy::ErrorOut));

            let input_file_info = fs_utils::get_file_info(&input_file).unwrap();
            let decryption_res_1 = alg.decrypt(&input_file_info, &test_files_output_dir);
            let decryption_res_2 = alg_with_strategy.decrypt(&input_file_info, &test_files_output_dir);
            
            assert!(decryption_res_1.is_ok());
            assert!(decryption_res_2.is_err());
            assert_eq!(ErrorKind::AlreadyExists, decryption_res_2.unwrap_err().downcast_ref::<Error>().unwrap().kind());
        });
    }

    #[test]
    fn test_decryption_conflict_resolution_strategy_overwrite() {
        init_test(|test_files_output_dir| {
            let input_file = Path::new("tests/fixtures/encrypted_small_text_file_pwd_1234");
            let alg = AesGcmAlgorithm::new(String::from("1234"), None);
            let alg_with_strategy = AesGcmAlgorithm::new(String::from("1234"), Some(ConflictResolutionStrategy::Overwrite));

            let input_file_info = fs_utils::get_file_info(&input_file).unwrap();
            let decryption_res_1 = alg.decrypt(&input_file_info, &test_files_output_dir).expect("Decryption resulted in error");
            let decryption_res_2 = alg_with_strategy.decrypt(&input_file_info, &test_files_output_dir).expect("Decryption resulted in error");
            
            assert_eq!(decryption_res_1, decryption_res_2);
        });
    }

    fn create_test_files_output_dir(sub_dir: Option<&str>) -> PathBuf {
        let base_dir_path = env::temp_dir().join("crypto_tests_tmp_files");
        let test_files_dir_path = if sub_dir.is_some() {
            base_dir_path.join(sub_dir.unwrap()).to_path_buf()
        } else {
            base_dir_path.to_path_buf()
        };

        fs::create_dir_all(&test_files_dir_path).expect("Failed to create the dir for test files");

        test_files_dir_path
    }

    fn are_files_equal_contentwise(file1_path: &Path, file2_path: &Path) -> bool {
        let mut file1 = BufReader::new(fs::File::open(file1_path).unwrap());
        let mut file2 = BufReader::new(fs::File::open(file2_path).unwrap());
        
        let mut buf1 = vec![0u8; 1024 * 1024];
        let mut buf2 = vec![0u8; 1024 * 1024];
    
        loop {
            let bytes_read1 = file1.read(&mut buf1).unwrap();
            let bytes_read2 = file2.read(&mut buf2).unwrap();
    
            if (bytes_read1 != bytes_read2) || (buf1[..bytes_read1] != buf2[..bytes_read2]) {
                return false;
            }
    
            if bytes_read1 == 0 {
                break;
            }
        }
    
        true
    }

}