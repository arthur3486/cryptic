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

use std::path::{Path, PathBuf};
use std::fs::{File, create_dir_all};
use std::io::{Read, Write};
use std::io::{Error, ErrorKind};
use aes_gcm::aead::generic_array::{typenum};
use aes_gcm::{Aes256Gcm, KeyInit, Key, Nonce, Tag};
use aes_gcm::aead::{Aead, AeadInPlace};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::{Digest, Sha256};
use crate::fs_utils::{FileEntry};

#[derive(Debug, PartialEq, Eq)]
pub enum ConflictResolutionStrategy {
    Skip,
    ErrorOut,
    Overwrite,
}

pub trait CryptoAlg {
    fn encrypt(&self, src_file: &FileEntry, dest_dir: &Path) -> Result<PathBuf, Box<dyn std::error::Error>>;
    fn decrypt(&self, src_file: &FileEntry, dest_dir: &Path) -> Result<PathBuf, Box<dyn std::error::Error>>;
}

pub struct AesGcmAlgorithm {
    password: String,
    conflict_resolution_strategy: ConflictResolutionStrategy,
}

impl AesGcmAlgorithm {

    const BUFFER_SIZE: usize = (1024 * 1024); // 1 MB
    const TAG_SIZE: usize = 16;
    const SALT_SIZE: usize = 12;
    const NONCE_SIZE: usize = 12;

    pub fn new(password: String, conflict_resolution_strategy: Option<ConflictResolutionStrategy>) -> Self {
        Self { 
            password: password,
            conflict_resolution_strategy: match conflict_resolution_strategy {
                Some(strategy) => strategy,
                None => ConflictResolutionStrategy::Overwrite,
            },
        }
    }

    fn encrypt_text(cipher: &Aes256Gcm, nonce: &Nonce<typenum::U12>, text: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        match cipher.encrypt(&nonce, text.as_bytes()) {
            Ok(res) => Ok(res),
            Err(e) => Err(Box::new(Error::new(ErrorKind::Other, format!("Failed to encrypt the text. Error: {:?}", e))))
        }
    }

    fn decrypt_text(cipher: &Aes256Gcm, nonce: &Nonce<typenum::U12>, text_bytes: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
        match cipher.decrypt(&nonce, text_bytes) {
            Ok(res) => Ok(String::from_utf8(res).unwrap()),
            Err(e) => Err(Box::new(Error::new(ErrorKind::Other, format!("Failed to decrypt the text. Error: {:?}", e))))
        }
    }

    fn write_file_path(output_file: &mut File, raw_file_path: &Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
        let file_path_len = raw_file_path.len();

        output_file.write_all(&(file_path_len as u32).to_be_bytes())?;
        output_file.write_all(&raw_file_path)?;

        Ok(())
    }

    fn read_salt(input_file: &mut File) -> Result<Box<[u8]>, Box<dyn std::error::Error>> {
        let mut salt = [0u8; AesGcmAlgorithm::SALT_SIZE];
        input_file.read_exact(&mut salt)?;

        Ok(salt.to_vec().into_boxed_slice())
    }

    fn read_nonce(input_file: &mut File) -> Result<Box<Nonce<typenum::U12>>, Box<dyn std::error::Error>> {
        let mut raw_nonce = [0u8; AesGcmAlgorithm::NONCE_SIZE];
        input_file.read_exact(&mut raw_nonce)?;
        let nonce = Nonce::from_slice(&raw_nonce);

        Ok(Box::new(*nonce))
    }

    fn read_file_path(input_file: &mut File) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut file_name_len_buf = [0u8; 4];
        input_file.read_exact(&mut file_name_len_buf)?;

        let file_name_len = u32::from_be_bytes(file_name_len_buf) as usize;
        let mut file_path_buf = vec![0u8; file_name_len];
        input_file.read_exact(&mut file_path_buf)?;

        Ok(file_path_buf)
    }

    fn generate_random_salt() -> Box<[u8]> {
        let mut salt = [0u8; AesGcmAlgorithm::SALT_SIZE];
        rand::thread_rng().fill_bytes(&mut salt);
        salt.to_vec().into_boxed_slice()
    }

    fn generate_random_nonce() -> Box<Nonce<typenum::U12>> {
        let mut raw_nonce = [0u8; AesGcmAlgorithm::NONCE_SIZE];
        rand::thread_rng().fill_bytes(&mut raw_nonce);
        Box::new(*Nonce::from_slice(&raw_nonce))
    }

}

impl CryptoAlg for AesGcmAlgorithm {

    fn encrypt(&self, src_file: &FileEntry, dest_dir: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
        if !src_file.absolute_path.exists() {
            return Err(Box::new(Error::new(ErrorKind::NotFound, format!("Can't encrypt the file: {:?}. File doesn't exist.", src_file.absolute_path))));
        }

        if !src_file.absolute_path.is_file() {
            return Err(Box::new(Error::new(ErrorKind::InvalidInput, format!("Can't encrypt the file: {:?}. File is a directory.", src_file.absolute_path))));
        }

        let salt = AesGcmAlgorithm::generate_random_salt();
        let enc_key = derive_key(&self.password, &salt);
        let nonce = AesGcmAlgorithm::generate_random_nonce();
        let cipher = Aes256Gcm::new(&enc_key);
        let original_file_relative_path = AesGcmAlgorithm::encrypt_text(&cipher, &nonce, src_file.relative_path.to_str().unwrap())?;

        // preparing files
        create_dir_all(&dest_dir)?;

        let new_file_name = generate_hash(src_file.relative_path.to_str().unwrap());
        let output_file_path = dest_dir.join(new_file_name);

        if output_file_path.exists() {
            match self.conflict_resolution_strategy {
                ConflictResolutionStrategy::Skip => return Ok(output_file_path),
                ConflictResolutionStrategy::ErrorOut => {
                    let err_message = format!("Failed to encrypt the file: {:?}. Destination file with a matching name already exists.", src_file.absolute_path);
                    return Err(Box::new(Error::new(ErrorKind::AlreadyExists, err_message)));
                },
                _ => {}
            }
        }

        let mut input_file = File::open(&src_file.absolute_path)?;
        let mut output_file = File::create(&output_file_path)?;
        
        // writing metadata
        output_file.write_all(&salt)?;
        output_file.write_all(&nonce)?;
        AesGcmAlgorithm::write_file_path(&mut output_file, &original_file_relative_path)?;
        
        // encrypting file content
        let mut data_buffer = vec![0u8; AesGcmAlgorithm::BUFFER_SIZE];

        loop {
            let bytes_read = input_file.read(&mut data_buffer)?;

            if bytes_read == 0 {
                break;
            }

            match cipher.encrypt_in_place_detached(&nonce, &[], &mut data_buffer[..bytes_read]) {
                Ok(tag) => {
                    output_file.write_all(&data_buffer[..bytes_read])?;
                    output_file.write_all(&tag)?;
                }
                Err(e) => {
                    return Err(Box::new(Error::new(ErrorKind::Other, format!("Failed to encrypt the file chunk. Error: {:?}", e))));
                }
            };
        }

        Ok(output_file_path)
    }

    fn decrypt(&self, src_file: &FileEntry, dest_dir: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
        if !src_file.absolute_path.exists() {
            return Err(Box::new(Error::new(ErrorKind::NotFound, format!("Can't decrypt the file: {:?}. File doesn't exist.", src_file.absolute_path))));
        }

        if !src_file.absolute_path.is_file() {
            return Err(Box::new(Error::new(ErrorKind::InvalidInput, format!("Can't decrypt the file: {:?}. File is a directory.", src_file.absolute_path))));
        }
        
        // cipher initialization
        let mut input_file = File::open(&src_file.absolute_path)?;
        let salt = AesGcmAlgorithm::read_salt(&mut input_file)?;
        let nonce = AesGcmAlgorithm::read_nonce(&mut input_file)?;
        let key = derive_key(&self.password, &salt);
        let cipher = Aes256Gcm::new(&key);

        // recovering the original relative path of the file
        let recovered_relative_path_bytes = AesGcmAlgorithm::read_file_path(&mut input_file)?;
        let recovered_relative_path = AesGcmAlgorithm::decrypt_text(&cipher, &nonce, &recovered_relative_path_bytes)?;
        let output_file_path = dest_dir.join(recovered_relative_path);

        if output_file_path.exists() {
            match self.conflict_resolution_strategy {
                ConflictResolutionStrategy::Skip => return Ok(output_file_path),
                ConflictResolutionStrategy::ErrorOut => {
                    let err_message = format!("Failed to decrypt the file: {:?}. Destination file with a matching name already exists.", src_file.absolute_path);
                    return Err(Box::new(Error::new(ErrorKind::AlreadyExists, err_message)));
                },
                _ => {}
            }
        }

        if let Some(parent_dir) = output_file_path.parent() {
            create_dir_all(&parent_dir)?;
        }

        let mut output_file = File::create(&output_file_path)?;

        // decrypting the file content
        let mut data_buffer = vec![0u8; (AesGcmAlgorithm::BUFFER_SIZE + AesGcmAlgorithm::TAG_SIZE)];
        let mut tag_buffer = [0u8; AesGcmAlgorithm::TAG_SIZE];
        let tag_len = tag_buffer.len();

        loop {
            let bytes_read = input_file.read(&mut data_buffer)?;

            if bytes_read == 0 {
                break;
            }

            let tag_idx_range = (bytes_read - tag_len)..bytes_read;
            let data_idx_range = ..(bytes_read - tag_len);

            tag_buffer.copy_from_slice(&data_buffer[tag_idx_range]);
            let tag = Tag::from_slice(&tag_buffer);
            
            match cipher.decrypt_in_place_detached(&nonce, &[], &mut data_buffer[data_idx_range], &tag) {
                Ok(_) => {
                    output_file.write_all(&data_buffer[data_idx_range])?;
                }
                Err(e) => {
                    return Err(Box::new(Error::new(ErrorKind::Other, format!("Failed to decrypt the file chunk. Error: {:?}", e))));
                }
            }
        }

        Ok(output_file_path)
    }

}

fn derive_key(password: &str, salt: &[u8]) -> Box<Key<Aes256Gcm>> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), password.as_bytes());
    let mut key = [0u8; 32];

    hkdf.expand(b"aes-gcm key", &mut key).unwrap();

    Box::new(*Key::<Aes256Gcm>::from_slice(&key))
}

fn generate_hash(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());

    hex::encode(hasher.finalize()).to_uppercase()
}