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
use walkdir::WalkDir;

#[derive(Debug)]
pub struct FileEntry {
    pub original_parent_dir: PathBuf,
    pub absolute_path: PathBuf,
    pub relative_path: PathBuf,
}

pub fn get_file_info(file_path: &Path) -> Option<FileEntry> {
    if !file_path.exists() {
        return None;
    }

    let parent_dir = file_path.parent().expect("The File MUST BE located in a directory.");
    let relative_path = file_path.strip_prefix(parent_dir).unwrap();
    let file_info = FileEntry {
        original_parent_dir: parent_dir.to_path_buf(),
        absolute_path: file_path.to_path_buf(),
        relative_path: relative_path.to_path_buf(),
    };

    Some(file_info)
}

pub fn list_all_files(dir_path: &Path) -> Vec<FileEntry> {
    if !dir_path.is_dir() {
        return Vec::new();
    }

    WalkDir::new(dir_path)
        .follow_links(true)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_file())
        .filter_map(|e| {
            let abs_path = e.path();
            let relative_path = abs_path.strip_prefix(dir_path).unwrap();
            let file = FileEntry {
                original_parent_dir: dir_path.to_path_buf(),
                absolute_path: abs_path.to_path_buf(),
                relative_path: relative_path.to_path_buf(),
            };

            Some(file)
        })
        .collect()
}