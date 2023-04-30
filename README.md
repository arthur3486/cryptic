# cryptic

A simple self-contained CLI tool that makes it easy to efficiently encrypt/decrypt your files.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

## Contents

* [Features](#features)
* [Building](#building)
* [Usage](#usage)
* [License](#license)

## Features

* Self-contained binaries.
* Parallelized file processing.
* Support for advanced encryption algorithms:
    * **AES** (with **GCM**).
* Support for different authentication credential types:
    * **User-defined password** (key derivation from the user-defined password).

## Buidling

### Prerequisites

The following dependencies must be installed on your host machine to build the project:
* `rustc`
* `cargo`
* `rustup`

### Building for a Specific Target Platform
The project is currently configured to target 4 platforms, namely `linux x86_64`, `windows x86_64`, `macOS x86_64`, and `macOS Apple Silicon` (See: [`Cargo.toml`](Cargo.toml)).

> Before building binaries for any of the mentioned platforms, it is necessary to install the corresponding platform toolchains. You can install these toolchains by utilizing the provided utility script: [`install_targets.sh`](/script/install_targets.sh).

Example of a build command for a binary targeting the `linux x86_64` platform:

```
cargo build --release --target x86_64-unknown-linux-gnu
```

The resulting binary file will be stored under the [`target/release`](/target/release/) directory.

## Usage

The usage is quite straightforward. Once you have the tool binary (whether by building it yourself or by downloading a release variant), refer to the embedded manual.

To bring up the embedded manual use the following command:
```
cryptic --help
```

Example of file encryption command:
```
cryptic --input /my_files/photos --output /my_files/encrypted/photos --encrypt --verbose
```

Example of file decryption command:
```
cryptic --input /my_files/encrypted/photos --output /my_files/photos --decrypt --verbose
```

## License

**cryptic** is licensed under the [**Apache 2.0 License**](LICENSE).