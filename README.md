# AES-Implementation
This project provides a comprehensive implementation of the AES (Advanced Encryption Standard) algorithm in C++. It supports three modes of operation: CBC (Cipher Block Chaining), ECB (Electronic Codebook), and CFB (Cipher Feedback).

### Features
- **AES Encryption/Decryption**: Implemented AES in three popular modes: **CBC**, **ECB**, and **CFB**.
- **Key Management**: Includes **key generation** and **key expansion** functionality.
- **Padding/Unpadding**: Integrated mechanisms for padding and unpadding data blocks to support AES block size.
- **Secure Key Generation**: Integrated OpenSSL for generating cryptographically secure random keys.

### Files Overview
- **`AES.cpp`**: Core implementation of AES, including key generation, key expansion, and the encryption/decryption functions.
- **`AES.h`**: Header file defining the AES class interface.
- **`AES-CBC.cpp`**: AES implementation in CBC (Cipher Block Chaining) mode.
- **`AES-ECB.cpp`**: AES implementation in ECB (Electronic Codebook) mode.
- **`AES-CFB.cpp`**: AES implementation in CFB (Cipher Feedback) mode.
- **`main.cpp`**: Demonstrates the usage of AES in multiple modes, showcasing encryption/decryption workflows.
- **`.gitignore`**: Excludes unnecessary or temporary files from version control.
- **`LICENSE`**: The project is licensed under the MIT License.
- **`README.md`**: Project documentation explaining features, setup, and usage.

## Prerequisites
Before building the project, ensure the following:
- **OpenSSL** is installed on your system to enable cryptographic operations.
    - For Ubuntu/Debian-based systems: `sudo apt install libssl-dev`
    - For Windows, ensure that OpenSSL libraries and headers are properly set in your environment, possible option for setup: `choco install openssl`.

## Build Instructions

To build the project using VSCode, follow these steps:

1. **Install Dependencies**: Make sure that OpenSSL is installed and available on your system.
2. **VSCode Setup**:
     - Open the project folder in VSCode.
     - Open the Command Palette (`Ctrl+Shift+P`), then select **Tasks: Run Build Task**.
     - Select **C/C++: g++.exe build active file**.
3. **Configure the Build Task**:
     - Open `.vscode/tasks.json`.
     - Modify the `args` parameter to include all necessary source files and the required OpenSSL libraries. The updated `args` should look like this:
         ```json
         "args": [
                 "-fdiagnostics-color=always",
                 "-g",
                 "${fileDirname}\\AES.cpp",
                 "${fileDirname}\\AES-CBC.cpp",
                 "${fileDirname}\\AES-ECB.cpp",
                 "${fileDirname}\\AES-CFB.cpp",
                 "${fileDirname}\\main.cpp",
                 "-o",
                 "${fileDirname}\\${fileBasenameNoExtension}.exe",
                 "-lssl",
                 "-lcrypto"
         ]
         ```
4. **Build**: Run the build task. The output executable will be created in the project directory.

## Usage

After building the project, you can use the AES implementation as follows:

- **Encryption**: Call the appropriate mode’s function to encrypt data. For example:
    ```cpp
    AES_CBC aesCBC;
    std::string encrypted = aesCBC.encrypt(data_to_encrypt_in_vector_format);
    ```
- **Decryption**: Similarly, decrypt data using the corresponding mode.

### Example (main.cpp)
The `main.cpp` file demonstrates AES encryption and decryption in multiple modes.

## License
This project is licensed under the MIT License.

## Roadmap / Future Features
- Support for additional AES modes (e.g., OFB, CTR).
- More extensive key management features, including importing/exporting keys.
- Integration with external storage systems for secure key and data storage.