# Strix - Lightweight C++ Web Server

Strix is a lightweight, multi-threaded web server framework built in modern C++ with cross-platform support for macOS, Linux, and Windows.

## Features
- **HTTPS Support**: Runs on `https://127.0.0.1:8080/` with self-signed certificates.
- **Cross-Platform**: Compatible with macOS, Linux, and Windows using platform-specific socket handling.
- **Modern C++**: Leverages C++23 features like concepts and `<string_view>` for efficiency.
- **Thread Pool**: Handles multiple connections concurrently with a configurable thread pool.
- **Virtual Hosts**: Supports routing based on hostnames.
- **Static File Serving**: Serves files from a specified directory.

## Prerequisites
- **CMake**: Version 3.10 or higher for building the project.
- **OpenSSL**: Required for HTTPS support.
  - **macOS**: `brew install openssl`
  - **Linux**: `sudo apt-get install libssl-dev` (Ubuntu) or `sudo yum install openssl-devel` (CentOS)
  - **Windows**: Install via vcpkg or download from [OpenSSL binaries](https://slproweb.com/products/Win32OpenSSL.html)
- **C++ Compiler**: Must support C++23 (e.g., GCC 13+, Clang 16+, MSVC 2022+).
  - **macOS**: Install Xcode or `xcode-select --install` for Clang.
  - **Linux**: `sudo apt-get install g++` or equivalent.
  - **Windows**: Visual Studio 2022 with C++ tools or MinGW-w64.
- **Git**: For cloning the repository.

## Setup

### Clone the Repository
```bash
git clone https://github.com/compez/strix.git
cd strix
```

### Build Instructions

- You can use bootstrap method via PT project template.
```
 mkdir build
 cd build
 cmake .. -DUSE_JSON=true -DUSE_OPENSSL=true -DDUSE_ZLIB=true
 make
 ```

#### macOS
1. **Install Dependencies**:
   ```bash
   brew install cmake openssl
   ```
   Ensure OpenSSL is in your path (e.g., `/usr/local/opt/openssl`).

2. **Generate Build Files**:
   ```bash
   mkdir build && cd build
   cmake -G "Unix Makefiles" -DCMAKE_CXX_COMPILER=clang++ -DOPENSSL_ROOT_DIR=/usr/local/opt/openssl ..
   ```

3. **Build**:
   ```bash
   make
   ```

4. **Run**:
   ```bash
   ./strix
   ```

#### Linux (e.g., Ubuntu)
1. **Install Dependencies**:
   ```bash
   sudo apt-get update
   sudo apt-get install cmake g++ libssl-dev
   ```

2. **Generate Build Files**:
   ```bash
   mkdir build && cd build
   cmake -G "Unix Makefiles" -DCMAKE_CXX_COMPILER=g++ ..
   ```

3. **Build**:
   ```bash
   make
   ```

4. **Run**:
   ```bash
   ./strix
   ```

#### Windows
1. **Install Dependencies**:
   - Install [CMake](https://cmake.org/download/) and add it to your PATH.
   - Install OpenSSL via vcpkg:
     ```bash
     git clone https://github.com/Microsoft/vcpkg.git
     cd vcpkg
     .\bootstrap-vcpkg.bat
     .\vcpkg integrate install
     .\vcpkg install openssl:x64-windows
     ```
   - Install Visual Studio 2022 with C++ Desktop Development workload, or MinGW-w64.

2. **Generate Build Files**:
   - Using Visual Studio:
     ```bash
     mkdir build && cd build
     cmake -G "Visual Studio 17 2022" -A x64 -DCMAKE_TOOLCHAIN_FILE=[path_to_vcpkg]/scripts/buildsystems/vcpkg.cmake ..
     ```
   - Using MinGW:
     ```bash
     mkdir build && cd build
     cmake -G "MinGW Makefiles" -DCMAKE_CXX_COMPILER=g++ ..
     ```

3. **Build**:
   - Visual Studio: Open `strix.sln` in the build directory and build the `strix` target.
   - MinGW:
     ```bash
     mingw32-make
     ```

4. **Run**:
   - Visual Studio: Run from the debugger or `build/Debug/strix.exe`.
   - MinGW:
     ```bash
     .\strix.exe
     ```

### Generate Self-Signed Certificates (Optional for HTTPS)
To enable HTTPS, generate a self-signed certificate:
```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
```
Update your `Config` in `main.cpp` with paths to `cert.pem` and `key.pem`.

## Usage
- Default server runs on `http://127.0.0.1:8080/` (or `https` if configured).
- Customize `main.cpp` to add routes or handlers:
  ```cpp
  server->addRoute("", "/hello", Strix::Request::Method::GET, std::make_unique<Strix::StaticFileHandler>("./html"));
  ```

## Troubleshooting
- **Segmentation Fault**: Run with a debugger (e.g., `lldb ./strix` on macOS/Linux, Visual Studio Debugger on Windows) and check the backtrace (`bt`).
- **OpenSSL Not Found**: Ensure `OPENSSL_ROOT_DIR` is set correctly in CMake if it’s in a non-standard location.
- **Compiler Errors**: Verify C++23 support with your compiler (`g++ --version`, `clang++ --version`, or VS settings).

---

### Notes
- **Cross-Platform Adjustments**: The code already uses `#ifdef _WIN32` for socket handling (e.g., `winsock2.h` vs. POSIX sockets), so it’s cross-platform.
- **C++23**: Specified C++23 explicitly since your code uses concepts (`Loggable`, `RequestHandleable`).
- **OpenSSL**: Provided platform-specific installation instructions.
- **Build Systems**: Covered Unix Makefiles (macOS/Linux), Visual Studio, and MinGW for Windows.
