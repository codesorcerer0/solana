# solana
solana: Multi-threaded Ed25519 Key Generation & Target Matching Tool
solana is a high-performance, multi-threaded C++ tool that generates Ed25519 key pairs using the libsodium library. It offers both sequential and random scanning modes over a configurable keyspace and supports target address matching. Use solana to scan for keys that meet your criteria—whether you want to explore a specific range or search for target addresses (e.g., Solana addresses) from a file.

#Features
Multi-threaded Key Generation: Utilize multiple threads to maximize throughput.
Scan Modes: Choose between sequential scanning (default) or random scanning.
Custom Keyspace: Define your own keyspace range with hexadecimal start and end values.
Configurable Bit Length: Specify the key bit length (from 128 to 256 bits; default is 256).
Output Options: Save all generated keys to a file if desired.
Target Matching: Load a list of target addresses and record any matches to a file (foundsolana.txt).
Progress Reporting: Real-time output of keys generated per second and total keys scanned.
Optimized Target Loading: Uses Windows memory mapping for fast loading of target addresses (Linux support can be added).
Requirements
Compiler: A C++11 (or later) compliant compiler.
Dependencies: libsodium for cryptographic functions.
Platform: Designed for Windows (with memory mapping support); Linux users may need to implement an alternative target loader.
Build Instructions
Install libsodium:
Follow the instructions on the libsodium website to install the library on your system.

# Compile the Code:
For example, using g++ on Windows (adjust the command if needed):

bash
Copy
Edit
g++ -std=c++11 -O2 solana.cpp -lsodium -o solana
On Linux, ensure you link against libsodium and adjust any platform-specific code.

## Usage
Run the executable from the command line with the following options:

bash
Copy
Edit
solana.exe [options]
Command-line Options
-t <threads>
Specify the number of threads to use (default: 4).

-s
Use sequential scan mode (this is the default mode).

-r
Use random scan mode.

-keyspace <start:end>
Define a custom keyspace for scanning. Both start and end should be hexadecimal strings representing the variable portion of the key.

-b <bits>
Set the key bit length (allowed values: 128 to 256; default is 256).

-o <file>
Save all generated keys to the specified output file.

-f <target_file>
Load target addresses from the specified file. Any matching public keys will be saved to foundsolana.txt.

-h, -help
Display the help message.

How It Works
Key Generation:
The program generates a block of keys either sequentially or randomly. Each key is created by:

Generating a seed from the defined keyspace.
Using crypto_sign_seed_keypair from libsodium to produce the Ed25519 key pair.
Converting the public key to a Base58 string.
Target Matching (Optional):
If a target file is provided, the tool loads target addresses (using Windows memory mapping for efficiency) and compares each generated public key against these targets. Matches are logged to foundsolana.txt.

# Output:

Console: Displays real-time statistics (keys per second, total keys generated).
File Output: If specified, all generated keys are written to a file; matching keys are saved separately.
Disclaimer
This tool is provided for educational and research purposes only. Ensure that you use it in compliance with all applicable laws and regulations. The author is not responsible for any misuse or damages arising from its use.

## License
Distributed under the MIT License. See the LICENSE file for details.

## Contributing
Contributions are welcome! Feel free to fork the repository, submit pull requests, or open issues for improvements and bug fixes.

## Contact :: @CodeSorcerer0 / https://t.me/CodeSorcerer0
For questions or suggestions, please open an issue on the GitHub repository or contact the maintainer directly.
> telegram :: 
> code_crusaders :: https://t.me/code_Crusaders0/1
 > KEYFOUND ::  https://t.me/privatekeydirectorygroup

## Happy Key Hunting!
