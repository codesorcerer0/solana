#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <thread>
#include <atomic>
#include <chrono>
#include <iomanip>
#include <mutex>
#include <cstring>
#include <sodium.h>
#include <random>
#include <algorithm>
#include <unordered_set>
#include <cctype>

#ifdef _WIN32
  #include <windows.h>
#endif

// ----------------------- Utility Functions ---------------------------

// Base58 encoding function
std::string bytesToBase58(const unsigned char* bytes, size_t length) {
    static const char* BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    std::vector<unsigned char> temp(length * 2);
    size_t tempIndex = temp.size();

    for (size_t i = 0; i < length; ++i) {
        int carry = bytes[i];
        for (size_t j = temp.size(); j > tempIndex; --j) {
            carry += 256 * temp[j - 1];
            temp[j - 1] = carry % 58;
            carry /= 58;
        }
        while (carry > 0) {
            --tempIndex;
            temp[tempIndex] = carry % 58;
            carry /= 58;
        }
    }

    std::string result;
    for (size_t i = tempIndex; i < temp.size(); ++i)
        result += BASE58_ALPHABET[temp[i]];

    for (size_t i = 0; i < length && bytes[i] == 0; ++i)
        result.insert(result.begin(), '1');

    return result;
}

// Convert bytes to hex string
std::string bytesToHex(const unsigned char* bytes, size_t length) {
    std::ostringstream hexStream;
    for (size_t i = 0; i < length; ++i)
        hexStream << std::hex << std::setw(2) << std::setfill('0') << (int)bytes[i];
    return hexStream.str();
}

// Convert hex string to bytes
std::vector<unsigned char> hexToBytes(const std::string& hex) {
    std::vector<unsigned char> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteStr = hex.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(strtoul(byteStr.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

// ----------------------- Key Generation Utilities ---------------------------

// Generate a random private key for a given bitLength.
// Generates ceil(bitLength/8) bytes, masks off extra bits in the last byte,
// then left-pads the resulting hex string with zeros to a full 64 hex digits (32 bytes).
std::string generateRandomPrivateKey(int bitLength) {
    size_t fullBytes = bitLength / 8;
    size_t remainder = bitLength % 8;
    size_t totalBytes = (remainder == 0) ? fullBytes : fullBytes + 1;
    std::vector<unsigned char> randomBytes(totalBytes);
    randombytes_buf(randomBytes.data(), totalBytes);
    if (remainder != 0) {
        unsigned char mask = 0xFF << (8 - remainder);
        randomBytes[totalBytes - 1] &= mask;
    }
    std::string hexKey = bytesToHex(randomBytes.data(), totalBytes);
    if(hexKey.size() < 64)
        hexKey = std::string(64 - hexKey.size(), '0') + hexKey;
    return hexKey;
}

// Increment a hex string by 1 for the specified bit length.
// It uses ceil((bitLength)/4) hex digits.
void incrementHexString(std::string& hexKey, int bitLength) {
    size_t len = (bitLength + 3) / 4;
    for (int i = len - 1; i >= 0; --i) {
        if (hexKey[i] < 'f') {
            hexKey[i] = (hexKey[i] == '9') ? 'a' : hexKey[i] + 1;
            return;
        }
        hexKey[i] = '0';
    }
    hexKey = std::string(len, '0');
}

// ----------------------- Global Variables for Sequential Mode ---------------------------

std::string globalCurrentKey; // Variable portion of keyspace.
std::mutex globalKeyMutex;
const int BLOCK_SIZE = 1000;

// Get a block of keys from the global keyspace.
std::vector<std::string> getNextBlock(int blockSize, int bitLength, const std::string& endKey) {
    std::vector<std::string> block;
    std::lock_guard<std::mutex> lock(globalKeyMutex);
    for (int i = 0; i < blockSize; i++) {
        if (globalCurrentKey > endKey)
            break;
        block.push_back(globalCurrentKey);
        incrementHexString(globalCurrentKey, bitLength);
    }
    return block;
}

// ----------------------- Fast Target Loader using Windows Memory Mapping ---------------------------

std::unordered_set<std::string> loadTargetAddressesMMap(const std::string& filename) {
    std::unordered_set<std::string> targets;
#ifdef _WIN32
    HANDLE hFile = CreateFileA(filename.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "Error opening target file: " << filename << std::endl;
        return targets;
    }
    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hFile, &fileSize)) {
        std::cerr << "Error getting file size" << std::endl;
        CloseHandle(hFile);
        return targets;
    }
    HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMap) {
        std::cerr << "Error creating file mapping" << std::endl;
        CloseHandle(hFile);
        return targets;
    }
    char* data = static_cast<char*>(MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0));
    if (!data) {
        std::cerr << "Error mapping view of file" << std::endl;
        CloseHandle(hMap);
        CloseHandle(hFile);
        return targets;
    }
    size_t size = static_cast<size_t>(fileSize.QuadPart);
    std::string current;
    current.reserve(64);
    for (size_t i = 0; i < size; ++i) {
        char ch = data[i];
        if (ch == '\n' || ch == '\r') {
            if (!current.empty()) {
                current.erase(current.begin(), std::find_if(current.begin(), current.end(), [](unsigned char c){ return !std::isspace(c); }));
                current.erase(std::find_if(current.rbegin(), current.rend(), [](unsigned char c){ return !std::isspace(c); }).base(), current.end());
                if (!current.empty())
                    targets.insert(current);
                current.clear();
            }
        } else {
            current.push_back(ch);
        }
    }
    if (!current.empty()) {
        current.erase(current.begin(), std::find_if(current.begin(), current.end(), [](unsigned char c){ return !std::isspace(c); }));
        current.erase(std::find_if(current.rbegin(), current.rend(), [](unsigned char c){ return !std::isspace(c); }).base(), current.end());
        if (!current.empty())
            targets.insert(current);
    }
    UnmapViewOfFile(data);
    CloseHandle(hMap);
    CloseHandle(hFile);
#else
    // If not Windows, use the Linux version (omitted here)
#endif
    return targets;
}

// ----------------------- Key Generation Function ---------------------------

std::atomic<size_t> foundMatches(0);

// generateKeys works in sequential or random mode. It checks for target matches
// and saves keys if -o is specified.
void generateKeys(const std::string& keyspaceEnd, bool randomScan, int bitLength,
                  std::atomic<size_t>& totalKeysGenerated,
                  std::ofstream* outputFile, std::mutex* outputMutex,
                  const std::unordered_set<std::string>* targetSet,
                  std::mutex* foundMutex,
                  const std::string& foundFileName) {
    unsigned char publicKey[32];
    unsigned char privateKey[64];
    size_t varHexLength = (bitLength + 3) / 4;
    std::vector<std::string> localBuffer;
    if (outputFile)
        localBuffer.reserve(1000);

    if (!randomScan) {
        while (true) {
            auto block = getNextBlock(BLOCK_SIZE, bitLength, keyspaceEnd);
            if (block.empty())
                break;
            for (auto &varKey : block) {
                std::string paddedKey = std::string(64 - varKey.size(), '0') + varKey;
                std::vector<unsigned char> seed = hexToBytes(paddedKey);
                if (seed.size() != 32)
                    continue;
                if (crypto_sign_seed_keypair(publicKey, privateKey, seed.data()) != 0)
                    continue;
                std::string pubKeyBase58 = bytesToBase58(publicKey, sizeof(publicKey));
                totalKeysGenerated++;

                if (targetSet && targetSet->find(pubKeyBase58) != targetSet->end()) {
                    foundMatches++;
                    if (foundMutex) {
                        std::lock_guard<std::mutex> lock(*foundMutex);
                        std::ofstream foundFile(foundFileName, std::ios::app);
                        if (foundFile)
                            foundFile << pubKeyBase58 << " " << varKey << "\n";
                    }
                }
                if (outputFile)
                    localBuffer.push_back(pubKeyBase58 + " " + varKey);
            }
            if (outputFile && !localBuffer.empty()) {
                std::lock_guard<std::mutex> lock(*outputMutex);
                for (const auto& entry : localBuffer)
                    *outputFile << entry << "\n";
                localBuffer.clear();
            }
        }
    } else {
        while (true) { // In random mode, an external break condition is required.
            std::string varKey = generateRandomPrivateKey(bitLength).substr(64 - varHexLength);
            std::string paddedKey = std::string(64 - varKey.size(), '0') + varKey;
            std::vector<unsigned char> seed = hexToBytes(paddedKey);
            if (seed.size() != 32)
                continue;
            if (crypto_sign_seed_keypair(publicKey, privateKey, seed.data()) != 0)
                continue;
            std::string pubKeyBase58 = bytesToBase58(publicKey, sizeof(publicKey));
            totalKeysGenerated++;

            if (targetSet && targetSet->find(pubKeyBase58) != targetSet->end()) {
                foundMatches++;
                if (foundMutex) {
                    std::lock_guard<std::mutex> lock(*foundMutex);
                    std::ofstream foundFile(foundFileName, std::ios::app);
                    if (foundFile)
                        foundFile << pubKeyBase58 << " " << varKey << "\n";
                }
            }
            if (outputFile)
                localBuffer.push_back(pubKeyBase58 + " " + varKey);
        }
    }
}

// ----------------------- Print Usage ---------------------------

void printUsage() {
    std::cout << "Usage: ./keygen [options]\n"
              << "Options:\n"
              << "  -t <threads>           Number of threads (default: 4)\n"
              << "  -s                     Sequential scan (default)\n"
              << "  -r                     Random scan\n"
              << "  -keyspace <start:end>  Custom keyspace (hex strings for variable portion)\n"
              << "  -b <bits>              Key bit length (128 to 256, default: 256)\n"
              << "  -o <file>              Save all generated keys to <file>\n"
              << "  -f <target_file>       Load target addresses from <target_file> and save matches to foundsolana.txt\n"
              << "  -h, -help              Show help\n";
}

// ----------------------- Main ---------------------------

int main(int argc, char* argv[]) {
    if (sodium_init() < 0) {
        std::cerr << "Failed to initialize libsodium" << std::endl;
        return 1;
    }

    int numThreads = 4;
    bool randomScan = false;
    int bitLength = 256;
    std::string keyspaceStart, keyspaceEnd;
    std::string outputFileName;
    std::string targetFileName;

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-t") == 0 && i+1 < argc)
            numThreads = std::stoi(argv[++i]);
        else if (strcmp(argv[i], "-s") == 0)
            randomScan = false;
        else if (strcmp(argv[i], "-r") == 0)
            randomScan = true;
        else if (strcmp(argv[i], "-b") == 0 && i+1 < argc)
            bitLength = std::stoi(argv[++i]);
        else if (strcmp(argv[i], "-keyspace") == 0 && i+1 < argc) {
            std::string ks = argv[++i];
            size_t colon = ks.find(':');
            if (colon == std::string::npos) {
                std::cerr << "Invalid keyspace format" << std::endl;
                return 1;
            }
            keyspaceStart = ks.substr(0, colon);
            keyspaceEnd = ks.substr(colon+1);
        }
        else if (strcmp(argv[i], "-o") == 0 && i+1 < argc)
            outputFileName = argv[++i];
        else if (strcmp(argv[i], "-f") == 0 && i+1 < argc)
            targetFileName = argv[++i];
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "-help") == 0) {
            printUsage();
            return 0;
        }
    }

    size_t expectedVarLength = (bitLength + 3) / 4;
    if (keyspaceStart.empty())
        keyspaceStart = std::string(expectedVarLength, '0');
    if (keyspaceEnd.empty())
        keyspaceEnd = std::string(expectedVarLength, 'f');

    // In sequential mode, initialize the global key.
    if (!randomScan) {
        std::lock_guard<std::mutex> lock(globalKeyMutex);
        globalCurrentKey = keyspaceStart;
    }

    // Load target addresses.
    std::unordered_set<std::string> targetAddresses;
    bool useTargets = false;
    if (!targetFileName.empty()) {
        std::cout << "Loading target addresses from " << targetFileName << " ..." << std::endl;
        targetAddresses = loadTargetAddressesMMap(targetFileName);
        if (!targetAddresses.empty()) {
            useTargets = true;
            std::cout << "Loaded " << targetAddresses.size() << " target addresses." << std::endl;
        }
    }

    // Open output file if -o is specified.
    std::ofstream outputFile;
    std::mutex fileMutex;
    bool saveAll = !outputFileName.empty();
    if (saveAll) {
        outputFile.open(outputFileName);
        if (!outputFile) {
            std::cerr << "Failed to open output file: " << outputFileName << std::endl;
            return 1;
        }
    }

    std::mutex foundMutex;
    const std::string foundFileName = "foundsolana.txt";

    std::atomic<size_t> totalKeys(0);
    std::vector<std::thread> threads;
    std::atomic<bool> running(true);
    auto start = std::chrono::high_resolution_clock::now();

    std::thread speedThread([&]() {
        while (running) {
            auto now = std::chrono::high_resolution_clock::now();
            double elapsed = std::chrono::duration<double>(now - start).count();
            std::cout << "\rKeys/s: " << std::fixed << std::setprecision(2)
                      << totalKeys.load() / elapsed << " (" << totalKeys.load() << " total)" << std::flush;
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    });

    for (int i = 0; i < numThreads; ++i) {
        threads.emplace_back(generateKeys, keyspaceEnd, randomScan, bitLength,
                             std::ref(totalKeys),
                             saveAll ? &outputFile : nullptr, &fileMutex,
                             useTargets ? &targetAddresses : nullptr, &foundMutex, foundFileName);
    }

    for (auto& t : threads)
        t.join();
    running = false;
    speedThread.join();

    if (saveAll)
        outputFile.close();

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;
    std::cout << "\nTotal keys scanned: " << totalKeys.load() << "\n";
    if (useTargets)
        std::cout << "Total target matches found: " << foundMatches.load() << "\n";
    std::cout << "Elapsed time: " << elapsed.count() << " seconds\n";

    return 0;
}
