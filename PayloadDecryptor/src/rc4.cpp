#include <iostream>
#include <fstream>
#include <vector>
#include <string>

class RC4 {
public:
    RC4(const std::vector<uint8_t>& key) {
        for (int i = 0; i < 256; ++i) {
            S[i] = i;
        }
        int j = 0;
        for (int i = 0; i < 256; ++i) {
            j = (j + S[i] + key[i % key.size()]) % 256;
            std::swap(S[i], S[j]);
        }
        i = j = 0;
    }

    void process(std::vector<uint8_t>& data) {
        for (auto& byte : data) {
            i = (i + 1) % 256;
            j = (j + S[i]) % 256;
            std::swap(S[i], S[j]);
            byte ^= S[(S[i] + S[j]) % 256];
        }
    }

private:
    uint8_t S[256];
    int i, j;
};

std::vector<uint8_t> convertKey(const std::string& keyStr) {
    std::vector<uint8_t> keyBytes;
    uint64_t keyInt = std::stoull(keyStr);
    while (keyInt > 0) {
        keyBytes.push_back(static_cast<uint8_t>(keyInt & 0xFF));
        keyInt >>= 8;
    }
    return keyBytes;
}

std::vector<uint8_t> readFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}

void writeFile(const std::string& filename, const std::vector<uint8_t>& data) {
    std::ofstream file(filename, std::ios::binary);
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <encrypted file> <key> <output file>\n";
        return 1;
    }

    std::string inputFile = argv[1];
    std::string keyStr = argv[2];
    std::string outputFile = argv[3];

    std::vector<uint8_t> key = convertKey(keyStr);
    std::vector<uint8_t> data = readFile(inputFile);
    std::cout << data.size() << "\n";
    std::cout << key.size() << "\n";
    std::cout << std::hex;
    std::reverse(key.begin(), key.end());
    for (uint8_t x : key)
        std::cout << (int)x << " ";
    std::cout << "\n";

    RC4 rc4(key);
    rc4.process(data);

    writeFile(outputFile, data);

    std::cout << "Decryption complete. Output written to " << outputFile << "\n";
    return 0;
}
