#ifndef UTIL_H
#define UTIL_H

#include <string>
#include <sstream>
#include <vector>
#include <format>

namespace Util {
inline std::vector<uint8_t> getAsVector(const std::string& hex) {
    std::vector<uint8_t> bytes;

    for (unsigned int i = 0; i < hex.length(); i += 2) {
        auto byteString = hex.substr(i, 2);
        uint8_t byte = std::strtol(byteString.c_str(), NULL, 16);
        bytes.push_back(byte);
    }
    
    return bytes;
}

inline std::string getAsString(const std::vector<uint8_t>& bytes) {
    std::ostringstream output;

    for (unsigned int i = 0; i < bytes.size(); i++) {
        output << std::format("{:02x}", bytes[i]);
    }

    return output.str();
}
}

#endif // UTIL_H