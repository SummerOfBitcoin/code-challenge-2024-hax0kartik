#pragma once
#include <cstdlib>
#include <string>
#include <sstream>
#include <vector>
#include <format>

namespace Util {
/*
template<std::size_t t1>
constexpr std::string convertToHexStr(const int& inp) {
    size_t sz = t1 -1;
    constexpr char data[t1] = {'0'};
    int inpS = inp;
    while(inpS > 0) {
        int d = inp % 10;
        data[sz--] = d;

    }

    return std::string(data);
}
*/

inline std::vector<uint8_t> getAsVector(const std::string& hex) {
    std::vector<uint8_t> bytes;

    for (unsigned int i = 0; i < hex.length(); i += 2) {
        auto byteString = hex.substr(i, 2);
        uint8_t byte = std::stoi(byteString.c_str(), NULL, 16);
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
