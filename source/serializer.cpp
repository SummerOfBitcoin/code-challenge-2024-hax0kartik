#include <bit>
#include <cstdlib>
#include <string>
#include <sstream>
#include <format>
#include <nlohmann/json.hpp>
#include "serializer.h"

using json = nlohmann::json;

namespace Serializer {
    
std::vector<uint8_t> getAsVector(const std::string& hex) {
    std::vector<uint8_t> bytes;

    for (unsigned int i = 0; i < hex.length(); i += 2) {
        auto byteString = hex.substr(i, 2);
        uint8_t byte = std::strtol(byteString.c_str(), NULL, 16);
        bytes.push_back(byte);
    }
    
    return bytes;
}

std::string getAsString(const std::vector<uint8_t>& bytes) {
    std::ostringstream output;

    for (unsigned int i = 0; i < bytes.size(); i++) {
        output << std::format("{:02x}", bytes[i]);
    }

    return output.str();
}

auto genCompactInt(const auto &num) {
    if (num >= 0 && num <= 252)
        return std::format("{:02x}", std::byteswap(static_cast<uint8_t>(num)));
    else if (num >= 253 && num <= 0xffff)
        return std::format("{:04x}", std::byteswap(static_cast<uint16_t>(num)));
    else if (num >= 0x10000 and num <= 0xffffffff)
        return std::format("{:08x}", std::byteswap(static_cast<uint32_t>(num)));

    return std::format("{:016x}", std::byteswap(static_cast<uint64_t>(num)));
}

std::string genRawFromJson(const json& data) {
    std::ostringstream rawTx;

    int version = data["version"];
    rawTx << std::format("{:08x}", std::byteswap(version));

    auto txInLen = data["vin"].size();
    rawTx << genCompactInt(txInLen);

    for (const auto& vin : data["vin"]) {
        auto txID = getAsVector(vin["txid"]);
        for (int i = txID.size() - 1; i >= 0; i--) {
            rawTx << std::format("{:02x}", txID[i]);
        }

        uint32_t vout_idx = vin["vout"];
        rawTx << std::format("{:08x}", std::byteswap(vout_idx));

        std::string scriptSig = vin["scriptsig"];
        rawTx << genCompactInt(scriptSig.length() / 2); // each character is a single nyble
        rawTx << scriptSig;

        uint32_t sequence = vin["sequence"];
        rawTx << std::format("{:08x}", std::byteswap(sequence));
    }

    auto txOutLen = data["vout"].size();
    rawTx << genCompactInt(txOutLen);

    for (const auto& vout : data["vout"]) {
        uint64_t value = vout["value"];
        rawTx << std::format("{:016x}", std::byteswap(value));

        std::string scriptPubKey = vout["scriptpubkey"];
        rawTx << genCompactInt(scriptPubKey.length() / 2); // each character is a single nyble
        rawTx << scriptPubKey;
    }

    uint32_t lockTime = data["locktime"];
    rawTx << std::format("{:08x}", std::byteswap(lockTime));

    return rawTx.str();
}

std::string getForVerificationFromJson(const json& data) {
    std::ostringstream rawTx;

    int version = data["version"];
    rawTx << std::format("{:08x}", std::byteswap(version));

    auto txInLen = data["vin"].size();
    rawTx << genCompactInt(txInLen);

    for (const auto& vin : data["vin"]) {
        auto txID = getAsVector(vin["txid"]);
        for (int i = txID.size() - 1; i >= 0; i--) {
            rawTx << std::format("{:02x}", txID[i]);
        }

        uint32_t vout_idx = vin["vout"];
        rawTx << std::format("{:08x}", std::byteswap(vout_idx));

        std::string scriptPubKey = vin["prevout"]["scriptpubkey"];
        rawTx << genCompactInt(scriptPubKey.length() / 2); // each character is a single nyble
        rawTx << scriptPubKey;

        uint32_t sequence = vin["sequence"];
        rawTx << std::format("{:08x}", std::byteswap(sequence));
    }

    auto txOutLen = data["vout"].size();
    rawTx << genCompactInt(txOutLen);

    for (const auto& vout : data["vout"]) {
        uint64_t value = vout["value"];
        rawTx << std::format("{:016x}", std::byteswap(value));

        std::string scriptPubKey = vout["scriptpubkey"];
        rawTx << genCompactInt(scriptPubKey.length() / 2); // each character is a single nyble
        rawTx << scriptPubKey;
    }

    uint32_t lockTime = data["locktime"];
    rawTx << std::format("{:08x}", std::byteswap(lockTime));
    rawTx << "01000000"; // Eeeks, fixme

    return rawTx.str();
}
}