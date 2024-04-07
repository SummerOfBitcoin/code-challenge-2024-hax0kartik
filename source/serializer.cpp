#include <bit>
#include <cstdlib>
#include <string>
#include <sstream>
#include <format>
#include <nlohmann/json.hpp>
#include "crypto.h"
#include "serializer.h"
#include "util.h"

using json = nlohmann::json;
using namespace Util;
namespace Serializer {
    
auto genCompactInt(const auto &num) {
    if (num >= 0 && num <= 252)
        return std::format("{:02x}", std::byteswap(static_cast<uint8_t>(num)));
    else if (num >= 253 && num <= 0xffff)
        return std::format("{:04x}", std::byteswap(static_cast<uint16_t>(num)));
    else if (num >= 0x10000 and num <= 0xffffffff)
        return std::format("{:08x}", std::byteswap(static_cast<uint32_t>(num)));

    return std::format("{:016x}", std::byteswap(static_cast<uint64_t>(num)));
}

std::string genRaw(const json& data) {
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

std::string getOrigSerialization(const json& data) {
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

        if (vin["prevout"]["scriptpubkey_type"] == "p2sh") {
            // get redeem script
            std::string scriptPubKey = vin["scriptsig_asm"];
            auto idx = scriptPubKey.rfind(" ") + 1;
            scriptPubKey = scriptPubKey.substr(idx);

            rawTx << genCompactInt(scriptPubKey.length() / 2);
            rawTx << scriptPubKey;
        } else {
            std::string scriptPubKey = vin["prevout"]["scriptpubkey"];
            rawTx << genCompactInt(scriptPubKey.length() / 2); // each character is a single nyble
            rawTx << scriptPubKey;
        }

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

std::string getBIP143Serialization(const json &data, unsigned int idx) {
    std::ostringstream rawTx, vinOutpoints, vinSeq, outPoint, voutOutpoints;

    int version = data["version"];
    rawTx << std::format("{:08x}", std::byteswap(version));

    for (unsigned int i = 0; i < data["vin"].size(); i++) {
        const auto& vin = data["vin"][i];
        auto txID = getAsVector(vin["txid"]);
        for (int j = txID.size() - 1; j >= 0; j--) {
            vinOutpoints << std::format("{:02x}", txID[j]);
        }

        uint32_t vout_idx = vin["vout"];
        vinOutpoints << std::format("{:08x}", std::byteswap(vout_idx));

        uint32_t sequence = vin["sequence"];
        vinSeq << std::format("{:08x}", std::byteswap(sequence));
    }

    rawTx << Crypto::getSHA256<std::string>(Crypto::getSHA256(getAsVector(vinOutpoints.str())));
    rawTx << Crypto::getSHA256<std::string>(Crypto::getSHA256(getAsVector(vinSeq.str())));

    const auto& vinAtIdx = data["vin"][idx];
    auto txID = getAsVector(vinAtIdx["txid"]);
    uint32_t vout_idx = vinAtIdx["vout"];

    for (int j = txID.size() - 1; j >= 0; j--)
        outPoint << std::format("{:02x}", txID[j]);
    outPoint << std::format("{:08x}", std::byteswap(vout_idx));

    rawTx << outPoint.str();

    if (vinAtIdx["prevout"]["scriptpubkey_type"] == "v0_p2wsh") {
        const auto last = vinAtIdx["witness"].size() - 1;
        const std::string witnessScript = vinAtIdx["witness"][last];

        rawTx << genCompactInt(witnessScript.length() / 2);
        rawTx << witnessScript;
    } else if (vinAtIdx["prevout"]["scriptpubkey_type"] == "p2sh" && vinAtIdx.contains("witness")) {
        std::string redeemScript = vinAtIdx["scriptsig"];
        redeemScript = redeemScript.substr(6);
        
        rawTx << "1976a914" + redeemScript + "88ac";
    } else {
        const std::string scriptPubKey = vinAtIdx["prevout"]["scriptpubkey"];
        const auto& pubKeyHash = scriptPubKey.substr(4);

        rawTx << "1976a914" + pubKeyHash + "88ac";
    }

    uint64_t value = vinAtIdx["prevout"]["value"];
    rawTx << std::format("{:016x}", std::byteswap(value));

    uint32_t sequence = vinAtIdx["sequence"];
    rawTx << std::format("{:08x}", std::byteswap(sequence));

    for (const auto& vout : data["vout"]) {
        uint64_t value = vout["value"];
        voutOutpoints << std::format("{:016x}", std::byteswap(value));

        std::string scriptPubKey = vout["scriptpubkey"];
        voutOutpoints << genCompactInt(scriptPubKey.length() / 2); // each character is a single nyble
        voutOutpoints << scriptPubKey;
    }

    rawTx << Crypto::getSHA256<std::string>(Crypto::getSHA256(getAsVector(voutOutpoints.str())));

    uint32_t lockTime = data["locktime"];
    rawTx << std::format("{:08x}", std::byteswap(lockTime));
    rawTx << "01000000"; // Eeeks, fixme

    return rawTx.str();
}
}