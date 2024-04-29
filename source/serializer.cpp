#include <bit>
#include <cstdlib>
#include <string>
#include <format>
#include "block.h"
#include "crypto.h"
#include "serializer.h"
#include "tx.h"
#include "util.h"

using namespace Util;
namespace Serializer {

auto genCompactInt(const auto &num) {
    if (num >= 0 && num <= 252)
        return std::format("{:02x}", std::byteswap<uint8_t>(num));
    else if (num >= 253 && num <= 0xffff)
        return std::format("fd{:04x}", std::byteswap<uint16_t>(num));
    else if (num >= 0x10000 and num <= 0xffffffff)
        return std::format("fe{:08x}", std::byteswap<uint32_t>(num));

    return std::format("ff{:016x}", std::byteswap<uint64_t>(num));
}

std::string genRaw(const Tx::Tx& tx, bool forceLegacy) {
    std::string rawTx;
    rawTx.reserve(8192);

    bool isSegwit = false;
    for (const auto& txin : tx.txIns) {
        isSegwit = txin.witness.size() > 0;
        if (isSegwit)
            break;
    }

    isSegwit = !forceLegacy && isSegwit;

    rawTx += std::format("{:08x}", std::byteswap(tx.version));

    if (isSegwit) {
        rawTx += std::format("{:02x}", tx.marker);
        rawTx += std::format("{:02x}", tx.flag);
    }

    rawTx += genCompactInt(tx.txIns.size());

    for (const auto& vin : tx.txIns) {
        auto txID = getAsVector(vin.txId);
        for (int i = txID.size() - 1; i >= 0; i--) {
            rawTx += std::format("{:02x}", txID[i]);
        }

        rawTx += std::format("{:08x}", std::byteswap(vin.vout));

        const std::string& scriptSig = vin.scriptSig;
        rawTx += genCompactInt(scriptSig.length() / 2); // each character is a single nyble
        rawTx += scriptSig;

        rawTx += std::format("{:08x}", std::byteswap(vin.sequence));
    }

    rawTx += genCompactInt(tx.txOuts.size());

    for (const auto& vout : tx.txOuts) {
        auto value = vout.value;
        rawTx += std::format("{:016x}", std::byteswap<uint64_t>(value));

        rawTx += genCompactInt(vout.scriptPubKey.length() / 2); // each character is a single nyble
        rawTx += vout.scriptPubKey;
    }

    if (isSegwit) {
        for (const auto& vin: tx.txIns) {
            rawTx += genCompactInt(vin.witness.size());

            for (const auto& w : vin.witness) {
                rawTx += genCompactInt(w.length() / 2);
                rawTx += w;
            }
        }
    }

    rawTx += std::format("{:08x}", std::byteswap(tx.lockTime));
    return rawTx;
}

std::string getOrigSerialization(const Tx::Tx& tx) {
    std::string rawTx;
    rawTx.reserve(8192);

    rawTx += std::format("{:08x}", std::byteswap(tx.version));

    rawTx += genCompactInt(tx.txIns.size());

    for (const auto& vin : tx.txIns) {
        auto txID = getAsVector(vin.txId);
        for (int i = txID.size() - 1; i >= 0; i--) {
            rawTx += std::format("{:02x}", txID[i]);
        }

        rawTx += std::format("{:08x}", std::byteswap(vin.vout));

        if (vin.prevout.scriptpubkeyType == "p2sh") {
            // get redeem script
            std::string scriptPubKey = vin.scriptSigAsm;
            auto idx = scriptPubKey.rfind(" ") + 1;
            scriptPubKey = scriptPubKey.substr(idx);

            rawTx += genCompactInt(scriptPubKey.length() / 2);
            rawTx += scriptPubKey;
        } else {
            const std::string& scriptPubKey = vin.prevout.scriptPubKey;
            rawTx += genCompactInt(scriptPubKey.length() / 2); // each character is a single nyble
            rawTx += scriptPubKey;
        }

        rawTx += std::format("{:08x}", std::byteswap(vin.sequence));
    }

    rawTx += genCompactInt(tx.txOuts.size());

    for (const auto& vout : tx.txOuts) {
        rawTx += std::format("{:016x}", std::byteswap<uint64_t>(vout.value));

        const std::string&  scriptPubKey = vout.scriptPubKey;
        rawTx += genCompactInt(scriptPubKey.length() / 2); // each character is a single nyble
        rawTx += scriptPubKey;
    }

    rawTx += std::format("{:08x}", std::byteswap(tx.lockTime));
    rawTx += "01000000"; // Eeeks, fixme


    return rawTx;
}

std::string getBIP143Serialization(const Tx::Tx& tx, unsigned int idx) {
    std::string rawTx, vinOutpoints, vinSeq, outPoint, voutOutpoints;

    rawTx.reserve(8192);
    vinOutpoints.reserve(8192);
    vinSeq.reserve(8192);
    outPoint.reserve(4096);
    voutOutpoints.reserve(8192);

    rawTx += std::format("{:08x}", std::byteswap(tx.version));

    for (unsigned int i = 0; i < tx.txIns.size(); i++) {
        const auto& vin = tx.txIns[i];
        auto txID = getAsVector(vin.txId);
        for (int j = txID.size() - 1; j >= 0; j--) {
            vinOutpoints += std::format("{:02x}", txID[j]);
        }

        vinOutpoints += std::format("{:08x}", std::byteswap(vin.vout));
        vinSeq += std::format("{:08x}", std::byteswap(vin.sequence));
    }

    rawTx += Crypto::getSHA256<std::string>(Crypto::getSHA256(getAsVector(vinOutpoints)));
    rawTx += Crypto::getSHA256<std::string>(Crypto::getSHA256(getAsVector(vinSeq)));

    const auto& vinAtIdx = tx.txIns[idx];
    auto txID = getAsVector(vinAtIdx.txId);
    auto vout_idx = vinAtIdx.vout;

    for (int j = txID.size() - 1; j >= 0; j--)
        outPoint += std::format("{:02x}", txID[j]);
    outPoint += std::format("{:08x}", std::byteswap(vout_idx));

    rawTx += outPoint;

    if (vinAtIdx.prevout.scriptpubkeyType == "v0_p2wsh") {
        const auto last = vinAtIdx.witness.size() - 1;
        const std::string witnessScript = vinAtIdx.witness[last];

        rawTx += genCompactInt(witnessScript.length() / 2);
        rawTx += witnessScript;
    } else if (vinAtIdx.prevout.scriptpubkeyType == "p2sh" && !vinAtIdx.witness.empty()) {
        std::string redeemScript = vinAtIdx.scriptSig.substr(6);

        rawTx += "1976a914";
        rawTx += redeemScript;
        rawTx += "88ac";
    } else {
        const std::string&  scriptPubKey = vinAtIdx.prevout.scriptPubKey;
        const auto& pubKeyHash = scriptPubKey.substr(4);

        rawTx += "1976a914";
        rawTx += pubKeyHash;
        rawTx += "88ac";
    }

    rawTx += std::format("{:016x}", std::byteswap<uint64_t>(vinAtIdx.prevout.value));

    rawTx += std::format("{:08x}", std::byteswap(vinAtIdx.sequence));

    for (const auto& vout : tx.txOuts) {
        voutOutpoints += std::format("{:016x}", std::byteswap<uint64_t>(vout.value));

        const std::string& scriptPubKey = vout.scriptPubKey;
        voutOutpoints += genCompactInt(scriptPubKey.length() / 2); // each character is a single nyble
        voutOutpoints += scriptPubKey;
    }

    rawTx += Crypto::getSHA256<std::string>(Crypto::getSHA256(getAsVector(voutOutpoints)));

    rawTx += std::format("{:08x}", std::byteswap(tx.lockTime));
    rawTx += "01000000"; // Eeeks, fixme

    return rawTx;
}

std::string getBlockHeaderSerialization(const Block::Block &b) {
    std::string rawBlock {};
    rawBlock.reserve(100);

    rawBlock += std::format("{:08x}", std::byteswap(b.version));
    for (int j = b.prevBlkHash.size() - 1; j >= 0; j--)
        rawBlock += std::format("{:02x}", b.prevBlkHash[j]);

    for (int j = b.merkleRoot.size() - 1; j >= 0; j--)
        rawBlock += std::format("{:02x}", b.merkleRoot[j]);

    rawBlock += std::format("{:08x}", std::byteswap(b.time));
    rawBlock += std::format("{:08x}", std::byteswap(b.bits));

    // nonce is added manually by the mining function

    return rawBlock;
}

}
