#pragma once
#include <string>
#include <vector>
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace Tx {
struct TxOut {
    std::string scriptPubKey {};
    std::string scriptpubkeyAsm {};
    std::string scriptpubkeyType {};
    std::string scriptpubkeyAddress {};
    uint64_t value {};

    TxOut() = default;

    TxOut(const json& j);
};

struct TxIn {
    std::string txId {};
    uint32_t vout {};
    TxOut prevout {};
    std::string scriptSig {};
    std::string scriptSigAsm {}; // this saves from having to implement opcode decoder
    std::vector<std::string> witness {};
    bool isCoinbase {};
    uint32_t sequence {};
    std::string innerScriptAsm {};

    TxIn() = default;

    TxIn(const json& j);
};

struct Tx {
    std::vector<uint8_t> txid {};
    std::string txidHash {};

    uint32_t version {};
    uint32_t lockTime {};

    std::vector<TxIn> txIns {};
    std::vector<TxOut> txOuts {};

    int64_t fees {};

    void calcFees();

    // copy is expensive, do not allow copying this struct
    Tx(const Tx&) = delete;
    Tx& operator=(const Tx&) = delete;
    Tx(Tx&& ) = default;
    Tx() = default;

    Tx(const json& j);
};

}
