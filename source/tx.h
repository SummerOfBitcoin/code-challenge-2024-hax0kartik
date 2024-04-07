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
};

struct Tx {
    uint32_t version {};
    uint32_t lockTime {};

    std::vector<TxIn> txIns {};
    std::vector<TxOut> txOuts {};
};

inline void from_json(const json& j, TxOut& txOut) {
    j.at("scriptpubkey").get_to(txOut.scriptPubKey);
    j.at("scriptpubkey_asm").get_to(txOut.scriptpubkeyAsm);
    j.at("scriptpubkey_type").get_to(txOut.scriptpubkeyType);
    if (j.contains("scriptpubkey_address"))
        j.at("scriptpubkey_address").get_to(txOut.scriptpubkeyAddress);
    j.at("value").get_to(txOut.value);
}

inline void from_json(const json& j, TxIn& txIn) {
    j.at("txid").get_to(txIn.txId);
    j.at("vout").get_to(txIn.vout);
    j.at("prevout").get_to(txIn.prevout);
    j.at("scriptsig").get_to(txIn.scriptSig);
    j.at("scriptsig_asm").get_to(txIn.scriptSigAsm);
    if (j.contains("witness"))
        j.at("witness").get_to(txIn.witness);
    j.at("is_coinbase").get_to(txIn.isCoinbase);
    j.at("sequence").get_to(txIn.sequence);
    if (j.contains("inner_witnessscript_asm"))
        j.at("inner_witnessscript_asm").get_to(txIn.innerScriptAsm);
    else if (j.contains("inner_redeemscript_asm"))
        j.at("inner_redeemscript_asm").get_to(txIn.innerScriptAsm);
}


inline void from_json(const json& j, Tx& tx) {
    j.at("version").get_to(tx.version);
    j.at("locktime").get_to(tx.lockTime);
    j.at("vin").get_to(tx.txIns);
    j.at("vout").get_to(tx.txOuts);
}

}
