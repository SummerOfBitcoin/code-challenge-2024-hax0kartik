#include <iostream>
#include <string>
#include <functional>
#include <unordered_map>
#include "verifier.h"
#include "script.h"
#include "serializer.h"

namespace TxVerifier {

bool do_p2pkh(const Tx::Tx& tx, unsigned int vIdx) {
    Script::Script script;
    const auto& vin = tx.txIns[vIdx];
    auto forSig = Serializer::getOrigSerialization(tx);
    //std::cout << forSig << std::endl;
    script.setMsg(forSig);

    script.exec(vin.scriptSigAsm);
    return script.exec(vin.prevout.scriptpubkeyAsm);
}

bool do_p2sh(const Tx::Tx& tx, unsigned int vIdx) {
    Script::Script script;
    const auto& vin = tx.txIns[vIdx];
    auto forSig = Serializer::getOrigSerialization(tx);
    script.setMsg(forSig);

    script.exec(vin.scriptSigAsm);
    script.exec(vin.prevout.scriptpubkeyAsm);
    script.clearStack();

    std::string ops {};

    if (!vin.witness.empty()) {
        forSig = Serializer::getBIP143Serialization(tx, vIdx);
        script.setMsg(forSig);

        // manually push everything in the witness field to stack
        for (const std::string &wfe : vin.witness)
            script.getStack().push(wfe);

        const std::string& scriptPubKey = vin.scriptSig;
        const auto& pubKeyHash = scriptPubKey.substr(6);

        ops = "OP_DUP OP_HASH160 OP_PUSHBYTES_20 " + pubKeyHash + " OP_EQUALVERIFY OP_CHECKSIG";

    } else {
        script.exec(vin.scriptSigAsm);
        script.getStack().pop(); // pop redeem script from stack
        ops = vin.innerScriptAsm;
    }

    return script.exec(ops);
}

bool do_p2wpkh(const Tx::Tx& tx, unsigned int vIdx) {
    Script::Script script;
    const auto& vin = tx.txIns[vIdx];
    auto forSig = Serializer::getBIP143Serialization(tx, vIdx);
    //std::cout << forSig << std::endl;
    script.setMsg(forSig);

    auto signature = vin.witness[0];
    auto pubKey = vin.witness[1];

    // Explicitly push signature and pubkey from the witness field to stack
    script.getStack().push(signature);
    script.getStack().push(pubKey);

    const auto& scriptPubKey = vin.prevout.scriptPubKey;
    const auto& pubKeyHash = scriptPubKey.substr(4);

    const std::string s = "OP_DUP OP_HASH160 OP_PUSHBYTES_20 " + pubKeyHash + " OP_EQUALVERIFY OP_CHECKSIG";
    return script.exec(s);
}

bool do_p2wsh(const Tx::Tx& tx, unsigned int vIdx) {
    Script::Script script;
    const auto& vin = tx.txIns[vIdx];
    auto forSig = Serializer::getBIP143Serialization(tx, vIdx);
    script.setMsg(forSig);

    // manually push everything in the witness field to stack
    for (const std::string& wfe : vin.witness)
        script.getStack().push(wfe);

    const auto& scriptPubKey = vin.prevout.scriptPubKey;
    const auto& redeemScriptHash = scriptPubKey.substr(4);

    const std::string s = "OP_DUP OP_SHA256 OP_PUSHBYTES_32 " + redeemScriptHash + " OP_EQUAL";
    if (script.exec(s) == false) {
        std::cout << "Failed!";
        return false;
    }

    script.clearStack();

    // manually push everything in the witness field to stack
    for (const std::string& wfe : vin.witness)
        script.getStack().push(wfe);
    script.getStack().pop(); // pop redeem script from stack

    return script.exec(vin.innerScriptAsm);
}

bool do_p2tr(const Tx::Tx& tx, unsigned int vIdx) {
    return false;
}

void verify(const std::vector<Tx::Tx>& transactions) {

    std::unordered_map<std::string, std::array<int, 2>> stats {
        {"p2pkh",     {0, 0}},
        {"p2sh",      {0, 0}},
        {"v0_p2wpkh", {0, 0}},
        {"v0_p2wsh", {0, 0}}
    };

    std::unordered_map<std::string, std::function<bool(const Tx::Tx&, int)>> funcs {
        {"p2pkh", do_p2pkh},
        {"p2sh", do_p2sh},
        {"v0_p2wpkh", do_p2wpkh},
        {"v0_p2wsh", do_p2wsh},
        {"v1_p2tr", do_p2tr}
    };

    for (const auto& tx : transactions) {
        for (unsigned int i = 0; i < tx.txIns.size(); i++) {
            const auto& vin = tx.txIns[i];
            const auto& type = vin.prevout.scriptpubkeyType;

            bool ok = funcs[type](tx, i);
            if (!ok) {
                std::cout << "Script verification failed!" << std::endl;
                stats[type][1]++;
                break;
            } else
                stats[type][0]++;
        }
    }

    // Print stats
    for (auto& [e, v] : stats)
        std::cout << "Type: " << e << " Passed: " << v[0] << " Failed: " << v[1] << std::endl; 
}
}