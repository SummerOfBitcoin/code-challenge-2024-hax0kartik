#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <set>
#include <functional>
#include <unordered_map>
#include <vector>
#include <nlohmann/json.hpp>
#include "crypto.h"
#include "script.h"
#include "serializer.h"
#include "util.h"
#include "tx.h"

using json = nlohmann::json;

bool do_p2pkh(const Tx::Tx tx, unsigned int vIdx) {
    Script::Script script;
    const auto& vin = tx.txIns[vIdx];
    auto forSig = Serializer::getOrigSerialization(tx);
    //std::cout << forSig << std::endl;
    script.setMsg(forSig);

    script.exec(vin.scriptSigAsm);
    return script.exec(vin.prevout.scriptpubkeyAsm);
}

bool do_p2sh(const Tx::Tx tx, unsigned int vIdx) {
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
        //std::cout << forSig << std::endl;
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

bool do_p2wpkh(const Tx::Tx tx, unsigned int vIdx) {
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

bool do_p2wsh(const Tx::Tx tx, unsigned int vIdx) {
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

bool do_p2tr(const Tx::Tx tx, unsigned int vIdx) {
    return false;
}

int main() {
    /* first, lets get all files in the mempool */

    //std::vector<std::string> files { "../mempool/0a8b21af1cfcc26774df1f513a72cd362a14f5a598ec39d915323078efb5a240.json" }; // p2pkh
    //std::vector<std::string> files { "../mempool/0af55b69fab549b98d1f7ec5100b738dad4b520384b3b8f9ff38b25ad1e2940a.json" }; // p2wpkh
    //std::vector<std::string> files { "../mempool/7372f6ac893159b976571ab2af6fb32236361e33d1f0d4b93e89d1206242a8d0.json" }; // p2sh
    //std::vector<std::string> files { "../mempool/0c7ad20fb3f17c1406f5cdb13ced233db492a4dac76908477ab3e3d48b0116ce.json" }; // p2wsh
    //std::vector<std::string> files { "../mempool/0e6535a4e5d8f1ee0507afb9adebaadab9e7c306f6db80fda4fe497ce64ade95.json" }; // p2wsh

    std::vector<std::string> files {};
    constexpr auto& path = "../mempool/";
    for (const auto& entry : std::filesystem::directory_iterator(path)) {
        files.push_back(entry.path().string());
    }

    std::unordered_map<std::string, std::array<int, 2>> stats {
        {"p2pkh",     {0, 0}},
        {"p2sh",      {0, 0}},
        {"v0_p2wpkh", {0, 0}},
        {"v0_p2wsh", {0, 0}}
    };

    std::unordered_map<std::string, std::function<bool(const Tx::Tx& , int)>> funcs {
        {"p2pkh", do_p2pkh},
        {"p2sh", do_p2sh},
        {"v0_p2wpkh", do_p2wpkh},
        {"v0_p2wsh", do_p2wsh},
        {"v1_p2tr", do_p2tr}
    };

    std::set<std::string> types = {};

    for (auto &e : files) {
        std::ifstream f(e);
        json data = json::parse(f);

        std::cout << "File: " << e << std::endl;
        auto t = data.template get<Tx::Tx>();

        auto raw = Serializer::genRaw(t);
        //std::cout << raw << std::endl;

        auto rawAsBytes = Util::getAsVector(raw);
        std::vector<uint8_t> txid = Crypto::getSHA256(Crypto::getSHA256(rawAsBytes));
        std::reverse(txid.begin(), txid.end());

        std::string txid_hash = Crypto::getSHA256<std::string>(txid);

        for (unsigned int i = 0; i < t.txIns.size(); i++) {
            const auto& vin = t.txIns[i];
            Script::Script script;
            std::string type = vin.prevout.scriptpubkeyType;

            types.insert(type);

            bool ok = funcs[type](t, i);
            if (!ok) {
                std::cout << "Script verification failed!" << std::endl;
                stats[type][1]++;
                break;
            } else
                stats[type][0]++;
        }
    }

    for (auto& e : types)
        std::cout << "Type: " << e << std::endl;

    // Print stats
    for (auto& [e, v] : stats)
        std::cout << "Type: " << e << " Passed: " << v[0] << " Failed: " << v[1] << std::endl; 

    return 0;
}