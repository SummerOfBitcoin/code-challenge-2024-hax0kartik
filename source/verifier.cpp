#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>
#include <set>

#include <nlohmann/json.hpp>
#include "crypto.h"
#include "script.h"
#include "serializer.h"
#include "util.h"

using json = nlohmann::json;

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

    std::set<std::string> types = {};

    for (auto &e : files) {
        std::ifstream f(e);
        json data = json::parse(f);

        auto raw = Serializer::genRaw(data);
        //std::cout << raw << std::endl;

        auto rawAsBytes = Util::getAsVector(raw);
        std::vector<uint8_t> txid = Crypto::getSHA256(Crypto::getSHA256(rawAsBytes));
        std::reverse(txid.begin(), txid.end());

        std::string txid_hash = Crypto::getSHA256<std::string>(txid);
        std::cout << "File: " << e << std::endl;

        for (unsigned int i = 0; i < data["vin"].size(); i++) {
            const auto& vin = data["vin"][i];
            Script::Script script;
            std::string type = vin["prevout"]["scriptpubkey_type"];

            types.insert(type);

            bool ok = false;

            if (type == "p2pkh") {
                auto forSig = Serializer::getOrigSerialization(data);
                //std::cout << forSig << std::endl;
                script.setMsg(forSig);

                script.exec(vin["scriptsig_asm"]);
                ok = script.exec(vin["prevout"]["scriptpubkey_asm"]);

            } else if (type == "p2sh") {
                auto forSig = Serializer::getOrigSerialization(data);
                script.setMsg(forSig);

                script.exec(vin["scriptsig_asm"]);
                script.exec(vin["prevout"]["scriptpubkey_asm"]);
                script.clearStack();

                std::string ops {};

                if (vin.contains("witness")) {
                    forSig = Serializer::getBIP143Serialization(data, i);
                    //std::cout << forSig << std::endl;
                    script.setMsg(forSig);

                    /* manually push everything in the witness field to stack */
                    for (const std::string wfe : vin["witness"])
                        script.getStack().push(wfe);

                    const std::string& scriptPubKey = vin["scriptsig"];
                    const auto& pubKeyHash = scriptPubKey.substr(6);

                    ops = "OP_DUP OP_HASH160 OP_PUSHBYTES_20 " + pubKeyHash + " OP_EQUALVERIFY OP_CHECKSIG";

                } else {
                    script.exec(vin["scriptsig_asm"]);
                    script.getStack().pop(); // pop redeem script from stack
                    ops = vin["inner_redeemscript_asm"];
                }

                ok = script.exec(ops);

            } else if (type == "v0_p2wpkh") {
                auto forSig = Serializer::getBIP143Serialization(data, i);
                //std::cout << forSig << std::endl;
                script.setMsg(forSig);

                auto signature = vin["witness"][0];
                auto pubKey = vin["witness"][1];

                /* Explicitly push signature and pubkey from the witness field to stack */
                script.getStack().push(signature);
                script.getStack().push(pubKey);

                const std::string& scriptPubKey = vin["prevout"]["scriptpubkey"];
                const auto& pubKeyHash = scriptPubKey.substr(4);

                const std::string s = "OP_DUP OP_HASH160 OP_PUSHBYTES_20 " + pubKeyHash + " OP_EQUALVERIFY OP_CHECKSIG";
                ok = script.exec(s);

            } else if (type == "v0_p2wsh") {
                auto forSig = Serializer::getBIP143Serialization(data, i);
                script.setMsg(forSig);

                /* manually push everything in the witness field to stack */
                for (const std::string wfe : vin["witness"])
                    script.getStack().push(wfe);

                const std::string& scriptPubKey = vin["prevout"]["scriptpubkey"];
                const auto& redeemScriptHash = scriptPubKey.substr(4);

                const std::string s = "OP_DUP OP_SHA256 OP_PUSHBYTES_32 " + redeemScriptHash + " OP_EQUAL";
                if (script.exec(s) == false) {
                    //script.printStack();
                    std::cout << "Failed!";

                    // figure out how not to execute rest of program
                }

                script.clearStack();

                /* manually push everything in the witness field to stack */
                for (const std::string wfe : vin["witness"])
                    script.getStack().push(wfe);
                script.getStack().pop(); // pop redeem script from stack

                ok = script.exec(vin["inner_witnessscript_asm"]);
            }

            if (!ok) {
                std::cout << "Script verification failed!" << std::endl;
                stats[type][1]++;
                break;
            } else
                stats[type][0]++;

        }

    }

    for (auto& e : types) {
        std::cout << "Type: " << e << std::endl;
    }

    /* Print stats */
    for (auto& [e, v] : stats) {
        std::cout << "Type: " << e << " Passed: " << v[0] << " Failed: " << v[1] << std::endl; 
    }

    return 0;
}