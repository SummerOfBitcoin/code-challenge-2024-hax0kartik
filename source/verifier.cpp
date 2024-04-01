#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>
#include "crypto.h"
#include "script.h"
#include "serializer.h"

using json = nlohmann::json;

int main() {
    /* first, lets get all files in the mempool */

    std::vector<std::string> files { "../mempool/0a8b21af1cfcc26774df1f513a72cd362a14f5a598ec39d915323078efb5a240.json" };

    /*
    constexpr auto& path = "../mempool/";
    for (const auto& entry : std::filesystem::directory_iterator(path)) {
        files.push_back(entry.path().string());
    }*/

    for (auto &e : files) {
        std::ifstream f(e);
        json data = json::parse(f);

        auto raw = Serializer::genRawFromJson(data);
        std::cout << raw << std::endl;

        auto rawAsBytes = Serializer::getAsVector(raw);
        std::vector<uint8_t> txid = Crypto::getSHA256(Crypto::getSHA256(rawAsBytes));
        std::reverse(txid.begin(), txid.end());

        std::vector<uint8_t> txid_hash = Crypto::getSHA256(txid);

        auto forSig = Serializer::getForVerificationFromJson(data);
        std::cout << forSig << std::endl;
        
        for (const auto& vin : data["vin"]) {
            Script::Script script(forSig);
            std::string type = vin["prevout"]["scriptpubkey_type"];
            if (type == "p2pkh") {
                script.exec(vin["scriptsig_asm"]);
                if (script.exec(vin["prevout"]["scriptpubkey_asm"]) == false) {
                    std::cout << "Script verification failed!" << std::endl;
                }
            }

            script.printStack();
        }
    }

    return 0;
}