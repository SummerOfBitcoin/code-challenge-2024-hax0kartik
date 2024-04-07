#include <format>
#include <iostream>
#include <sstream>
#include <string>
#include <utility>
#include "script.h"
#include "serializer.h"
#include "crypto.h"
#include "util.h"

namespace Script {

void Script::printStack() {
    const auto size = stack.size();
    for (unsigned int i = 0; i < size; i++) {
        std::cout << stack.top() << " ";
        stack.pop();
    }

    std::cout << std::endl;
}

bool Script::exec(const std::string& opstr) {
    std::stringstream ss(opstr);
    std::string buf;
    while (ss >> buf) {
        if (buf.find("OP_PUSHNUM") != std::string::npos) {

            constexpr int len = std::string("OP_PUSHNUM_").length();
            const auto &substr = buf.substr(len);
            stack.push(substr);

        } else if (buf.find("OP_PUSHBYTES") != std::string::npos) {
        
            /* Push data to Stack */
            std::string tmp;
            ss >> tmp;
            stack.push(std::move(tmp));
        
        } else if (buf.find("OP_PUSHDATA") != std::string::npos) {

            /* Push Data to Stack */
            std::string tmp;
            ss >> tmp;
            stack.push(std::move(tmp));

        } else if (buf == "OP_DUP") {

            /* Duplicate top element in stack */
            auto elem = stack.top();
            stack.push(std::move(elem));

        } else if (buf == "OP_SHA256") {

            /* Calculate SHA256(..) for topmost element */
            auto elem = stack.top();
            stack.pop();
            auto hash = Crypto::getSHA256<std::string>(Util::getAsVector(elem));
            stack.push(std::move(hash));
        
        } else if (buf == "OP_HASH160") {

            /* Calculate RIPEMD160(SHA256(..)) for topmost element */
            auto elem = stack.top();
            stack.pop();
            auto bytes = Crypto::getSHA256(Util::getAsVector(elem));
            std::string hexStr = Crypto::getRIPEMD160<std::string>(bytes);
            stack.push(std::move(hexStr));

        } else if (buf == "OP_EQUALVERIFY") {

            /* Verify that the topmost two string match */
            auto elem = stack.top();
            stack.pop();

            auto elem2 = stack.top();
            stack.pop();

            if (elem != elem2)
                return false; // Do not return true incase of success

        } else if (buf == "OP_EQUAL") {

            /* Verify that the topmost two string match */
            auto elem = stack.top();
            stack.pop();

            auto elem2 = stack.top();
            stack.pop();

            std::string val = (elem == elem2) ? "1" : "0";
            stack.push(std::move(val));

        } else if (buf == "OP_CHECKSIG") {

            auto pubkey = stack.top();
            stack.pop();

            auto signature = stack.top();
            stack.pop();

            bool ok = Crypto::verifyECDSA(pubkey, signature, msg);

            stack.push(ok ? "1" : "0");

        } else if (buf == "OP_CHECKSIGVERIFY") {

            auto pubkey = stack.top();
            stack.pop();

            auto signature = stack.top();
            stack.pop();

            if (!Crypto::verifyECDSA(pubkey, signature, msg))
                return false; // do nothing if the signature is valid

        } else if (buf == "OP_CHECKMULTISIG") {

            int n = std::stoul(stack.top());
            stack.pop();

            std::vector<std::string> pubKeys (n);
            for (int i = 0; i < n; i++) {
                pubKeys[i] = stack.top();
                stack.pop();
            }

            int m = std::stoul(stack.top());
            stack.pop();

            std::vector<std::string> sigs (m);
            for (int i = 0; i < m; i++) {
                sigs[i] = stack.top();
                stack.pop();
            }

            // emulate one extra pop bug
            stack.pop();

            int iKey = 0, iSig = 0;
            bool ok = true;
            while (ok && n > 0 && m > 0) {

                const auto& pubkey = pubKeys[iKey];
                const auto& signature = sigs[iSig];

                if (Crypto::verifyECDSA(pubkey, signature, msg) == true) {
                    iSig++;
                    m--;
                }

                iKey++;
                n--;

                if (m > n) {
                    ok = false;
                }
            }

            stack.push(ok ? "1" : "0");

        } else if (buf.find("OP_0") != std::string::npos) {
            stack.push("");
        } else {
            std::cout << "Unknown OpCode: " << buf << std::endl;
            return false;
        }
    }

    return stack.empty() || stack.top() == "1" ? true : false; 
}

}