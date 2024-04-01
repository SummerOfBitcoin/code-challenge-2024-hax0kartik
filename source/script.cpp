#include <format>
#include <iostream>
#include <sstream>
#include "script.h"
#include "serializer.h"
#include "crypto.h"

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
        if (buf.find("OP_PUSHBYTES") != std::string::npos) {
        
            /* Push data to Stack */
            std::string tmp;
            ss >> tmp;
            stack.push(std::move(tmp));
        
        } else if (buf.find("OP_DUP") != std::string::npos) {
           
            /* Duplicate top element in stack */
            auto elem = stack.top();
            stack.push(std::move(elem));
        
        } else if (buf.find("OP_HASH160") != std::string::npos) {

            /* Calculate RIPEMD160 for topmost element */
            auto elem = stack.top();
            stack.pop();
            std::vector<uint8_t> bytes = Crypto::getRIPEMD160(Crypto::getSHA256(Serializer::getAsVector(elem)));
            std::string hexStr = Serializer::getAsString(bytes);
            stack.push(std::move(hexStr));

        } else if (buf.find("OP_EQUALVERIFY") != std::string::npos) {

            /* Verify that th topmost two string match */
            auto elem = stack.top();
            stack.pop();

            auto elem2 = stack.top();
            stack.pop();

            if (elem != elem2)
                return false;

        } else if (buf.find("OP_CHECKSIG") != std::string::npos) {

            auto pubkey = stack.top();
            stack.pop();

            auto signature = stack.top();
            stack.pop();

            if (Crypto::verifyECDSA(pubkey, signature, msg) == false)
                std::cout << "Signature verification failed!\n" << std::endl;
            else
                std::cout << "Signature verification passed!\n" << std::endl;

        } else {
            std::cout << "Unknown OpCode: " << buf << std::endl;
        }
    }

    return true;
}

}