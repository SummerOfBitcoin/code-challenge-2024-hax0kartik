#ifndef CRYPTO_H
#define CRYPTO_H

#include <vector>
#include <string>

namespace Crypto {

std::vector<uint8_t> getSHA256(const std::vector<uint8_t>& bytes);
std::vector<uint8_t> getRIPEMD160(const std::vector<uint8_t>& bytes);
bool verifyECDSA(const std::string& pubKey, const std::string& signature, const std::string& msg);

}

#endif // CRYPTO_H