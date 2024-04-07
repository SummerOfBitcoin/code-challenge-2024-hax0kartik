#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace Crypto {

template<typename T = std::vector<uint8_t>>
T getSHA256(const std::vector<uint8_t>& bytes);

/** OpenSSL has issues with RIPEMD160 where it is not supported in latest versions, 
 *  use this alternative lib instead.
 */
template<typename T = std::vector<uint8_t>>
T getRIPEMD160(const std::vector<uint8_t>& bytes);

bool verifyECDSA(const std::string& pubKey, const std::string& signature, const std::string& msg);

}
