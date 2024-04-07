#pragma once

#include <string>

namespace Tx {
struct Tx;
}
namespace Serializer {

auto genCompactInt(const auto &num);
std::string genRaw(const Tx::Tx& t);
std::string getOrigSerialization(const Tx::Tx& t);
std::string getBIP143Serialization(const Tx::Tx& t, unsigned int idx);

}
