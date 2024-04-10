#pragma once

#include "source/block.h"
#include <string>

namespace Tx {
struct Tx;
}

struct Block;

namespace Serializer {

auto genCompactInt(const auto &num);
std::string genRaw(const Tx::Tx& t, bool forceLegacy = true);
std::string getOrigSerialization(const Tx::Tx& t);
std::string getBIP143Serialization(const Tx::Tx& t, unsigned int idx);
std::string getBlockHeaderSerialization(const Block& b);
}
