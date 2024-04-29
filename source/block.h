#pragma once
#include "tx.h"
#include <list>
#include <string>
#include <vector>

namespace Block {

struct Block {
    uint32_t version {};
    std::vector<uint8_t> prevBlkHash {};
    std::vector<uint8_t> merkleRoot {};
    uint32_t time {};
    uint32_t bits {};
    uint32_t nonce {};
    static std::vector<uint8_t> calcMerkleRoot(const std::vector<std::vector<uint8_t>>& txIds);
};

}