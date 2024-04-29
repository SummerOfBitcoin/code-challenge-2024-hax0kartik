#include "block.h"
#include "source/crypto.h"
#include "source/util.h"
#include <vector>

namespace Block {

std::vector<uint8_t> Block::calcMerkleRoot(const std::vector<std::vector<uint8_t>>& txIds) {
    std::vector<std::vector<uint8_t>> level(txIds.begin(), txIds.end());
    std::vector<std::vector<uint8_t>> newlevel {};

    bool firstLevel = true;
    while (level.size() > 1) {
        for (uint i = 0; i < level.size(); i += 2) {
            uint n = i + 1 == level.size() ? i : i + 1;
            auto bytes = level[i];
            auto bytes1 = level[n];

            if (firstLevel) {
                std::reverse(bytes.begin(), bytes.end());
                std::reverse(bytes1.begin(), bytes1.end());
            }

            bytes.insert(bytes.end(), bytes1.begin(), bytes1.end());
            newlevel.push_back(Crypto::getSHA256(Crypto::getSHA256(bytes)));
        }
        firstLevel = false;
        level = std::move(newlevel);
    }

    return level[0];
}

}