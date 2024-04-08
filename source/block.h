#pragma once
#include <string>

struct Block {
    int version {};
    std::string prevBlkHash {};
    std::string merkleRoot {};
    uint32_t time {};
    uint32_t bits {};
    uint32_t nonce {};

    static constexpr auto calcBits(const std::string& target) {
        auto f = target.find_first_not_of("0");
        f = f & 1 ? f - 1: f;
        uint32_t exponent = (target.size() - f) / 2;
    
        auto atob = [](char a, char b){
            a = (a <= '9') ? a - '0' : (a & 0x7) + 9;
            b = (b <= '9') ? b - '0' : (b & 0x7) + 9;

            return (a << 4) + b;
        };

        auto byte = atob(target[f], target[f+1]);

        if (byte > 0x7f) {
            exponent += 1;
            f -= 2;
        }

        for (int i = 0; i < 3; i++) {
            exponent <<= 8;
            exponent += atob(target[f + i], target[f+ i + 1]);
        }

        return exponent;
    }
};
