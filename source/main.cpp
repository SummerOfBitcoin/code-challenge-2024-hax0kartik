#include <bit>
#include <cstdint>
#include <ctime>
#include <format>
#include <fstream>
#include <iostream>
#include <limits>
#include <string>
#include <vector>
#include "mempool.h"
#include "source/serializer.h"
#include "source/tx.h"
#include "source/util.h"
#include "verifier.h"
#include "block.h"
#include "crypto.h"

int main() {
    /* first, lets get all files in the mempool */

    //auto file {  }; // p2pkh
    //auto file { "../mempool/0af55b69fab549b98d1f7ec5100b738dad4b520384b3b8f9ff38b25ad1e2940a.json" }; // p2wpkh
    //auto file { "../mempool/7372f6ac893159b976571ab2af6fb32236361e33d1f0d4b93e89d1206242a8d0.json" }; // p2sh
    //auto file { "../mempool/0c7ad20fb3f17c1406f5cdb13ced233db492a4dac76908477ab3e3d48b0116ce.json" }; // p2wsh
    //auto file { "../mempool/0e6535a4e5d8f1ee0507afb9adebaadab9e7c306f6db80fda4fe497ce64ade95.json" }; // p2wsh

    Mempool mempool;

    mempool.initFromFolder("../mempool");

    std::list<Tx::Tx> verified;
    TxVerifier::verify(mempool.getTransactions(), verified);

    verified.sort([](const Tx::Tx& tx1, const Tx::Tx& tx2){
        return tx1.fees/tx1.weight > tx2.fees/tx2.weight; // sort in descending order
    });

    uint64_t fee = 0, weight = 0;
    std::list<Tx::Tx> verified2;
    for (auto it = verified.begin(); it != verified.end(); it++) {
        auto& t = *it;
        //std::cout << t.txidHash << " Fee: " << t.fees << std::endl;
        if (weight + t.weight + 1000 > 4000000) { // keep a dfference of 1000 from max
            //std::cout << "Max free reached! " << fee << "Total weight: " << weight << "\n";
            continue;
        }

        fee += t.fees;
        weight += t.weight;
        verified2.push_back(std::move(t));
    }

    std::cout << "Total verified tx: " << verified2.size() << " Total fee: " << fee << " Total weight: " << weight << std::endl;

    /* Coinbase transaction generaton */
    static constexpr auto zeroes = "0000000000000000000000000000000000000000000000000000000000000000";
    Tx::TxIn txInForCoinbase {};
    txInForCoinbase.isCoinbase = true;
    txInForCoinbase.txId = zeroes;
    txInForCoinbase.vout = std::numeric_limits<uint32_t>().max();
    txInForCoinbase.witness.push_back(zeroes); // witness reserved value
    txInForCoinbase.scriptSig = "0164";

    Tx::TxOut txOutForCoinbase1 {};
    txOutForCoinbase1.value = fee;
    txOutForCoinbase1.scriptPubKey = "6a";

    std::vector<std::vector<uint8_t>> wTxids {};
    wTxids.push_back(Util::getAsVector(zeroes));
    for (const auto& tx : verified2)
        wTxids.push_back(tx.wTxid);

    std::vector<std::vector<uint8_t>> txids {};
    txids.push_back(Util::getAsVector(zeroes));
    for (const auto& tx : verified2)
        txids.push_back(tx.txid);

    auto witnessRootHash = Block::Block::calcMerkleRoot(wTxids);
    //std::cout << "WitnessRootHash: " << Util::getAsString(witnessRootHash);
    auto zeroesVec = Util::getAsVector(zeroes); 
    witnessRootHash.insert(witnessRootHash.end(), zeroesVec.begin(), zeroesVec.end());
    auto wTxidCommitment = Crypto::getSHA256<std::string>(Crypto::getSHA256(witnessRootHash));

    Tx::TxOut txOutForCoinbase2 {};
    txOutForCoinbase2.value = 0;
    txOutForCoinbase2.scriptPubKey = "6a24aa21a9ed" + wTxidCommitment;

    Tx::Tx coinBase {};
    coinBase.version = 1;
    coinBase.lockTime = 0;
    coinBase.txIns.push_back(txInForCoinbase);
    coinBase.txOuts.push_back(txOutForCoinbase1);
    coinBase.txOuts.push_back(txOutForCoinbase2);

    auto serCoinBase = Serializer::genRaw(coinBase, false);

    //std::cout << "Serialized coinbase: " << serCoinBase << std::endl;

    Block::Block block;
    block.version = 0x20000000;

    //target = "0000ffff00000000000000000000000000000000000000000000000000000000"

    static constexpr auto bits = 0x1f00ffff;
    block.bits = bits;
    block.prevBlkHash = zeroesVec;
    block.merkleRoot = Block::Block::calcMerkleRoot(txids);
    std::reverse(block.merkleRoot.begin(), block.merkleRoot.end());

    block.time = std::time(0);

    auto atob = [](char a, char b){
        a = (a <= '9') ? a - '0' : (a & 0x7) + 9;
        b = (b <= '9') ? b - '0' : (b & 0x7) + 9;

        return (a << 4) + b;
    };

    // we only need to compare the first 32 bits
    uint32_t target_u32 = 0x0000ffff;
    std::string finalBlock {};

    auto serBlock = Serializer::getBlockHeaderSerialization(block);
    for (uint32_t i = 0; i < std::numeric_limits<uint32_t>().max(); i++) {
        auto newserBlock = serBlock + std::format("{:08x}", std::byteswap(i));
        auto hash = Crypto::getSHA256(Crypto::getSHA256(Util::getAsVector(newserBlock)));
        std::reverse(hash.begin(), hash.end());

        auto hashAsString = Util::getAsString(hash);
        uint32_t val = atob(hashAsString[0], hashAsString[1]);
        val <<= 8;
        val += atob(hashAsString[2], hashAsString[3]);
        val <<= 8;
        val += atob(hashAsString[4], hashAsString[5]);
        val <<= 8;
        val += atob(hashAsString[6], hashAsString[7]);

        if (val < target_u32) {
            //std::cout << "Target: " << target << " Hash: " << hashAsString << " Nonce: " << i << std::endl;
            //std::cout << "Target: " << std::format("{:08x}", target_u32) << " Hash: " << std::format("{:08x}", val) << std::endl;
            //std::cout << "Successfully mined" << std::endl;
            finalBlock = newserBlock;
            break;
        }
    }

    std::ofstream f("../output.txt");
    f << finalBlock << "\n";
    f << serCoinBase << "\n";
    for (auto &e: txids)
        f << Util::getAsString(e) << "\n";

    f.close();

    return 0;
}