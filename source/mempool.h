#pragma once
#include <memory>
#include <vector>
#include "tx.h"

class Mempool {
    public:
        Mempool() = default;
        void initFromFolder(const std::string& s);
        void addFile(const std::string& s);

        auto& getTransactions() {
            return transactions;
        }

    private:
        std::vector<std::string> filenames;
        std::vector<Tx::Tx> transactions;
};
