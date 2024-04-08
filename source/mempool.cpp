#include <filesystem>
#include <fstream>
#include "mempool.h"
#include "source/tx.h"

void Mempool::initFromFolder(const std::string& path) {
    for (const auto& entry : std::filesystem::directory_iterator(path))
        filenames.push_back(entry.path().string());

    for (auto &e : filenames) {
        std::ifstream f(e);
        json data = json::parse(f);
        transactions.emplace_back(data);
    }
}

void Mempool::addFile(const std::string& filepath) {
    filenames.push_back(filepath);

    std::ifstream f(filepath);
    json data = json::parse(f);

    transactions.emplace_back(data);
}
