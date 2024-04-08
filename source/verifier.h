#pragma once
#include "tx.h"
#include <memory>
#include <vector>

namespace TxVerifier {

void verify(std::vector<Tx::Tx>& transactions);

};
