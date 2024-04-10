#pragma once
#include "tx.h"
#include <list>
#include <vector>

namespace TxVerifier {

void verify(std::vector<Tx::Tx>& transactions, std::list<Tx::Tx>& verifiedTx);

};
