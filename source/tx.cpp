#include "tx.h"
#include "crypto.h"
#include "serializer.h"
#include "util.h"

namespace Tx {

TxOut::TxOut(const json& j) {
    j.at("scriptpubkey").get_to(scriptPubKey);
    j.at("scriptpubkey_asm").get_to(scriptpubkeyAsm);
    j.at("scriptpubkey_type").get_to(scriptpubkeyType);
    if (j.contains("scriptpubkey_address"))
        j.at("scriptpubkey_address").get_to(scriptpubkeyAddress);
    j.at("value").get_to(value);
}

TxIn::TxIn(const json& j) {
    j.at("txid").get_to(txId);
    j.at("vout").get_to(vout);
    prevout = TxOut(j.at("prevout"));
    j.at("scriptsig").get_to(scriptSig);
    j.at("scriptsig_asm").get_to(scriptSigAsm);
    if (j.contains("witness"))
        j.at("witness").get_to(witness);
    j.at("is_coinbase").get_to(isCoinbase);
    j.at("sequence").get_to(sequence);
    if (j.contains("inner_witnessscript_asm"))
        j.at("inner_witnessscript_asm").get_to(innerScriptAsm);
    else if (j.contains("inner_redeemscript_asm"))
        j.at("inner_redeemscript_asm").get_to(innerScriptAsm);
}

Tx::Tx(const json& j) {
    j.at("version").get_to(version);
    j.at("locktime").get_to(lockTime);

    for (const auto& vin : j["vin"])
        txIns.emplace_back(vin);

    for (const auto& vout : j["vout"])
        txOuts.emplace_back(vout);

    auto raw = Serializer::genRaw(*this);
    auto rawAsBytes = Util::getAsVector(raw);
    txid = Crypto::getSHA256(Crypto::getSHA256(rawAsBytes));
    std::reverse(txid.begin(), txid.end());
    txidHash = Crypto::getSHA256<std::string>(txid);

    calcFees();
}

void Tx::calcFees() {
    int64_t vInSum = 0, vOutSum = 0;
    for (const auto& vin: txIns)
        vInSum += vin.prevout.value;

    for (const auto& vout: txOuts)
        vOutSum += vout.value;

    fees = vInSum - vOutSum;
}

}