#include "mempool.h"
#include "verifier.h"

int main() {
    /* first, lets get all files in the mempool */

    //auto file { "../mempool/0a8b21af1cfcc26774df1f513a72cd362a14f5a598ec39d915323078efb5a240.json" }; // p2pkh
    //auto file { "../mempool/0af55b69fab549b98d1f7ec5100b738dad4b520384b3b8f9ff38b25ad1e2940a.json" }; // p2wpkh
    //auto file { "../mempool/7372f6ac893159b976571ab2af6fb32236361e33d1f0d4b93e89d1206242a8d0.json" }; // p2sh
    //auto file { "../mempool/0c7ad20fb3f17c1406f5cdb13ced233db492a4dac76908477ab3e3d48b0116ce.json" }; // p2wsh
    //auto file { "../mempool/0e6535a4e5d8f1ee0507afb9adebaadab9e7c306f6db80fda4fe497ce64ade95.json" }; // p2wsh

    Mempool mempool;
    //mempool.addFile(file);
    mempool.initFromFolder("../mempool");

    TxVerifier::verify(mempool.getTransactions());

    return 0;
}