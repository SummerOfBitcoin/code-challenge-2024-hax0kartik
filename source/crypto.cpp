#include "crypto.h"
#include <cstdint>
#include <vector>
#include <format>
#include <iostream>
#include <string>
#include <cstdlib>
#include <secp256k1.h>
#include "source/Hash/src/ripemd_160.h"
#include "util.h"
#include "Hash/src/sha2_256.h"
#include "Hash/src/ripemd_160.h"

namespace Crypto {

template <>
std::string getSHA256(const std::vector<uint8_t>& bytes) {
    return Chocobo1::SHA2_256().addData(bytes).finalize().toString();
}

template <>
std::vector<uint8_t> getSHA256(const std::vector<uint8_t>& bytes) {
    return Chocobo1::SHA2_256().addData(bytes).finalize().toVector();
}

template <>
std::string getRIPEMD160(const std::vector<uint8_t>& bytes) {
    return Chocobo1::RIPEMD_160().addData(bytes).finalize().toString();
}

template <>
std::vector<uint8_t> getRIPEMD160(const std::vector<uint8_t>& bytes) {
    return Chocobo1::RIPEMD_160().addData(bytes).finalize().toVector();
}

/** This function is taken from the libsecp256k1 distribution and implements
 *  DER parsing for ECDSA signatures, while supporting an arbitrary subset of
 *  format violations.
 *
 *  Supported violations include negative integers, excessive padding, garbage
 *  at the end, and overly long length descriptors. This is safe to use in
 *  Bitcoin because since the activation of BIP66, signatures are verified to be
 *  strict DER before being passed to this module, and we know it supports all
 *  violations present in the blockchain before that point.
 */
static int ecdsa_signature_parse_der_lax(const secp256k1_context* ctx, secp256k1_ecdsa_signature* sig, const unsigned char *input, size_t inputlen) {
    size_t rpos, rlen, spos, slen;
    size_t pos = 0;
    size_t lenbyte;
    unsigned char tmpsig[64] = {0};
    int overflow = 0;

    /* Hack to initialize sig with a correctly-parsed but invalid signature. */
    secp256k1_ecdsa_signature_parse_compact(ctx, sig, tmpsig);

    /* Sequence tag byte */
    if (pos == inputlen || input[pos] != 0x30) {
        return 0;
    }
    pos++;

    /* Sequence length bytes */
    if (pos == inputlen) {
        return 0;
    }
    lenbyte = input[pos++];
    if (lenbyte & 0x80) {
        lenbyte -= 0x80;
        if (pos + lenbyte > inputlen) {
            return 0;
        }
        pos += lenbyte;
    }

    /* Integer tag byte for R */
    if (pos == inputlen || input[pos] != 0x02) {
        return 0;
    }
    pos++;

    /* Integer length for R */
    if (pos == inputlen) {
        return 0;
    }
    lenbyte = input[pos++];
    if (lenbyte & 0x80) {
        lenbyte -= 0x80;
        if (pos + lenbyte > inputlen) {
            return 0;
        }
        while (lenbyte > 0 && input[pos] == 0) {
            pos++;
            lenbyte--;
        }
        if (lenbyte >= sizeof(size_t)) {
            return 0;
        }
        rlen = 0;
        while (lenbyte > 0) {
            rlen = (rlen << 8) + input[pos];
            pos++;
            lenbyte--;
        }
    } else {
        rlen = lenbyte;
    }
    if (rlen > inputlen - pos) {
        return 0;
    }
    rpos = pos;
    pos += rlen;

    /* Integer tag byte for S */
    if (pos == inputlen || input[pos] != 0x02) {
        return 0;
    }
    pos++;

    /* Integer length for S */
    if (pos == inputlen) {
        return 0;
    }
    lenbyte = input[pos++];
    if (lenbyte & 0x80) {
        lenbyte -= 0x80;
        if (pos + lenbyte > inputlen) {
            return 0;
        }
        while (lenbyte > 0 && input[pos] == 0) {
            pos++;
            lenbyte--;
        }
        if (lenbyte >= sizeof(size_t)) {
            return 0;
        }
        slen = 0;
        while (lenbyte > 0) {
            slen = (slen << 8) + input[pos];
            pos++;
            lenbyte--;
        }
    } else {
        slen = lenbyte;
    }
    if (slen > inputlen - pos) {
        return 0;
    }
    spos = pos;

    /* Ignore leading zeroes in R */
    while (rlen > 0 && input[rpos] == 0) {
        rlen--;
        rpos++;
    }
    /* Copy R value */
    if (rlen > 32) {
        overflow = 1;
    } else {
        std::memcpy(tmpsig + 32 - rlen, input + rpos, rlen);
    }

    /* Ignore leading zeroes in S */
    while (slen > 0 && input[spos] == 0) {
        slen--;
        spos++;
    }
    /* Copy S value */
    if (slen > 32) {
        overflow = 1;
    } else {
        std::memcpy(tmpsig + 64 - slen, input + spos, slen);
    }

    if (!overflow) {
        overflow = !secp256k1_ecdsa_signature_parse_compact(ctx, sig, tmpsig);
    }
    if (overflow) {
        /* Overwrite the result again with a correctly-parsed but invalid
           signature if parsing failed. */
        std::memset(tmpsig, 0, 64);
        secp256k1_ecdsa_signature_parse_compact(ctx, sig, tmpsig);
    }
    return 1;
}

bool verifyECDSA(const std::string& pubKey, const std::string& signature, const std::string& msg) {
    const std::vector<uint8_t> pubKeyAsBytes = Util::getAsVector(pubKey);
    const std::vector<uint8_t> signatureAsBytes = Util::getAsVector(signature);
    const std::vector<uint8_t> msgAsBytes = Util::getAsVector(msg);

    const std::vector<uint8_t> digest = getSHA256(getSHA256(msgAsBytes));

    secp256k1_pubkey secp256k1PubKey;
    secp256k1_ecdsa_signature secp256k1Signature;

    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);

    if (!secp256k1_ec_pubkey_parse(ctx, &secp256k1PubKey, pubKeyAsBytes.data(), pubKeyAsBytes.size())) {
        std::cout << "Failed parsing the public key\n";
        return false;
    }

    if (!ecdsa_signature_parse_der_lax(ctx, &secp256k1Signature, signatureAsBytes.data(), signatureAsBytes.size())) {
        std::cout << "Failed parsing the signature\n";
        return false;
    }
    
    bool res = secp256k1_ecdsa_verify(ctx, &secp256k1Signature, digest.data(), &secp256k1PubKey) == 1;

    secp256k1_context_destroy(ctx);

    return res;
}

}