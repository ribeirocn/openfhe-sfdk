//==================================================================================
// This file is part of the SFDK library.
//
// Author : Carlos Ribeiro
//


/*
 * API to generate BFVRNSSFDK crypto context
 */

#ifndef __GEN_CRYPTOCONTEXT_BFVRNS_SFDK_H__
#define __GEN_CRYPTOCONTEXT_BFVRNS_SFDK_H__

#include "scheme/bfvrns-sfdk/gen-cryptocontext-bfvrns-internal-sfdk.h"
#include "scheme/bfvrns-sfdk/gen-cryptocontext-bfvrns-params-sfdk.h"
#include "scheme/bfvrns-sfdk/bfvrns-scheme-sfdk.h"
#include "scheme/bfvrns-sfdk/bfvrns-cryptoparameters-sfdk.h"
#include "scheme/gen-cryptocontext-params-sfdk.h"
#include "cryptocontext-fwd-sfdk.h"
#include "lattice/lat-hal.h"

namespace lbcrypto {

template <typename Element>
class CryptoContextFactorySFDK;

class CryptoContextBFVRNSSFDK : CryptoContext<DCRTPoly> {
    using Element = DCRTPoly;

public:
    using ContextType               = CryptoContextSFDK<DCRTPoly>;  // required by GenCryptoContext() in gen-cryptocontext.h
    using Factory                   = CryptoContextFactorySFDK<DCRTPoly>;
    using PublicKeyEncryptionScheme = SchemeBFVRNSSFDK;
    using CryptoParams              = CryptoParametersBFVRNSSFDK;

    static CryptoContextSFDK<Element> genCryptoContext(const CCParams<CryptoContextBFVRNSSFDK>& parameters) {
        validateParametersForCryptocontext(parameters);
        return genCryptoContextBFVRNSSFDKInternal<CryptoContextBFVRNSSFDK, Element>(parameters);
    }
};

}  // namespace lbcrypto

#endif  // __GEN_CRYPTOCONTEXT_BFVRNS_SFDK_H__
