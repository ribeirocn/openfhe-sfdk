//==================================================================================
// This file is part of the SFDK library.
// Author Carlos Ribeiro
//
//==================================================================================

/*
  API to generate BFVRNS crypto context. MUST NOT (!) be used without a wrapper function
 */

#ifndef _GEN_CRYPTOCONTEXT_BFVRNS_SFDK_INTERNAL_H_
#define _GEN_CRYPTOCONTEXT_BFVRNS_SFDK_INTERNAL_H_

#include "pke/encoding/encodingparams.h"
#include "pke/constants.h"
#include "pke/scheme/scheme-utils.h"
#include "pke/scheme/scheme-id.h"
#include "cryptocontextfactory-sfdk.h"

#include <memory>

namespace lbcrypto {

// forward declarations (don't include headers as compilation fails when you do)
template <typename T>
class CCParams;

template <typename ContextGeneratorType, typename Element>
typename ContextGeneratorType::ContextType genCryptoContextBFVRNSSFDKInternal(
    const CCParams<ContextGeneratorType>& parameters) {
    using ParmType                   = typename Element::Params;
    constexpr float assuranceMeasure = 36.0f;

    auto ep = std::make_shared<ParmType>();
    EncodingParams encodingParams(
        std::make_shared<EncodingParamsImpl>(parameters.GetPlaintextModulus(), parameters.GetBatchSize()));

    // clang-format off
    auto params = std::make_shared<typename ContextGeneratorType::CryptoParams>(
        ep,
        encodingParams,
        parameters.GetStandardDeviation(),
        assuranceMeasure,
        parameters.GetSecurityLevel(),
        parameters.GetDigitSize(),
        parameters.GetSecretKeyDist(),
        parameters.GetMaxRelinSkDeg(),
        parameters.GetKeySwitchTechnique(),
        parameters.GetScalingTechnique(),
        parameters.GetEncryptionTechnique(),
        parameters.GetMultiplicationTechnique(),
        parameters.GetPREMode(),
        parameters.GetMultipartyMode(),
        parameters.GetExecutionMode(),
        parameters.GetDecryptionNoiseMode(),
        parameters.GetPlaintextModulus(),
        parameters.GetStatisticalSecurity(),
        parameters.GetNumAdversarialQueries(),
        parameters.GetThresholdNumOfParties(),
        parameters.GetBase(),
        parameters.GetVerifyNorm());

    // for BFV scheme noise scale is always set to 1
    params->SetNoiseScale(1);

    auto scheme = std::make_shared<typename ContextGeneratorType::PublicKeyEncryptionScheme>();
    scheme->SetKeySwitchingTechnique(parameters.GetKeySwitchTechnique());
    scheme->ParamsGenBFVRNS(
        params,
        parameters.GetEvalAddCount(),
        parameters.GetMultiplicativeDepth(),
        parameters.GetKeySwitchCount(),
        parameters.GetScalingModSize(),
        parameters.GetRingDim(),
        parameters.GetNumLargeDigits());
    // clang-format on
    //std::shared_ptr<CryptoContextImpl<DCRTPoly>> cc = CryptoContextFactorySFDK<Element>::GetContext(params, scheme);
    auto cc = ContextGeneratorType::Factory::GetContext(params, scheme);
    cc->setSchemeId(SCHEME::BFVRNS_SCHEME);
    auto ccSFDK = std::dynamic_pointer_cast<CryptoContextImplSFDK<DCRTPoly>>(cc);
    return ccSFDK;
    //return dynamic_cast<std::shared_ptr<CryptoContextImplSFDK<DCRTPoly>>>(cc);
};

}  // namespace lbcrypto

#endif  // _GEN_CRYPTOCONTEXT_BFVRNS_SFDK_INTERNAL_H_
