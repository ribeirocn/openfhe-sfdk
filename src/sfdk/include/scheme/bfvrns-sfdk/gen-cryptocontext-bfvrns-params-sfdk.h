//==================================================================================

//
// Author Carlos Ribeiro
//
//==================================================================================

/*
  Parameter class to generate BFVRNS crypto context
 */

#ifndef __GEN_CRYPTOCONTEXT_BFVRNS_PARAMS_SFDK_H__
#define __GEN_CRYPTOCONTEXT_BFVRNS_PARAMS_SFDK_H__

#include "scheme/gen-cryptocontext-params-sfdk.h"

#include <string>
#include <vector>

namespace lbcrypto {

class CryptoContextBFVRNSSFDK;

// every CCParams class should include the following forward declaration as there is
// no general CCParams class template. This way we may create scheme specific classes
// derived from Params or have them completely independent.
template <typename T>
class CCParams;
//====================================================================================================================
template <>
class CCParams<CryptoContextBFVRNSSFDK> : public ParamsSFDK {
public:
    CCParams() : ParamsSFDK() {}
    explicit CCParams(const std::vector<std::string>& vals) : ParamsSFDK(vals) {}
    CCParams(const CCParams& obj) = default;
    CCParams(CCParams&& obj)      = default;

    //================================================================================================================
    // DISABLE FUNCTIONS that are not applicable to BFVRNS
    //================================================================================================================
    void SetScalingTechnique(ScalingTechnique scalTech0) override {
        DISABLED_FOR_BFVRNS;
    }
    void SetFirstModSize(uint32_t firstModSize0) override {
        DISABLED_FOR_BFVRNS;
    }
    void SetPRENumHops(uint32_t PRENumHops0) override {
        DISABLED_FOR_BFVRNS;
    }
    void SetExecutionMode(ExecutionMode executionMode0) override {
        DISABLED_FOR_BGVRNS;
    }
    void SetDecryptionNoiseMode(DecryptionNoiseMode decryptionNoiseMode0) override {
        DISABLED_FOR_BFVRNS;
    }
    void SetNoiseEstimate(double noiseEstimate0) override {
        DISABLED_FOR_BFVRNS;
    }
    void SetDesiredPrecision(double desiredPrecision0) override {
        DISABLED_FOR_BFVRNS;
    }
    void SetStatisticalSecurity(uint32_t statisticalSecurity0) override {
        DISABLED_FOR_BFVRNS;
    }
    void SetNumAdversarialQueries(uint32_t numAdversarialQueries0) override {
        DISABLED_FOR_BFVRNS;
    }
    void SetInteractiveBootCompressionLevel(COMPRESSION_LEVEL interactiveBootCompressionLevel0) override {
        DISABLED_FOR_BFVRNS;
    }
};
//====================================================================================================================

}  // namespace lbcrypto

#endif  // __GEN_CRYPTOCONTEXT_BFVRNS_PARAMS_SFDK_H__
