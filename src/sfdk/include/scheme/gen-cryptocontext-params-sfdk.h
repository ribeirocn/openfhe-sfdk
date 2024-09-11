// File: gen-cryptocontext-params_sfdk.h
// author: Carlos Ribeiro

/*
  Scheme parameter default class
  Changed to allow for trapdoor base and length
 */

#ifndef __GEN_CRYPTOCONTEXT_PARAMS_SFDK_H__
#define __GEN_CRYPTOCONTEXT_PARAMS_SFDK_H__

#include "pke/scheme/gen-cryptocontext-params.h"

namespace lbcrypto {

//====================================================================================================================
class ParamsSFDK : public Params {
    // Trapdoor base
    uint32_t m_base;
    //flag for verifying norm of trapdoor
    bool VerifyNorm;

protected:
    // How to disable a particular setter for a particular scheme and get an exception thrown if a user tries to call it:
    // 1. The set function should be declared virtual in this file
    // 2. The same function should be re-defined in the scheme-specific derived file using macros DISABLED_FOR_xxxxRNS defined below.
    //
    // Example:
    // the original setter defined in gen-cryptocontext-params.h:
    //
    // virtual void SetPlaintextModulus(PlaintextModulus ptModulus0) {
    //     ptModulus = ptModulus0;
    // }
    //
    // the setter re-defined and disabled in gen-cryptocontext-ckksrns-params.h:
    //
    // void SetPlaintextModulus(PlaintextModulus ptModulus0) override {
    //     DISABLED_FOR_CKKS;
    // }

#define DISABLED_FOR_CKKSRNS OPENFHE_THROW("This function is not available for CKKSRNS.");
#define DISABLED_FOR_BGVRNS  OPENFHE_THROW("This function is not available for BGVRNS.");
#define DISABLED_FOR_BFVRNS  OPENFHE_THROW("This function is not available for BFVRNS.");

public:
    explicit ParamsSFDK(SCHEME scheme0 = BFVRNS_SCHEME) : Params::Params(scheme0) {
        SetSDKDefaults();
    }
    ParamsSFDK(const std::vector<std::string>& vals) : Params::Params(vals) {
    }
    ParamsSFDK(const ParamsSFDK& obj) = default;
    ParamsSFDK(ParamsSFDK&& obj)      = default;

    // getters

    uint32_t GetBase() const {
        return m_base;
    }

    bool GetVerifyNorm() const {
        return VerifyNorm;
    }

    // setters
    // They all must be virtual, so any of them can be disabled in the derived class
    virtual void SetBase(uint32_t base0) {
        m_base = base0;
    }

    virtual void SetVerifyNorm(bool verifyNorm0) {
        VerifyNorm = verifyNorm0;
    }

    void SetSDKDefaults() {
        Params::SetSecretKeyDist(GAUSSIAN);
        m_base                        = 2; 
        VerifyNorm                  = false;
    }

    friend std::ostream& operator<<(std::ostream& os, const ParamsSFDK& obj);
};
// ====================================================================================================================

}  // namespace lbcrypto

#endif  // __GEN_CRYPTOCONTEXT_PARAMS_SFDK_H__
