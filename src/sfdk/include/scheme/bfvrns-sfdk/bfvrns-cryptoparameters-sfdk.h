//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2022, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//
// Author TPOC: contact@openfhe.org
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//==================================================================================

#ifndef LBCRYPTO_CRYPTO_BFVRNS_SFDK_CRYPTOPARAMETERS_H
#define LBCRYPTO_CRYPTO_BFVRNS_SFDK_CRYPTOPARAMETERS_H

#include "pke/scheme/bfvrns/bfvrns-cryptoparameters.h"

#include <memory>
#include <string>

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

class CryptoParametersBFVRNSSFDK : public CryptoParametersBFVRNS {
    using ParmType = typename DCRTPoly::Params;

public:
    CryptoParametersBFVRNSSFDK() : CryptoParametersBFVRNS() {}

    CryptoParametersBFVRNSSFDK(const CryptoParametersBFVRNSSFDK& rhs) : CryptoParametersBFVRNS(rhs) {}

    CryptoParametersBFVRNSSFDK(std::shared_ptr<ParmType> params, const PlaintextModulus& plaintextModulus,
                           float distributionParameter, float assuranceMeasure, SecurityLevel securityLevel,
                           usint digitSize, SecretKeyDist secretKeyDist, int maxRelinSkDeg = 2,
                           KeySwitchTechnique ksTech = BV, ScalingTechnique scalTech = FIXEDMANUAL,
                           EncryptionTechnique encTech = STANDARD, MultiplicationTechnique multTech = HPS,
                           MultipartyMode multipartyMode = FIXED_NOISE_MULTIPARTY,
                           usint base = 2, bool VerifyNormFlag = false)
        : CryptoParametersBFVRNS(params, plaintextModulus, distributionParameter, assuranceMeasure, securityLevel,
                              digitSize, secretKeyDist, maxRelinSkDeg, ksTech, scalTech, encTech, multTech,
                              multipartyMode), m_base(base), VerifyNorm(VerifyNormFlag) {}

    CryptoParametersBFVRNSSFDK(std::shared_ptr<ParmType> params, EncodingParams encodingParams, float distributionParameter,
                           float assuranceMeasure, SecurityLevel securityLevel, usint digitSize,
                           SecretKeyDist secretKeyDist, int maxRelinSkDeg = 2, KeySwitchTechnique ksTech = BV,
                           ScalingTechnique scalTech = FIXEDMANUAL, EncryptionTechnique encTech = STANDARD,
                           MultiplicationTechnique multTech = HPS, ProxyReEncryptionMode PREMode = NOT_SET,
                           MultipartyMode multipartyMode           = FIXED_NOISE_MULTIPARTY,
                           ExecutionMode executionMode             = EXEC_EVALUATION,
                           DecryptionNoiseMode decryptionNoiseMode = FIXED_NOISE_DECRYPT,
                           PlaintextModulus noiseScale = 1, uint32_t statisticalSecurity = 30,
                           uint32_t numAdversarialQueries = 1, uint32_t thresholdNumOfParties = 1,
                           usint base = 2, bool VerifyNormFlag = false)
        : CryptoParametersBFVRNS(params, encodingParams, distributionParameter, assuranceMeasure, securityLevel, digitSize,
                              secretKeyDist, maxRelinSkDeg, ksTech, scalTech, encTech, multTech, PREMode,
                              multipartyMode, executionMode, decryptionNoiseMode, noiseScale, statisticalSecurity,
                              numAdversarialQueries, thresholdNumOfParties), m_base(base), VerifyNorm(VerifyNormFlag) {}

    virtual ~CryptoParametersBFVRNSSFDK() {}

    usint GetK() const {return m_k;}
    void SetK(usint k){m_k = k;}
    usint GetBase() const {return m_base;}
    void SetBase(usint base){m_base = base;}
    typename DCRTPoly::DggType &GetDiscreteGaussianGeneratorLargeSigma() {return m_dggLargeSigma;}

    bool operator==(const CryptoParametersBase<DCRTPoly>& rhs) const override {
        const auto* el =
            dynamic_cast<const CryptoParametersBFVRNSSFDK*>(&rhs);

        if (el == nullptr) return false;

        return el->GetK() == m_k && CryptoParametersBFVRNSSFDK::operator==(rhs);
    } 
    /////////////////////////////////////
    // SERIALIZATION
    /////////////////////////////////////

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(cereal::base_class<CryptoParametersBFVRNSSFDK>(this));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            std::string errMsg("serialized object version " + std::to_string(version) +
                               " is from a later version of the library");
            OPENFHE_THROW(errMsg);
        }

        ar(cereal::base_class<CryptoParametersBFVRNSSFDK>(this));

        if (PrecomputeCRTTablesAfterDeserializaton()) {
            PrecomputeCRTTables(m_ksTechnique, m_scalTechnique, m_encTechnique, m_multTechnique, m_numPartQ, m_auxBits,
                                m_extraBits);
        }
    }

    std::string SerializedObjectName() const override {
        return "CryptoParametersBFVRNSSFDK";
    }
    static uint32_t SerializedVersion() {
        return 1;
    }

    protected:

    // Trapdoor base
    usint m_base;
    // Trapdoor length
    usint m_k;

    // Discrete Gaussian Generator for random number generation
    typename DCRTPoly::DggType m_dgg;

    // Discrete Gaussian Generator with high distribution parameter for random
    // number generation
    typename DCRTPoly::DggType m_dggLargeSigma;

    //flag for verifying norm of trapdoor
    bool VerifyNorm;
};

}  // namespace lbcrypto

#endif
