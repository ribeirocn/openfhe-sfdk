//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2022, NJIT, Duality Technologies Inc. and other
// contributors
//
// All rights reserved.
//
// Author TPOC: contact@openfhe.org
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
// this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//==================================================================================

#ifndef LBCRYPTO_CRYPTO_BFVRNS_SFDK_SCHEME_H
#define LBCRYPTO_CRYPTO_BFVRNS_SFDK_SCHEME_H

#include "scheme/bfvrns-sfdk/bfvrns-cryptoparameters-sfdk.h"
#include "pke/scheme/bfvrns/bfvrns-parametergeneration.h"
#include "scheme/bfvrns-sfdk/bfvrns-sfdk.h"

#include <string>
#include <memory>

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

#define SFDK 0x100



class SchemeBFVRNSSFDK : public SchemeBFVRNS {
 public:
  SchemeBFVRNSSFDK() {
    this->m_ParamsGen = std::make_shared<ParameterGenerationBFVRNS>();
    //this->m_SFDKBase =
    //    std::make_shared<SFDKBFVRNS>();
  }

  virtual ~SchemeBFVRNSSFDK() {}

  bool operator==(const SchemeBase<DCRTPoly> &sch) const override {
    return dynamic_cast<const SchemeBFVRNSSFDK *>(&sch) != nullptr;
  }

  

  /**
   * Enable features with a bit mast of PKESchemeFeature codes
   * @param mask
   */
  void EnableSFDK() {
    if (this->m_SFDKBase == nullptr) {
      this->m_SFDKBase =
        std::make_shared<SFDKBFVRNS>();
    }
  }


  uint32_t GetEnabled() const {
    uint32_t flag = 0;
    if (m_PKE != nullptr) flag |= PKE;
    if (m_KeySwitch != nullptr) flag |= KEYSWITCH;
    if (m_LeveledSHE != nullptr) flag |= LEVELEDSHE;
    if (m_AdvancedSHE != nullptr) flag |= ADVANCEDSHE;
    if (m_PRE != nullptr) flag |= PRE;
    if (m_Multiparty != nullptr) flag |= MULTIPARTY;
    if (m_FHE != nullptr) flag |= FHE;
    if (m_SchemeSwitch != nullptr) flag |= SCHEMESWITCH;
    if (m_SFDKBase != nullptr) flag |= SFDK;
    return flag;
  }

  bool IsFeatureEnabled(PKESchemeFeature feature) {
    switch (feature) {
      case PKE:
        if (m_PKE != nullptr) return true;
        break;
      case KEYSWITCH:
        if (m_KeySwitch != nullptr) return true;
        break;
      case LEVELEDSHE:
        if (m_LeveledSHE != nullptr) return true;
        break;
      case ADVANCEDSHE:
        if (m_AdvancedSHE != nullptr) return true;
        break;
      case PRE:
        if (m_PRE != nullptr) return true;
        break;
      case MULTIPARTY:
        if (m_Multiparty != nullptr) return true;
        break;
      case FHE:
        if (m_FHE != nullptr) return true;
        break;
      case SCHEMESWITCH:
        if (m_SchemeSwitch != nullptr) return true;
        break;
      default:
        OPENFHE_THROW("Unknown PKESchemeFeature " + std::to_string(feature));
        break;
    }
    return false;
  }

  inline void VerifySFDKEnabled(const std::string &functionName) const {
    if (m_SFDKBase == nullptr) {
      std::string errMsg = std::string(functionName) +
                           " operation has not been enabled. Enable(SFDK) must "
                           "be called to enable it.";
      OPENFHE_THROW(errMsg);
    }
  }

  /////////////////////////////////////////
  // SFDK WRAPPER
  /////////////////////////////////////////
  using SchemeBase::KeyGen;

  virtual KeyPairSFDK<DCRTPoly> KeyGen(CryptoContextSFDK<DCRTPoly> cc,
                                      bool makeSparse) const {
    VerifySFDKEnabled(__func__);
    return m_SFDKBase->KeyGenInternal(cc, makeSparse);
  }

  virtual KeyCipher<DCRTPoly> GenDecKeyFor(
      Ciphertext<DCRTPoly> &cipherText, KeyCipherGenKey<DCRTPoly> keyGen,
      PublicKeySFDK<DCRTPoly> publicKey) const {
    VerifySFDKEnabled(__func__);
    if (!publicKey) OPENFHE_THROW("Input public key is nullptr");
    if (!keyGen) OPENFHE_THROW("Input generation key is nullptr");
    return m_SFDKBase->GenDecKeyFor(cipherText, keyGen, publicKey);
  }

  using SchemeBase::Encrypt;
  virtual Ciphertext<DCRTPoly> Encrypt(
      const DCRTPoly &plaintext, const PublicKeySFDK<DCRTPoly> publicKey) const {
    VerifySFDKEnabled(__func__);
    //      if (!plaintext)
    //        OPENFHE_THROW( "Input plaintext is nullptr");
    if (!publicKey) OPENFHE_THROW("Input public key is nullptr");

    return m_SFDKBase->Encrypt(plaintext, publicKey);
  }
  using SchemeBase::Decrypt;
  virtual DecryptResult Decrypt(Ciphertext<DCRTPoly> &ciphertext,
                                KeyCipher<DCRTPoly> &decKey,
                                PublicKeySFDK<DCRTPoly> publicKey,
                                Plaintext *plaintext) const {
    VerifySFDKEnabled(__func__);
    if (!ciphertext) OPENFHE_THROW("Input ciphertext is nullptr");
    if (!publicKey) OPENFHE_THROW("Input public key is nullptr");
    if (!decKey) OPENFHE_THROW("Input decryption key is nullptr");
    return m_SFDKBase->Decrypt(ciphertext, decKey, publicKey, plaintext);
  }

  virtual Ciphertext<DCRTPoly> PrivateSetMembership(
      const Ciphertext<DCRTPoly> &ciphertext, const std::vector<int64_t> &testset,
      CryptoContextImplSFDK<DCRTPoly> *cryptoContext)  {
    VerifySFDKEnabled(__func__);
    if (!ciphertext) OPENFHE_THROW("Input ciphertext is nullptr");

    return m_SFDKBase->PrivateSetMembership(ciphertext, testset, cryptoContext);
  }

  virtual Ciphertext<DCRTPoly> PrivateSetMembership(
      const Ciphertext<DCRTPoly> &ciphertext, uint start, uint size,
      CryptoContextImplSFDK<DCRTPoly> *cryptoContext)  {
    VerifySFDKEnabled(__func__);
    if (!ciphertext) OPENFHE_THROW("Input ciphertext is nullptr");

    return m_SFDKBase->PrivateSetMembership(ciphertext, start, size,
                                            cryptoContext);
  }

  virtual void PreparePSM(PrivateKey<DCRTPoly> secretKey, uint maxsize,
                          CryptoContextImplSFDK<DCRTPoly> *cryptoContext) {
    VerifySFDKEnabled(__func__);
    if (!secretKey) OPENFHE_THROW("Input private key is nullptr");
    return m_SFDKBase->PreparePSM(secretKey, maxsize, cryptoContext);
  }

  virtual Ciphertext<DCRTPoly> GetZeroSpongeEncryption(
      const PrivateKey<DCRTPoly> privateKey,
      const PublicKeySFDK<DCRTPoly> publicKey, Ciphertext<DCRTPoly> ciphertext,
      usint &scale, bool isNotZero = false) const {
    VerifySFDKEnabled(__func__);
    if (!ciphertext) OPENFHE_THROW("Input ciphertext is nullptr");
    if (!publicKey) OPENFHE_THROW("Input public key is nullptr");
    if (!privateKey) OPENFHE_THROW("Input decryption key is nullptr");
    return m_SFDKBase->GetZeroSpongeEncryption(privateKey, publicKey,
                                               ciphertext, scale, isNotZero);
  }

  virtual Ciphertext<DCRTPoly> ScaleByBits(ConstCiphertext<DCRTPoly> ciphertext,
                                          usint bits) const {
    VerifySFDKEnabled(__func__);
    if (!ciphertext) OPENFHE_THROW("Input ciphertext is nullptr");
    return m_SFDKBase->ScaleByBits(ciphertext, bits);
  }

  virtual DCRTPoly GetDecryptionError(const PrivateKey<DCRTPoly> privateKey,
                             Ciphertext<DCRTPoly> &ciphertext,
                             Plaintext plaintext = NULL) const {
    VerifySFDKEnabled(__func__);
    if (!ciphertext) OPENFHE_THROW("Input ciphertext is nullptr");
    if (!privateKey) OPENFHE_THROW("Input decryption key is nullptr");
    return m_SFDKBase->GetDecryptionError(privateKey, ciphertext, plaintext);
  }

  friend std::ostream &operator<<(std::ostream &out,
                                  const SchemeBFVRNSSFDK &s) {
    out << typeid(s).name() << ":";
    bool isParamsGenNull = (s.m_ParamsGen == 0);
    bool isPKENull = (s.m_PKE == 0);
    bool isKeySwitchNull = (s.m_KeySwitch == 0);
    bool isPRENull = (s.m_PRE == 0);
    bool isLeveledSHENull = (s.m_LeveledSHE == 0);

    out << " ParamsGen " << (isParamsGenNull ? "none" : typeid(s.m_ParamsGen).name());
    out << ", PKE " << (isPKENull ? "none" : typeid(s.m_PKE).name());
    out << ", KeySwitch " << (isKeySwitchNull ? "none" : typeid(s.m_KeySwitch).name());
    out << ", PRE " << (isPRENull ? "none" : typeid(s.m_PRE).name());
    out << ", LeveledSHE " << (isLeveledSHENull ? "none" : typeid(s.m_LeveledSHE).name());
    out << ", AdvancedSHE "
        << (s.m_AdvancedSHE == 0 ? "none" : typeid(s.m_AdvancedSHE).name());
    out << ", Multiparty "
        << (s.m_Multiparty == 0 ? "none" : typeid(s.m_Multiparty).name());
    out << ", FHE " << (s.m_FHE == 0 ? "none" : typeid(s.m_FHE).name());
    out << ", SchemeSwitch "
        << (s.m_SchemeSwitch == 0 ? "none" : typeid(s.m_SchemeSwitch).name());
    out << ", SFDK "
        << (s.m_SFDKBase == 0 ? "none" : typeid(s.m_SFDKBase).name());

    return out;
  }

  /////////////////////////////////////
  // SERIALIZATION
  /////////////////////////////////////

  template <class Archive>
  void save(Archive &ar, std::uint32_t const version) const {
    ar(cereal::base_class<SchemeRNS>(this));
  }

  template <class Archive>
  void load(Archive &ar, std::uint32_t const version) {
    ar(cereal::base_class<SchemeRNS>(this));
  }

  std::string SerializedObjectName() const override {
    return "SchemeBFVRNSSFDK";
  }

 protected:
  std::shared_ptr<SFDKBFVRNS> m_SFDKBase;
};
}  // namespace lbcrypto

#endif
