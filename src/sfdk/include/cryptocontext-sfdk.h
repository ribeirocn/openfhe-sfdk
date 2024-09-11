//==================================================================================
// Author Carlos Ribeiro
//
//==================================================================================

/*
  Control for encryption operations
 */

#ifndef SRC_PKE_CRYPTOCONTEXT_SFDK_H_
#define SRC_PKE_CRYPTOCONTEXT_SFDK_H_

#include "pke/cryptocontext.h"
#include "key/keypair-sfdk.h"
#include "key/cipherkey-sfdk.h"
#include "cryptocontext-fwd-sfdk.h"
#include "scheme/bfvrns-sfdk/bfvrns-scheme-sfdk.h"
#include "scheme/bfvrns-sfdk/gen-cryptocontext-bfvrns-sfdk.h"


namespace lbcrypto {

/**
 * @brief CryptoContextImpl
 * 
 */
template <typename Element>
class CryptoContextImplSFDK : public CryptoContextImpl<Element>, std::enable_shared_from_this<CryptoContextImplSFDK<Element>> {
//class CryptoContextImplSFDK : public CryptoContextImpl<Element> {
    using IntType  = typename Element::Integer;
    using ParmType = typename Element::Params;


    const std::shared_ptr<SchemeBFVRNSSFDK> GetSFDKScheme() const {
        return std::dynamic_pointer_cast<SchemeBFVRNSSFDK>(this->GetScheme());
    }

    public:

    CryptoContextImplSFDK(CryptoParametersBase<Element>* params, SchemeBFVRNSSFDK* scheme,
                      SCHEME schemeId) : CryptoContextImpl<Element>(params,scheme,schemeId) {}


    CryptoContextImplSFDK(std::shared_ptr<CryptoParametersBase<Element>> params,
                      std::shared_ptr<SchemeBFVRNSSFDK> scheme, SCHEME schemeId ) : CryptoContextImpl<Element>(params,scheme,schemeId) {}

    CryptoContextImplSFDK(const CryptoContextImplSFDK<Element>& c) : CryptoContextImpl<Element>(c) {}

    
    const CryptoContextSFDK<Element> GetContextForPointer(const CryptoContextImplSFDK<Element>* cc) const {
        const auto& contexts = CryptoContextFactory<Element>::GetAllContexts();
        for (const auto& ctx : contexts) {
            if (cc == ctx.get()) {
                CryptoContextSFDK<Element> xctx = std::dynamic_pointer_cast<CryptoContextImplSFDK<Element>>(ctx);
                if(!xctx)
                    OPENFHE_THROW("Context found is not of the SFDK type");
                return xctx;
            }
        }
        OPENFHE_THROW("Cannot find context for the given pointer to CryptoContextImpl");
    }

    void Enable(usint featureMask) {
        this->scheme->Enable(featureMask);
        if (featureMask & SFDK ) {
            GetSFDKScheme()->EnableSFDK();
        }
    }

    /**
   * Function to generate public and private keys
   *
   * @param &publicKey private key used for decryption.
   * @param &privateKey private key used for decryption.
   * @return function ran correctly.
   */
    KeyPairSFDK<Element> KeyGenSFDK() const {
        return GetSFDKScheme()->KeyGen(GetContextForPointer(this), false);
    }

    /**
   * Function to generate public and private keys
   *
   * @param &publicKey private key used for decryption.
   * @param &privateKey private key used for decryption.
   * @return function ran correctly.
   */
    KeyPairSFDK<Element>  SparseKeyGenSFDK() const {
        return GetSFDKScheme()->KeyGenInternal(GetContextForPointer(this), true);
    }

    /**
   * Function to generate a decryption key for a specific cipher
   *
   * @param &cipherText ciphertext to generate the decryption key for.
   * @param &keyGen key generator used to generate the decryption key.
   * @param &publicKey private key used for decryption.
   * @return function ran correctly.
   */
    KeyCipher<Element> GenDecKeyFor(Ciphertext<Element> &cipherText, KeyCipherGenKey<Element> keyGen, PublicKeySFDK<Element> publicKey) const {
        return GetSFDKScheme()->GenDecKeyFor(cipherText, keyGen, publicKey);
    }

    /**
   * Method for encrypting plaintext using LBC
   *
   * @param&publicKey public key used for encryption.
   * @param plaintext copy of the plaintext element. NOTE a copy is passed!
   * That is NOT an error!
   * @param doEncryption encrypts if true, embeds (encodes) the plaintext into
   * cryptocontext if false
   * @param *ciphertext ciphertext which results from encryption.
   */
    Ciphertext<Element> Encrypt(Plaintext plaintext, const PublicKeySFDK<Element> publicKey) const {
        //ValidateKey(publicKey);  // to do
        Ciphertext<Element> ciphertext = GetSFDKScheme()->Encrypt(plaintext->GetElement<Element>(), publicKey);

        if (ciphertext) {
            ciphertext->SetEncodingType(plaintext->GetEncodingType());
            ciphertext->SetScalingFactor(plaintext->GetScalingFactor());
            ciphertext->SetScalingFactorInt(plaintext->GetScalingFactorInt());
            ciphertext->SetNoiseScaleDeg(plaintext->GetNoiseScaleDeg());
            ciphertext->SetLevel(plaintext->GetLevel());
            ciphertext->SetSlots(plaintext->GetSlots());
        }

        return ciphertext;
    }

    Ciphertext<Element> Encrypt(const PublicKeySFDK<Element> publicKey, Plaintext plaintext) const {
        return Encrypt(plaintext, publicKey);
    }

    /**
   * Method for decrypting plaintext using LBC
   *
   * @param &ciphertext ciphertext id decrypted.
   * @param &decKey private key used for decryption.
   * @param publicKey public key used for decryption.
   * @param *plaintext the plaintext output.
   * @return the decoding result.
   */
    DecryptResult DecryptSFDK(Ciphertext<Element> &ciphertext, KeyCipher<Element> &decKey, PublicKeySFDK<Element> publicKey,
                                  Plaintext* plaintext) {
        return GetSFDKScheme()->Decrypt(ciphertext, decKey, publicKey, plaintext);
    }

/**
 * @brief Method for testing if a ciphertext is a member of a set
 * 
 * @param ciphertext with the element to be tested
 * @param testset the set to be tested against
 * @param cryptoContext the crypto context
 * @return Ciphertext<Element> 
 */
Ciphertext<Element> PrivateSetMembership(Ciphertext<Element> &ciphertext, std::vector<int64_t> &testset) const {
    //auto shared_this = std::const_pointer_cast<CryptoContextImplSFDK<Element>>(this->shared_from_this());
    return GetSFDKScheme()->PrivateSetMembership(ciphertext, testset, const_cast<CryptoContextImplSFDK<DCRTPoly>*>(this));
 }
   
/**
 * @brief Method for testing if a ciphertext between two integers
 * 
 * @param ciphertext with the element to be tested
 * @param start the lower bound of the interval
 * @param size the size of the interval
 * @param cryptoContext the crypto context
 * @return Ciphertext<Element> 
 */
 Ciphertext<Element> PrivateSetMembership(Ciphertext<Element> &ciphertext, uint start, uint size) const {
    //auto shared_this = std::const_pointer_cast<CryptoContextImplSFDK<Element>>(this->shared_from_this());
    return GetSFDKScheme()->PrivateSetMembership(ciphertext, start, size, const_cast<CryptoContextImplSFDK<DCRTPoly>*>(this));
 }

/**
 * @brief Method to set the parameters for a Private Membership Test
 * 
 * @param secretKey 
 * @param maxsize the maximum size of the set
 * @param cryptoContext 
 */
void PreparePSM(PrivateKey<Element> secretKey, uint maxsize)  {
    ///auto shared_this = std::const_pointer_cast<CryptoContextImplSFDK<Element>>(this->shared_from_this());
    return GetSFDKScheme()->PreparePSM(secretKey, maxsize, this);
 }

 /**
  * @brief Get the Zero Sponge Encryption object
  * 
  * @param privateKey  the private key
  * @param publicKey   the public key
  * @param ciphertext  the ciphertext to absorb
  * @param scale 
  * @param isNotZero 
  * @return Ciphertext<Element> 
  */
Ciphertext<Element> GetZeroSpongeEncryption(
		const PrivateKey<Element> privateKey, 
		const PublicKeySFDK<Element> publicKey,
		Ciphertext<Element> ciphertext,
		usint &scale,
		bool isNotZero=false) const {
    return GetSFDKScheme()->GetZeroSpongeEncryption(privateKey, publicKey, ciphertext, scale, isNotZero);
}

/**
 * @brief SAcalke the erro by the number of bits
 * 
 * @param ciphertext 
 * @param bits 
 * @return Ciphertext<Element> 
 */
Ciphertext<Element> ScaleByBits(ConstCiphertext<Element> ciphertext, usint bits) const {
    return GetSFDKScheme()->ScaleByBits(ciphertext, bits);
}

/**
 * @brief Get the error of the ciphertext after decryption
 * 
 * @param privateKey 
 * @param ciphertext 
 * @param plaintext 
 */
Element GetDecryptionError(const PrivateKey<Element> privateKey, Ciphertext<Element> &ciphertext, Plaintext plaintext = NULL) const {
    return GetSFDKScheme()->GetDecryptionError(privateKey, ciphertext, plaintext);
}

};

}  // namespace lbcrypto

#endif /* SRC_PKE_CRYPTOCONTEXT_SFDK_H_ */
