//==================================================================================
// Author Carlos Ribeiro
//
//==================================================================================

#ifndef LBCRYPTO_CRYPTO_BFVRNS_SFDK_PKE_H
#define LBCRYPTO_CRYPTO_BFVRNS_SFDK_PKE_H


#include "openfhe.h"
#include "cryptocontext-sfdk.h"

#include <string>

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

class SFDKBFVRNS  {
    using ParmType = typename DCRTPoly::Params;
    using IntType  = typename DCRTPoly::Integer;
    using DugType  = typename DCRTPoly::DugType;
    using DggType  = typename DCRTPoly::DggType;
    using TugType  = typename DCRTPoly::TugType;

public:
    virtual ~SFDKBFVRNS() {}

 /**
   * Function to generate public and private keys
   *
   * @param &publicKey private key used for decryption.
   * @param &privateKey private key used for decryption.
   * @return function ran correctly.
   */
   KeyPairSFDK<DCRTPoly> KeyGenInternal(CryptoContextSFDK<DCRTPoly> cc, bool makeSparse) const ;

    /**
   * Function to generate a decryption key for a specific cipher
   *
   * @param &cipherText ciphertext to generate the decryption key for.
   * @param &keyGen key generator used to generate the decryption key.
   * @param &publicKey private key used for decryption.
   * @return function ran correctly.
   */
    KeyCipher<DCRTPoly> GenDecKeyFor(Ciphertext<DCRTPoly> &cipherText, KeyCipherGenKey<DCRTPoly> keyGen, PublicKeySFDK<DCRTPoly> publicKey) const ;

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
    Ciphertext<DCRTPoly> Encrypt(DCRTPoly plaintext, const PublicKeySFDK<DCRTPoly> publicKey) const ;

    /**
   * Method for decrypting plaintext using LBC
   *
   * @param &ciphertext ciphertext id decrypted.
   * @param &decKey private key used for decryption.
   * @param publicKey public key used for decryption.
   * @param *plaintext the plaintext output.
   * @return the decoding result.
   */
    DecryptResult Decrypt(const Ciphertext<DCRTPoly> &ciphertext, const KeyCipher<DCRTPoly> &decKey, const PublicKeySFDK<DCRTPoly> publicKey,
                                  Plaintext* plaintext) ;

/**
 * @brief Method for testing if a ciphertext is a member of a set
 * 
 * @param ciphertext with the element to be tested
 * @param testset the set to be tested against
 * @param cryptoContext the crypto context
 * @param secretKey the secret key
 * @return Ciphertext<DCRTPoly> 
 */
 Ciphertext<DCRTPoly> PrivateSetMembership(Ciphertext<DCRTPoly> ciphertext, const std::vector<int64_t> &testset, CryptoContextImplSFDK<DCRTPoly> *cryptoContext)  ;
   
/**
 * @brief Method for testing if a ciphertext between two integers
 * 
 * @param ciphertext with the element to be tested
 * @param start the lower bound of the interval
 * @param size the size of the interval
 * @param cryptoContext the crypto context
 * @param secretKey the secret key
 * @return Ciphertext<DCRTPoly> 
 */
 Ciphertext<DCRTPoly> PrivateSetMembership(Ciphertext<DCRTPoly> ciphertext, uint start, uint size, CryptoContextImplSFDK<DCRTPoly> *cryptoContext)  ;

/**
 * @brief Method to set the parameters for a Private Membership Test
 * 
 * @param secretKey 
 * @param maxsize the maximum size of the set
 * @param cryptoContext 
 */
void PreparePSM(PrivateKey<DCRTPoly> secretKey, uint maxsize, CryptoContextImplSFDK<DCRTPoly> *cryptoContext)  ;

 /**
  * @brief Get the Zero Sponge Encryption object
  * 
  * @param privateKey  the private key
  * @param publicKey   the public key
  * @param ciphertext  the ciphertext to absorb
  * @param scale 
  * @param isNotZero 
  * @return Ciphertext<DCRTPoly> 
  */
 Ciphertext<DCRTPoly> GetZeroSpongeEncryption(
		const PrivateKey<DCRTPoly> privateKey, 
		const PublicKeySFDK<DCRTPoly> publicKey,
		Ciphertext<DCRTPoly> ciphertext,
		usint &scale,
		bool isNotZero=false) const ;

/**
 * @brief SAcalke the erro by the number of bits
 * 
 * @param ciphertext 
 * @param bits 
 * @return Ciphertext<DCRTPoly> 
 */
Ciphertext<DCRTPoly> ScaleByBits(ConstCiphertext<DCRTPoly> ciphertext, usint bits) const ;

/**
 * @brief Get the error of the ciphertext after decryption
 * 
 * @param privateKey 
 * @param ciphertext 
 * @param plaintext 
 */
  DCRTPoly GetDecryptionError(const PrivateKey<DCRTPoly> privateKey, Ciphertext<DCRTPoly> &ciphertext, Plaintext plaintext = NULL) const ;

    /////////////////////////////////////
    // SERIALIZATION
    /////////////////////////////////////

    template <class Archive>
    void save(Archive& ar) const {
        ar(cereal::base_class<SFDKBFVRNS>(this));
    }

    template <class Archive>
    void load(Archive& ar) {
        ar(cereal::base_class<SFDKBFVRNS>(this));
    }

    std::string SerializedObjectName() const {
        return "SFDKBFVRNS";
    }
};
}  // namespace lbcrypto

#endif
