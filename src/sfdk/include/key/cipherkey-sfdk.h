//==================================================================================
//
// Author Carlos Ribeiro
//
//==================================================================================

/*
  Public key type for lattice crypto operations
 */

#ifndef LBCRYPTO_CRYPTO_KEY_CIPHERKEY_SFDK_H
#define LBCRYPTO_CRYPTO_KEY_CIPHERKEY_SFDK_H

#include "pke/cryptoobject.h"
#include "publickey-sfdk.h"
#include "cipherkey-fwd-sfdk.h"

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

/**
 * @brief Class for cipher key
 * @tparam Element a ring element.
 */
template <class Element>
class KeyCipherImpl : public CryptoObject<Element> {
  public:
    explicit KeyCipherImpl(std::shared_ptr<Matrix<Element>> key, PublicKeySFDK<Element> publicKey) : 
      CryptoObject<Element>(publicKey->GetCryptoContext(), publicKey->GetKeyTag()), m_key(key) {
      }
  std::shared_ptr<Matrix<Element>> getPrivateElement() {
    return m_key;
  }
  protected:
    std::shared_ptr<Matrix<Element>> m_key;
};
}
#endif /* LBCRYPTO_CRYPTO_KEY_CIPHERKEYGEN_SFDK_H */