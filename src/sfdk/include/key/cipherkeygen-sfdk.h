//==================================================================================
//
// Author Carlos Ribeiro
//
//==================================================================================

/*
  Public key type for lattice crypto operations
 */

#ifndef LBCRYPTO_CRYPTO_KEY_CIPHERKEYGEN_SFDK_H
#define LBCRYPTO_CRYPTO_KEY_CIPHERKEYGEN_SFDK_H

#include "cipherkeygen-fwd-sfdk.h"
#include "lattice/trapdoor.h"

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
class KeyCipherGenKeyImpl : public Key<Element> {
  public:
    KeyCipherGenKeyImpl(std::shared_ptr<RLWETrapdoorPair<Element>> trapdoor, PublicKeySFDK<Element> publicKey) : 
      Key<Element>(publicKey->GetCryptoContext(), publicKey->GetKeyTag()), m_key(trapdoor) {

    }
    KeyCipherGenKeyImpl(CryptoContext<Element> cc = 0, const std::string &id = "")
      : Key<Element>(cc, id) {}

    KeyCipherGenKeyImpl(const KeyCipherGenKeyImpl<Element> &rhs)
      : Key<Element>(rhs.GetCryptoContext(), rhs.GetKeyTag()) {
      this->m_key = rhs.m_key;
    }

    KeyCipherGenKeyImpl(KeyCipherGenKeyImpl<Element> &&rhs)
      : Key<Element>(rhs.GetCryptoContext(), rhs.GetKeyTag()) {
        this->m_key = std::move(rhs.m_key);
    }

    operator bool() const { return static_cast<bool>(this->context); }

    const KeyCipherGenKeyImpl<Element> &operator=(const KeyCipherGenKeyImpl<Element> &rhs) {
        CryptoObject<Element>::operator=(rhs);
        this->m_key = rhs.m_key;
        return *this;
    }

    const KeyCipherGenKeyImpl<Element> &operator=(KeyCipherGenKeyImpl<Element> &&rhs) {
        CryptoObject<Element>::operator=(rhs);
        this->m_key = std::move(rhs.m_key);
        return *this;
    }

    const std::shared_ptr<RLWETrapdoorPair<Element>> GetPrivateElement() const { return m_key; }

    void SetPrivateElement(const std::shared_ptr<RLWETrapdoorPair<Element>> x) { m_key = x; }

    bool operator==(const KeyCipherGenKeyImpl &other) const {
        return CryptoObject<Element>::operator==(other) && m_key == other.m_key;
    }

    bool operator!=(const KeyCipherGenKeyImpl &other) const {
        return !(*this == other);
    }

    template <class Archive>
    void save(Archive &ar, std::uint32_t const version) const {
        ar(::cereal::base_class<Key<Element>>(this));
        ar(::cereal::make_nvp("s", m_key));
    }

    template <class Archive>
    void load(Archive &ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            OPENFHE_THROW(deserialize_error,
                     "serialized object version " + std::to_string(version) +
                         " is from a later version of the library");
        }
        ar(::cereal::base_class<Key<Element>>(this));
        ar(::cereal::make_nvp("s", m_key));
    }

    std::string SerializedObjectName() const { return "KeyCipherGenKey"; }
    static uint32_t SerializedVersion() { return 1; }


  protected:
    std::shared_ptr<RLWETrapdoorPair<Element>> m_key;
};

}  // namespace lbcrypto
#endif  // LBCRYPTO_CRYPTO_KEY_CIPHERKEYGEN_SFDK_H

