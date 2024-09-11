//==================================================================================
//
// Author Carlos Ribeiro
//
//==================================================================================

/*
  Public key type for lattice crypto operations
 */

#ifndef LBCRYPTO_CRYPTO_KEY_PUBLICKEY_SFDK_H
#define LBCRYPTO_CRYPTO_KEY_PUBLICKEY_SFDK_H

#include "key/publickey-fwd-sfdk.h"
#include "cryptocontext-sfdk.h"
#include "pke/key/publickey.h"
#include "lattice/trapdoor.h"

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

/**
 * @brief Class for public key
 * @tparam Element a ring element.
 */
template <typename Element>
class PublicKeyImplSFDK : public PublicKeyImpl<Element> {
public:


    /**
   * Copy constructor
   *
   *@param &rhs PublicKeyImpl to copy from
   */
    explicit PublicKeyImplSFDK(const PublicKeyImplSFDK<Element>& rhs)
        : PublicKeyImpl<Element>(rhs.GetCryptoContext(), rhs.GetKeyTag()), m_xh(rhs.m_xh) {}


    /**
   * Basic constructor
   *
   * @param cc - CryptoContext
   * @param id - key identifier
   */
   explicit PublicKeyImplSFDK(CryptoContext<Element> cc, const std::string& id = "") : PublicKeyImpl<Element>(cc, id) {}

    /**
   * Move constructor
   *
   *@param &rhs PublicKeyImpl to move from
   */
    explicit PublicKeyImplSFDK(PublicKeyImplSFDK<Element>&& rhs) noexcept
        : PublicKeyImpl<Element>(rhs.GetCryptoContext(), rhs.GetKeyTag()), 
            m_xh(std::move(rhs.m_xh)) {}

    operator bool() const {
        return static_cast<bool>(this->context) && m_xh.size() != 0;
    }

    /**
   * Assignment Operator.
   *
   * @param &rhs PublicKeyImpl to copy from
   */
    PublicKeyImplSFDK<Element>& operator=(const PublicKeyImplSFDK<Element>& rhs) {
        CryptoObject<Element>::operator=(rhs);
        this->m_xh = rhs.m_xh;
        return *this;
    }

    /**
   * Move Assignment Operator.
   *
   * @param &rhs PublicKeyImpl to copy from
   */
    PublicKeyImplSFDK<Element>& operator=(PublicKeyImplSFDK<Element>&& rhs) {
        CryptoObject<Element>::operator=(rhs);
        m_xh = std::move(rhs.m_xh);
        return *this;
    }

    // @Get Properties

    /**
   * Gets the computed public key
   * @return the public key element.
   */
    const std::vector<Matrix<Element>>& GetLargePublicElements() const {
        return this->m_xh;
    }

    // @Set Properties

    /**
   * Sets the public key vector of Element.
   * @param &element is the public key Element vector to be copied.
   */
    void SetLargePublicElements(const std::vector<Matrix<Element>>& element) {
        m_xh = element;
    }

    /**
   * Sets the public key vector of Element.
   * @param &&element is the public key Element vector to be moved.
   */
    void SetLargePublicElements(std::vector<Matrix<Element>>&& element) {
        m_xh = std::move(element);
    }

    /**
   * Sets the public key Element at index idx.
   * @param &element is the public key Element to be copied.
   */
    void SetLargePublicElementAtIndex(usint idx, const Matrix<Element>& element) {
        m_xh.insert(m_xh.begin() + idx, element);
    }

    /**
   * Sets the public key Element at index idx.
   * @param &&element is the public key Element to be moved.
   */
    void SetLargePublicElementAtIndex(usint idx, Matrix<Element>&& element) {
        m_xh.insert(m_xh.begin() + idx, std::move(element));
    }

    bool operator==(const PublicKeyImplSFDK& other) const {
        if (!CryptoObject<Element>::operator==(other)) {
            return false;
        }

        if (m_xh.size() != other.m_xh.size()) {
            return false;
        }

        for (size_t i = 0; i < m_xh.size(); i++) {
            if (m_xh[i] != other.m_xh[i]) {
                return false;
            }
        }

        return true;
    }

    bool operator!=(const PublicKeyImplSFDK& other) const {
        return !(*this == other);
    }

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::base_class<Key<Element>>(this));
        ar(::cereal::make_nvp("h", m_xh));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            OPENFHE_THROW("serialized object version " + std::to_string(version) +
                          " is from a later version of the library");
        }
        ar(::cereal::base_class<Key<Element>>(this));
        ar(::cereal::make_nvp("h", m_xh));
    }

    std::string SerializedObjectName() const {
        return "PublicKeySFDK";
    }
    static uint32_t SerializedVersion() {
        return 1;
    }

    Matrix<Element> m_error;
    Element m_s;
private:
    std::vector<Matrix<Element>> m_xh;
};

}  // namespace lbcrypto

#endif
