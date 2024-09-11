//==================================================================================
// Author : Carlos Ribeiro
//
//==================================================================================
/*
 * It is a lightweight file to be included where we need the declaration of PublicKey only
 *
 */
#ifndef __CIPHERKEYGEN_FWD_SFDK_H__
#define __CIPHERKEYGEN_FWD_SFDK_H__

#include <memory>

namespace lbcrypto {

template <typename Element>
class KeyCipherGenKeyImpl;

template <typename Element>
using KeyCipherGenKey = std::shared_ptr<KeyCipherGenKeyImpl<Element>>;



}  // namespace lbcrypto

#endif  // ___CIPHERKEYGEN_FWD_SFDK_H__
