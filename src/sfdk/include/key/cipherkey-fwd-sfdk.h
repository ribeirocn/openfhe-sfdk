//==================================================================================
// Author : Carlos Ribeiro
//
//==================================================================================
/*
 * It is a lightweight file to be included where we need the declaration of PublicKey only
 *
 */
#ifndef __CIPHERKEY_FWD_SFDK_H__
#define __CIPHERKEY_FWD_SFDK_H__

#include <memory>

namespace lbcrypto {

template <typename Element>
class KeyCipherImpl;

template <typename Element>
using KeyCipher = std::shared_ptr<KeyCipherImpl<Element>>;



}  // namespace lbcrypto

#endif  // ___CIPHERKEY_FWD_SFDK_H__
