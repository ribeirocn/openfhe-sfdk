//==================================================================================
// Author : Carlos Ribeiro
//
//==================================================================================
/*
 * It is a lightweight file to be included where we need the declaration of PublicKey only
 *
 */
#ifndef __PUBLICKEY_FWD_SFDK_H__
#define __PUBLICKEY_FWD_SFDK_H__

#include <memory>

namespace lbcrypto {

template <typename Element>
class PublicKeyImplSFDK;

template <typename Element>
using PublicKeySFDK = std::shared_ptr<PublicKeyImplSFDK<Element>>;

}  // namespace lbcrypto

#endif  // __PUBLICKEY_FWD_SFDK_H__
