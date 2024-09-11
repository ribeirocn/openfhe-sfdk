//==================================================================================
// Author Carlos Ribeiro
//

//==================================================================================

/*
 * It is a lightweight file to be included where we need the declaration of CryptoContext only
 *
 */
#ifndef __CRYPTOCONTEXT_SFDK_FWD_H__
#define __CRYPTOCONTEXT_SFDK_FWD_H__

#include <memory>

namespace lbcrypto {

template <typename Element>
class CryptoContextImplSFDK;

template <typename Element>
using CryptoContextSFDK = std::shared_ptr<CryptoContextImplSFDK<Element>>;

} // namespace lbcrypto

#endif // __CRYPTOCONTEXT_SFDK_FWD_H__

