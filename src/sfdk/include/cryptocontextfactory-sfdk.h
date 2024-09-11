//==================================================================================
//
// Author Carlos Ribeiro
//
//==================================================================================

#ifndef SRC_PKE_CRYPTOCONTEXTFACTORY_SFDK_H_
#define SRC_PKE_CRYPTOCONTEXTFACTORY_SFDK_H_

#include "pke/cryptocontextfactory.h"
#include "cryptocontext-fwd-sfdk.h"


namespace lbcrypto {

template <typename Element>
class SchemeBase;
template <typename Element>
class CryptoParametersBase;

/**
 * @brief CryptoContextFactory
 *
 * A class that contains all generated contexts and static methods to access/release them
 */
template <typename Element>
class CryptoContextFactorySFDK : public CryptoContextFactory<Element> {


public:

    static CryptoContext<Element> GetContext(std::shared_ptr<CryptoParametersBase<Element>> params,
                                             std::shared_ptr<SchemeBase<Element>> scheme,
                                             SCHEME schemeId = SCHEME::INVALID_SCHEME) ;


};

template <typename Element>
inline CryptoContext<Element> CryptoContextFactorySFDK<Element>::GetContext(
    std::shared_ptr<CryptoParametersBase<Element>> params,
    std::shared_ptr<SchemeBase<Element>> scheme, SCHEME schemeId) {
    CryptoContext<Element> cc = CryptoContextFactory<Element>::FindContext(params, scheme);
    // if the context is not found we should create one
    if (nullptr == cc) {
        auto mscheme = std::static_pointer_cast<SchemeBFVRNSSFDK>(scheme);
        //auto gcc = CryptoContextImplSFDK<Element>(params, scheme, schemeId);
        cc = std::make_shared<CryptoContextImplSFDK<Element>>(params, mscheme, schemeId);
        CryptoContextFactory<Element>::AddContext(cc);
    }

    return cc;
}

}  // namespace lbcrypto

#endif
