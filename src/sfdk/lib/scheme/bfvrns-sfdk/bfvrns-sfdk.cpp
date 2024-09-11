#include "scheme/bfvrns-sfdk/bfvrns-cryptoparameters-sfdk.h"
#include "cryptocontext-sfdk.h"
#include "utils_sfdk.h"

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

KeyPairSFDK<DCRTPoly> lbcrypto::SFDKBFVRNS::KeyGenInternal(
    CryptoContextSFDK<DCRTPoly> cc, bool makeSparse) const {
  KeyPairSFDK<DCRTPoly> kp(std::make_shared<PublicKeyImplSFDK<DCRTPoly>>(cc),
                           std::make_shared<PrivateKeyImpl<DCRTPoly>>(cc),
                           std::make_shared<KeyCipherGenKeyImpl<DCRTPoly>>(cc));

  const auto cryptoParams =
      std::static_pointer_cast<CryptoParametersBFVRNSSFDK>(
          cc->GetCryptoParameters());

  const std::shared_ptr<ParmType> elementParams =
      cryptoParams->GetElementParams();

  usint base = cryptoParams->GetBase();

  const DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();
  DugType dug;
  TugType tug;

  auto stddev = dgg.GetStd();

  // Generate trapdoor based using parameters and
  std::pair<Matrix<DCRTPoly>, RLWETrapdoorPair<DCRTPoly>> keyPair =
      RLWETrapdoorUtility<DCRTPoly>::TrapdoorGen(elementParams, stddev, base);
  usint k = keyPair.first.GetData()[0].size();
  cryptoParams->SetK(k);
  // elementParams->SetK(keyPair.first.GetData()[0].size());
  //  Format of vectors are changed to prevent complications in calculations
  keyPair.second.m_e.SetFormat(Format::EVALUATION);
  keyPair.second.m_r.SetFormat(Format::EVALUATION);

  Matrix<DCRTPoly> &a = keyPair.first;

  a.SetFormat(Format::EVALUATION);
  // Generate the secret key
  DCRTPoly s;

  // Done in two steps not to use a random polynomial from a pre-computed pool
  // Supports both discrete Gaussian (RLWE) and ternary uniform distribution
  // (OPTIMIZED) cases

  if (cryptoParams->GetSecretKeyDist() == GAUSSIAN) {
    s = DCRTPoly(dgg, elementParams, Format::COEFFICIENT);
  } else {
    s = DCRTPoly(tug, elementParams, Format::COEFFICIENT, 0);
  }
  s.SetFormat(Format::EVALUATION);

  kp.secretKey->SetPrivateElement(s);

  auto zero_alloc = DCRTPoly::Allocator(elementParams, EVALUATION);
  auto gaussian_alloc = DCRTPoly::MakeDiscreteGaussianCoefficientAllocator(
      elementParams, Format::COEFFICIENT, dgg.GetStd());
  // Done in two steps not to use a discrete Gaussian polynomial from a
  // pre-computed pool
  Matrix<DCRTPoly> e(zero_alloc, 1, k, gaussian_alloc);
  // DCRTPoly e(dgg, elementParams, Format::COEFFICIENT,elementParams->GetK());
  e.SetFormat(Format::EVALUATION);
  kp.publicKey->m_error = e;
  kp.publicKey->m_s = s;

  Matrix<DCRTPoly> b(zero_alloc, 1, k);
  // DCRTPoly b(elementParams, Format::EVALUATION, true, elementParams->GetK());
  b -= e;
  b -= (a * s);

  kp.publicKey->SetLargePublicElementAtIndex(0, std::move(b));
  kp.publicKey->SetLargePublicElementAtIndex(1, std::move(a));

  // Signing key will contain public key matrix of the trapdoor and the trapdoor
  // matrices
  // functionDecryptionKeyGen->SetSFDKDecKeyGen(
  //    std::make_shared<RLWETrapdoorPair<typename
  //    DCRTPoly::PType>>(keyPair.second));
  kp.cipherKeyGen->SetKeyTag(kp.secretKey->GetKeyTag());
  kp.publicKey->SetKeyTag(kp.secretKey->GetKeyTag());
  kp.cipherKeyGen->SetPrivateElement(
      std::make_shared<RLWETrapdoorPair<DCRTPoly>>(keyPair.second));

  return kp;
}

KeyCipher<DCRTPoly> lbcrypto::SFDKBFVRNS::GenDecKeyFor(
    Ciphertext<DCRTPoly> &cipherText, KeyCipherGenKey<DCRTPoly> keyGen,
    PublicKeySFDK<DCRTPoly> publicKey) const {
  const std::vector<DCRTPoly> &cipherTextElements = cipherText->GetElements();
  if (cipherTextElements.size() != 2) {
    OPENFHE_THROW(config_error,
                  "Specific DecKey is only defined for ciphertexts of size 2"
                  "Please relinearize before");
  }

  const auto cryptoParams =
      std::static_pointer_cast<CryptoParametersBFVRNSSFDK>(
          publicKey->GetCryptoParameters());
  auto params = cryptoParams->GetElementParams();
  size_t n = params->GetRingDimension();
  size_t k = cryptoParams->GetK();
  size_t base = cryptoParams->GetBase();

  EncodingParams ep(
      std::make_shared<EncodingParamsImpl>(PlaintextModulus(512)));

  DCRTPoly u = cipherTextElements[1];
  u.SetFormat(Format::EVALUATION);

  // Getting the trapdoor, its public matrix, perturbation matrix and gaussian
  // generator to use in sampling
  auto A = publicKey->GetLargePublicElements()[1];
  auto zero_alloc = DCRTPoly::Allocator(params, EVALUATION);

  DggType dgg = cryptoParams->GetDiscreteGaussianGenerator();

  DggType &dggLargeSigma =
      cryptoParams->GetDiscreteGaussianGeneratorLargeSigma();

  Matrix<DCRTPoly> zHat = RLWETrapdoorUtility<DCRTPoly>::GaussSamp(
      n, k - 2, A, *keyGen->GetPrivateElement(), u, dgg, dggLargeSigma, base);

  return std::make_shared<KeyCipherImpl<DCRTPoly>>(
      std::make_shared<Matrix<DCRTPoly>>(zHat), publicKey);
}

Ciphertext<DCRTPoly> lbcrypto::SFDKBFVRNS::Encrypt(
    DCRTPoly plaintext, const PublicKeySFDK<DCRTPoly> publicKey) const {
  //----------------------------------------------------------------------------------
  // Test parameters
  //----------------------------------------------------------------------------------
  if (publicKey == nullptr) {
    OPENFHE_THROW(config_error,
                  "Wrong PubKey type. Please, generate key for this context");
  }
  auto cryptoParams = std::static_pointer_cast<CryptoParametersBFVRNSSFDK>(
      publicKey->GetCryptoParameters());

  if (cryptoParams->GetEncryptionTechnique() == EXTENDED) {
    OPENFHE_THROW(config_error, "Not Supprted: Extended encrytion technique");
  }
  auto elementParams = cryptoParams->GetElementParams();
  size_t sizeQ = elementParams->GetParams().size();
  auto encParams = plaintext.GetParams();
  size_t sizeP = encParams->GetParams().size();

  if (sizeP != sizeQ) {
    OPENFHE_THROW(config_error,
                  "Not Supported: Plaintext encodings with smaller number of "
                  "RNS limbs than the public key");
  }

  //----------------------------------------------------------------------------------
  // Multiply Plaintext
  //----------------------------------------------------------------------------------
  std::vector<NativeInteger> tInvModq = cryptoParams->GettInvModq();
  const NativeInteger t = cryptoParams->GetPlaintextModulus();
  NativeInteger NegQModt = cryptoParams->GetNegQModt(0);
  NativeInteger NegQModtPrecon = cryptoParams->GetNegQModtPrecon(0);

  plaintext.SetFormat(Format::COEFFICIENT);
  plaintext.TimesQovert(encParams, tInvModq, t, NegQModt, NegQModtPrecon);
  plaintext.SetFormat(Format::EVALUATION);

  //----------------------------------------------------------------------------------
  // Generates Zero Encrytion and add scaled plaintext
  //----------------------------------------------------------------------------------

  const DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();

  Matrix<DCRTPoly> p0 = publicKey->GetLargePublicElements().at(0);
  Matrix<DCRTPoly> p1 = publicKey->GetLargePublicElements().at(1);

  auto zero_alloc = DCRTPoly::Allocator(elementParams, EVALUATION);
  auto gaussian_alloc = DCRTPoly::MakeDiscreteGaussianCoefficientAllocator(
      elementParams, Format::COEFFICIENT, dgg.GetStd());

  Matrix<DCRTPoly> u(zero_alloc, p0.GetData()[0].size(), 1, gaussian_alloc);

  DCRTPoly e1(dgg, elementParams, Format::EVALUATION);
  DCRTPoly e2(dgg, elementParams, Format::EVALUATION);  // new version

  DCRTPoly c0(elementParams);
  DCRTPoly c1(elementParams);

  p0.SetFormat(Format::EVALUATION);
  p1.SetFormat(Format::EVALUATION);
  u.SetFormat(Format::EVALUATION);

  const auto ns = cryptoParams->GetNoiseScale();

  c0 = SdfkUtils::dotProd(p0, u) + ns * e1 + plaintext;

  c1 = SdfkUtils::dotProd(p1, u) + ns * e2;

  //----------------------------------------------------------------------------------
  // Build Ciphertext
  //----------------------------------------------------------------------------------
  Ciphertext<DCRTPoly> ciphertext(
      std::make_shared<CiphertextImpl<DCRTPoly>>(publicKey));
  ciphertext->SetElements({std::move(c0), std::move(c1)});
  ciphertext->SetNoiseScaleDeg(1);

  return ciphertext;
}

DecryptResult ScaleAndRound(
    DCRTPoly &b, NativePoly *plaintext,
    std::shared_ptr<CryptoParametersBFVRNSSFDK> cryptoParams) {
  b.SetFormat(Format::COEFFICIENT);
  if (cryptoParams->GetMultiplicationTechnique() == HPS ||
      cryptoParams->GetMultiplicationTechnique() == HPSPOVERQ ||
      cryptoParams->GetMultiplicationTechnique() == HPSPOVERQLEVELED) {
    *plaintext = b.ScaleAndRound(cryptoParams->GetPlaintextModulus(),
                                 cryptoParams->GettQHatInvModqDivqModt(),
                                 cryptoParams->GettQHatInvModqDivqModtPrecon(),
                                 cryptoParams->GettQHatInvModqBDivqModt(),
                                 cryptoParams->GettQHatInvModqBDivqModtPrecon(),
                                 cryptoParams->GettQHatInvModqDivqFrac(),
                                 cryptoParams->GettQHatInvModqBDivqFrac());
  } else {
    *plaintext = b.ScaleAndRound(
        cryptoParams->GetModuliQ(), cryptoParams->GetPlaintextModulus(),
        cryptoParams->Gettgamma(), cryptoParams->GettgammaQHatInvModq(),
        cryptoParams->GettgammaQHatInvModqPrecon(),
        cryptoParams->GetNegInvqModtgamma(),
        cryptoParams->GetNegInvqModtgammaPrecon());
  }

  return DecryptResult(plaintext->GetLength());
}

DecryptResult lbcrypto::SFDKBFVRNS::Decrypt(const Ciphertext<DCRTPoly> &ciphertext,
                                            const KeyCipher<DCRTPoly> &decKey,
                                            const PublicKeySFDK<DCRTPoly> publicKey,
                                            Plaintext *plaintext) {
  const std::vector<Matrix<DCRTPoly>> &pubKeyElements =
      publicKey->GetLargePublicElements();
  Matrix<DCRTPoly> b = pubKeyElements[0];

  const std::vector<DCRTPoly> &c = ciphertext->GetElements();

  DCRTPoly r = c[0];
  r.SetFormat(Format::EVALUATION);
  b.SetFormat(Format::EVALUATION);
  decKey->getPrivateElement()->SetFormat(Format::EVALUATION);
  auto zHat = *decKey->getPrivateElement();
  auto bt = SdfkUtils::dotProd(b, zHat);
  r -= bt;

  // this is the resulting vector of coefficients;

  auto vp = std::make_shared<typename NativePoly::Params>(
      ciphertext->GetElements()[0].GetParams()->GetCyclotomicOrder(),
      decKey->GetCryptoContext()->GetEncodingParams()->GetPlaintextModulus(),
      1);
  Plaintext decrypted = PlaintextFactory::MakePlaintext(
      ciphertext->GetEncodingType(), vp,
      decKey->GetCryptoContext()->GetEncodingParams());

  DecryptResult result =
      ScaleAndRound(r, &decrypted->GetElement<NativePoly>(),
                    std::static_pointer_cast<CryptoParametersBFVRNSSFDK>(
                        decKey->GetCryptoParameters()));
  decrypted->Decode();

  if (result.isValid == false) return result;

  *plaintext = std::move(decrypted);

  return result;
}

Ciphertext<DCRTPoly> lbcrypto::SFDKBFVRNS::PrivateSetMembership(
    Ciphertext<DCRTPoly> ciphertext, const std::vector<int64_t> &_testset,
    CryptoContextImplSFDK<DCRTPoly> *cryptoContext)  {
  Plaintext testset = cryptoContext->MakePackedPlaintext(_testset);
  uint size = _testset.size();
  // Copy ciphertext to every slot to be compared
  // The number of rot/add is ceil(log(size)) where size is the number of
  // elements in the Private Set
  uint rot, prot = 1;

  Ciphertext<DCRTPoly> result = nullptr;
  if ((size & 1) != 0) {
      result =  ciphertext;
  }
  for (rot = 2; rot <= size; rot = rot << 1) {
    ciphertext = cryptoContext->EvalAdd(
        ciphertext, cryptoContext->EvalAtIndex(ciphertext, -prot));
    if ((size & rot) != 0) {
      result = result == nullptr
                   ? ciphertext
                   : cryptoContext->EvalAdd(
                         ciphertext, cryptoContext->EvalAtIndex(result, -rot));
    }
    prot = rot;

  }

  // Subtract every element in the private set from one of the copies of the
  // plaintext. The slot with an equal value becames zero, all the others are
  // different from zero.
  ciphertext = cryptoContext->EvalSub(result, testset);

  // Caclulate the x^(p-1) mod p, where x is each of the slot values.
  // The slot with a zero value remains zero, all the other became 1 by the
  // Fermat Little Theorem
  auto p = cryptoContext->GetCryptoParameters()->GetPlaintextModulus();



  ciphertext = cryptoContext->EvalMult(ciphertext, ciphertext);

  result = (p & 2) != 0 ? ciphertext : nullptr;

  for (uint mask = 4; mask < p; mask <<= 1) {
    ciphertext = cryptoContext->EvalMult(ciphertext, ciphertext);
    if ((p & mask) != 0) {
      if (result == nullptr) {
        result = ciphertext;
      } else {
        result = cryptoContext->EvalMult(result, ciphertext);
      }
    }
    
  }

  // Creates a mask to clean the extra values in the vector, beyond the size of
  // the set Multiplies the mask by the ciphertext
  // std::vector<int64_t> mask_1(size, 1);
  // Plaintext mask1 = cryptoContext->MakePackedPlaintext(mask_1);
  // result = cryptoContext->EvalMult(result,mask1);

  // Add every element in the vector, by adding half of the vetor slots with the
  // other half for ceil(log(size)) times
  for (rot = rot / 2; rot > 0; rot = rot / 2) {
    result =
        cryptoContext->EvalAdd(result, cryptoContext->EvalAtIndex(result, rot));
  }

  // Use a mask to clean all other slot elements besides the first
  std::vector<int64_t> mask_2(1, 1);
  Plaintext mask2 = cryptoContext->MakePackedPlaintext(mask_2);
  result = cryptoContext->EvalMult(result, mask2);

  // Subtracts the size of the vector
  Plaintext _size = cryptoContext->MakePackedPlaintext({size - 1});
  result = cryptoContext->EvalSub(result, _size);

  // Returns 0 if ciphertext is in the set or 1 if it is not
  return result;
}

Ciphertext<DCRTPoly> lbcrypto::SFDKBFVRNS::PrivateSetMembership(
    Ciphertext<DCRTPoly> ciphertext, uint start, uint size,
    CryptoContextImplSFDK<DCRTPoly> *cryptoContext)  {
  auto n = cryptoContext->GetRingDimension();
  uint comp_size = size > n ? n : size;

  // Copy ciphertext to every slot to be compared
  // The number of rot/add is ceil(log(size)) where size is the number of
  // elements in the Private Set
  uint rot, prot = 1;


  Ciphertext<DCRTPoly> filled_ciphertext = (comp_size & 1) != 0 ? ciphertext : nullptr;
  for (rot = 2; rot <= comp_size; rot = rot << 1) {
    ciphertext = cryptoContext->EvalAdd(
        ciphertext, cryptoContext->EvalAtIndex(ciphertext, -prot));
    if ((comp_size & rot) != 0) {
      filled_ciphertext = filled_ciphertext == nullptr
                              ? ciphertext
                              : cryptoContext->EvalAdd(
                                    ciphertext, cryptoContext->EvalAtIndex(
                                                    filled_ciphertext, -rot));
    }
    prot = rot;
  }

  for (uint t = 0; t <= size / n; t++) {
    std::vector<int64_t> plainvector(
        t == (size / n) ? size - t * n : n);  // vector with 100 ints.
    std::iota(std::begin(plainvector), std::end(plainvector),
              start + t * n);  // Fill with 0, 1, ..., 99.
    Plaintext testset = cryptoContext->MakePackedPlaintext(plainvector);
    // Subtract every element in the set from one of the copies of the
    // plaintext. The slot with an equal value becames zero, all the others are
    // different from zero.
    ciphertext = t == 0 ? cryptoContext->EvalSub(filled_ciphertext, testset)
                        : cryptoContext->EvalMult(
                              ciphertext, cryptoContext->EvalSub(
                                              filled_ciphertext, testset));
  }

  // Caclulate the x^(p-1) mod p, where x is each of the slot values.
  // The slot with a zero value remains zero, all the other became 1 by the
  // Fermat Little Theorem
  auto p = cryptoContext->GetCryptoParameters()->GetPlaintextModulus();

  ciphertext = cryptoContext->EvalMult(ciphertext, ciphertext);

  Ciphertext<DCRTPoly> result = ((p & 2) != 0) ?ciphertext : nullptr;
  
  for (uint mask = 4; mask < p; mask <<= 1) {
    ciphertext = cryptoContext->EvalMult(ciphertext, ciphertext);
    if ((p & mask) != 0) {
      result = result == nullptr ? ciphertext
                                 : cryptoContext->EvalMult(result, ciphertext);
    }
    
  }

  // Add every element in the vector, by adding half of the vetor slots with the
  // other half for ceil(log(size)) times
  for (rot = rot / 2; rot > 0; rot = rot / 2) {
    result =
        cryptoContext->EvalAdd(result, cryptoContext->EvalAtIndex(result, rot));
  }

  // Use a mask to clean all other slot elements besides the first
  std::vector<int64_t> mask_2(1, 1);
  Plaintext mask2 = cryptoContext->MakePackedPlaintext(mask_2);
  result = cryptoContext->EvalMult(result, mask2);

  // Subtracts the size of the vector
  Plaintext _size =
      cryptoContext->MakePackedPlaintext({size > n ? n - 1 : size - 1});
  result = cryptoContext->EvalSub(result, _size);

  // Returns 0 if ciphertext is in the set or 1 if it is not
  return result;
}

void lbcrypto::SFDKBFVRNS::PreparePSM(
    PrivateKey<DCRTPoly> secretKey, uint maxsize,
    CryptoContextImplSFDK<DCRTPoly> *cryptoContext)  {
  auto n = cryptoContext->GetRingDimension();
  if (maxsize > n) {
    maxsize = n;
  }
  std::vector<int32_t> keys4shifts = {};
  uint i;

  for (i = 1; i < maxsize; i <<= 1) {
    keys4shifts.push_back(i);
    keys4shifts.push_back(-i);
  }
  keys4shifts.push_back(i);
  keys4shifts.push_back(-i);
  cryptoContext->EvalAtIndexKeyGen(secretKey, keys4shifts);
}

DCRTPoly DivideApproxBySQRootOfNorm(const DCRTPoly e, usint &bits) {
  Poly poly(e.CRTInterpolate());
  poly.SetFormat(Format::COEFFICIENT);
  Poly::Integer locVal;
  Poly::Integer retVal;

  auto m_params = poly.GetParams();
  const Poly::Integer &q = m_params->GetModulus();
  const Poly::Integer &half = m_params->GetModulus() >> 1;

  auto m_values = poly.GetValues();
  for (usint i = 0; i < m_values.GetLength(); i++) {
    if (m_values.operator[](i) > half)
      locVal = q - (m_values)[i];
    else
      locVal = m_values.operator[](i);

    if (locVal > retVal) retVal = locVal;
  }
  bits = retVal.GetMSB() / 2;
  for (usint i = 0; i < m_values.GetLength(); i++) {
    if (m_values[i] > half) {
      locVal = q - (m_values)[i];
      locVal.RShiftEq(bits);
      m_values[i] = q - locVal;
    } else {
      locVal = m_values[i];
      locVal.RShiftEq(bits);
      m_values[i] = locVal;
    }
  }
  poly.SetValues(m_values, poly.GetFormat());
  return DCRTPoly(poly, e.GetParams());
}

Ciphertext<DCRTPoly> lbcrypto::SFDKBFVRNS::GetZeroSpongeEncryption(
    const PrivateKey<DCRTPoly> privateKey, const PublicKeySFDK<DCRTPoly> pubKey,
    Ciphertext<DCRTPoly> ciphertext, usint &scale, bool isNotZero) const {
  auto publicKey =
      std::dynamic_pointer_cast<PublicKeyImplSFDK<DCRTPoly>>(pubKey);
  auto cryptoParams = std::static_pointer_cast<CryptoParametersBFVRNSSFDK>(
      privateKey->GetCryptoParameters());
  const std::shared_ptr<ParmType> elementParams =
      cryptoParams->GetElementParams();
  Ciphertext<DCRTPoly> newCiphertext(
      std::make_shared<CiphertextImpl<DCRTPoly>>(*ciphertext));

  const std::vector<DCRTPoly> &c = ciphertext->GetElements();
  const DCRTPoly &s = privateKey->GetPrivateElement();
  DCRTPoly sPower = s;

  DCRTPoly b = c[0];
  b.SetFormat(Format::EVALUATION);

  DCRTPoly cTemp;
  for (size_t i = 1; i < c.size(); i++) {
    cTemp = c[i];
    cTemp.SetFormat(Format::EVALUATION);

    b += sPower * cTemp;
    sPower *= s;
  }
  b.SwitchFormat();
  if (isNotZero) {
    // To be tested
    // If the original ciphertext is not an encryption of zero
    // then we must subtract the plaintext multiplied by delta
    //b.SwitchFormat();

    auto vp = std::make_shared<typename NativePoly::Params>(
        ciphertext->GetElements()[0].GetParams()->GetCyclotomicOrder(),
        privateKey->GetCryptoContext()
            ->GetEncodingParams()
            ->GetPlaintextModulus(),
        1);
    Plaintext decrypted = PlaintextFactory::MakePlaintext(
        ciphertext->GetEncodingType(), vp,
        privateKey->GetCryptoContext()->GetEncodingParams());

    // DecryptResult result = ScaleAndRound(
    //     b, &decrypted->GetElement<NativePoly>(),
    //     std::static_pointer_cast<CryptoParametersBFVRNSSFDK>(
    //         privateKey->GetCryptoParameters()));

    decrypted->Decode();
    Plaintext xplaintext = PlaintextFactory::MakePlaintext(
        decrypted->GetPackedValue(), ciphertext->GetEncodingType(),
        privateKey->GetCryptoContext()->GetElementParams(),
        privateKey->GetCryptoContext()->GetEncodingParams(),
        privateKey->GetCryptoContext()->getSchemeId());
    DCRTPoly ptxt = xplaintext->GetElement<DCRTPoly>();

    //----------------------------------------------------------------------------------
    // Multiply Plaintext
    //----------------------------------------------------------------------------------
    std::vector<NativeInteger> tInvModq = cryptoParams->GettInvModq();
    const NativeInteger t = cryptoParams->GetPlaintextModulus();
    NativeInteger NegQModt = cryptoParams->GetNegQModt(0);
    NativeInteger NegQModtPrecon = cryptoParams->GetNegQModtPrecon(0);

    ptxt.SetFormat(Format::COEFFICIENT);
    ptxt.TimesQovert(ptxt.GetParams(), tInvModq, t, NegQModt, NegQModtPrecon);
    //ptxt.SetFormat(Format::EVALUATION);

    b -= ptxt;
  }
  DCRTPoly error = DivideApproxBySQRootOfNorm(b, scale);
  error.SetFormat(Format::EVALUATION);

  // Create the Zero ciphertext with th especififed error
  const Matrix<DCRTPoly> &p0 = publicKey->GetLargePublicElements().at(0);
  const Matrix<DCRTPoly> &p1 = publicKey->GetLargePublicElements().at(1);
  const DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();
  auto zero_alloc = DCRTPoly::Allocator(elementParams, EVALUATION);
  auto gaussian_alloc = DCRTPoly::MakeDiscreteGaussianCoefficientAllocator(
      elementParams, Format::COEFFICIENT, dgg.GetStd());
  // u = Matrix<DCRTPoly>([&](){DCRTPoly(dgg, elementParams,
  // Format::EVALUATION);}, p0.GetData()[0].size(), 1);
  Matrix<DCRTPoly> u(zero_alloc, p0.GetData()[0].size(), 1, gaussian_alloc);
  DCRTPoly c0(elementParams);
  DCRTPoly c1(elementParams);
  u.SetFormat(Format::EVALUATION);

  Matrix<DCRTPoly> base(zero_alloc, 1, p0.GetData()[0].size());
  // DCRTPoly b(elementParams, Format::EVALUATION, true, elementParams->GetK());
  base -= (p1 * s);

  c1 = SdfkUtils::dotProd(p1, u);
  c0 = SdfkUtils::dotProd(base, u);
  c0 -= error;

  newCiphertext->SetElements({std::move(c0), std::move(c1)});

  return newCiphertext;
}

DCRTPoly ModLShift(DCRTPoly e, usint bits) {
  BigInteger a(1);
  a.LShiftEq(bits);
  e.SetFormat(Format::EVALUATION);
  return a * e;
}

Ciphertext<DCRTPoly> lbcrypto::SFDKBFVRNS::ScaleByBits(
    ConstCiphertext<DCRTPoly> ciphertext, usint bits) const {
  Ciphertext<DCRTPoly> newCiphertext = ciphertext->CloneEmpty();
  // newCiphertext->SetDepth(ciphertext->GetDepth());

  const std::vector<DCRTPoly> &cipherTextElements = ciphertext->GetElements();

  std::vector<DCRTPoly> c(cipherTextElements.size());

  for (size_t i = 0; i < cipherTextElements.size(); i++) {
    c[i] = ModLShift(cipherTextElements[i], bits);
    c[i].SetFormat(Format::EVALUATION);
  }

  newCiphertext->SetElements(std::move(c));

  return newCiphertext;
}

DCRTPoly lbcrypto::SFDKBFVRNS::GetDecryptionError(
    const PrivateKey<DCRTPoly> privateKey, Ciphertext<DCRTPoly> &ciphertext,
    Plaintext plaintext) const {
  auto cryptoParams = std::static_pointer_cast<CryptoParametersBFVRNSSFDK>(
      privateKey->GetCryptoParameters());
  //const std::vector<DCRTPoly>& cv = ciphertext->GetElements();
  DCRTPoly b                      = privateKey->GetCryptoContext()->GetScheme()->DecryptCore(ciphertext, privateKey);
  DCRTPoly ptxt;
  if(plaintext==NULL) {
    Plaintext decrypted ;
    privateKey->GetCryptoContext()->Decrypt(ciphertext,privateKey,&decrypted);
    Plaintext xplaintext = PlaintextFactory::MakePlaintext(decrypted->GetPackedValue(),ciphertext->GetEncodingType(), privateKey->GetCryptoContext()->GetElementParams(), privateKey->GetCryptoContext()->GetEncodingParams());
    ptxt = xplaintext->GetElement<DCRTPoly>();
  } else {
    ptxt = plaintext->GetElement<DCRTPoly>();
  }


  //----------------------------------------------------------------------------------
  // Multiply Plaintext
  //----------------------------------------------------------------------------------
  std::vector<NativeInteger> tInvModq = cryptoParams->GettInvModq();
  const NativeInteger t = cryptoParams->GetPlaintextModulus();
  NativeInteger NegQModt = cryptoParams->GetNegQModt(0);
  NativeInteger NegQModtPrecon = cryptoParams->GetNegQModtPrecon(0);

  b.SetFormat(Format::COEFFICIENT);
  ptxt.SetFormat(Format::COEFFICIENT);
  ptxt.TimesQovert(ptxt.GetParams(), tInvModq, t, NegQModt, NegQModtPrecon);

  auto error = b - ptxt;
  return error;

} 
/*
DCRTPoly lbcrypto::SFDKBFVRNS::GetDecryptionError(
    const PrivateKey<DCRTPoly> privateKey, Ciphertext<DCRTPoly> &ciphertext,
    Plaintext plaintext) const {
  auto cryptoParams = std::static_pointer_cast<CryptoParametersBFVRNSSFDK>(
      privateKey->GetCryptoParameters());

  const std::vector<DCRTPoly> &c = ciphertext->GetElements();
  const DCRTPoly &s = privateKey->GetPrivateElement();
  DCRTPoly sPower = s;

  DCRTPoly b = c[0];
  b.SetFormat(Format::EVALUATION);

  DCRTPoly cTemp;
  for (size_t i = 1; i < c.size(); i++) {
    cTemp = c[i];
    cTemp.SetFormat(Format::EVALUATION);

    b += sPower * cTemp;
    sPower *= s;
  }

  DCRTPoly ptxt;
  // Converts back to coefficient representation
  // b.SetFormat(Format::COEFFICIENT);
  if (plaintext == NULL) {
    b.SwitchFormat();

    auto vp = std::make_shared<typename NativePoly::Params>(
        ciphertext->GetElements()[0].GetParams()->GetCyclotomicOrder(),
        privateKey->GetCryptoContext()
            ->GetEncodingParams()
            ->GetPlaintextModulus(),
        1);
    Plaintext decrypted = PlaintextFactory::MakePlaintext(
        ciphertext->GetEncodingType(), vp,
        privateKey->GetCryptoContext()->GetEncodingParams());

    // DecryptResult result = ScaleAndRound(
    //     b, &decrypted->GetElement<NativePoly>(),
    //     std::static_pointer_cast<LPCryptoParametersBFVrns<DCRTPoly>>(
    //         privateKey->GetCryptoParameters()));

    decrypted->Decode();
    Plaintext xplaintext = PlaintextFactory::MakePlaintext(
        decrypted->GetPackedValue(), ciphertext->GetEncodingType(),
        privateKey->GetCryptoContext()->GetElementParams(),
        privateKey->GetCryptoContext()->GetEncodingParams(),
        privateKey->GetCryptoContext()->getSchemeId());
    ptxt = xplaintext->GetElement<DCRTPoly>();
    b.SwitchFormat();
  } else {
    ptxt = plaintext->GetElement<DCRTPoly>();
  }

  //----------------------------------------------------------------------------------
  // Multiply Plaintext
  //----------------------------------------------------------------------------------
  std::vector<NativeInteger> tInvModq = cryptoParams->GettInvModq();
  const NativeInteger t = cryptoParams->GetPlaintextModulus();
  NativeInteger NegQModt = cryptoParams->GetNegQModt(0);
  NativeInteger NegQModtPrecon = cryptoParams->GetNegQModtPrecon(0);

  ptxt.SetFormat(Format::COEFFICIENT);
  ptxt.TimesQovert(ptxt.GetParams(), tInvModq, t, NegQModt, NegQModtPrecon);
  ptxt.SetFormat(Format::EVALUATION);

  auto error = b - ptxt;
  error.SetFormat(Format::COEFFICIENT);
  return error;
}

*/
}  // namespace lbcrypto