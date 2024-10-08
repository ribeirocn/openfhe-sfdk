// @file
// @author Carlos Ribeiro
//

#include <iostream>
#include <vector>
#include "gtest/gtest.h"

#include "cryptocontext-sfdk.h"


#include "encoding/encodings.h"

#include "utils/debug.h"

using namespace std;
using namespace lbcrypto;

class UTBFVrnsDecrypt
    : public ::testing::TestWithParam<std::tuple<usint, usint>> {
 protected:
  void SetUp() {}

  void TearDown() {
    CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
  }

 public:
};

/**
 * This function checks whether vectors of numbers a and b are equal.
 *
 * @param vectorSize The length of the two vectors.
 * @param failmsg Debug message to display upon failure.
 */
static void checkEquality(const std::vector<int64_t>& a,
                          const std::vector<int64_t>& b, int vectorSize,
                          const string& failmsg) {
  std::vector<usint> allTrue(vectorSize);
  std::vector<usint> tmp(vectorSize);
  for (int i = 0; i < vectorSize; i++) {
    allTrue[i] = 1;
    tmp[i] = (a[i] == b[i]);
  }
  EXPECT_TRUE(tmp == allTrue) << failmsg;
}

// static vector<usint> ptm_args{2, 65537, 5308417};
// static vector<usint> dcrtbit_args{30, 40, 50, 60};

TEST_P(UTBFVrnsDecrypt, BFVrns_Decrypt) {
  usint ptm = std::get<0>(GetParam());
  usint dcrtBits = std::get<1>(GetParam());


    CCParams<CryptoContextBFVRNSSFDK> parameters;
  parameters.SetPlaintextModulus(ptm);
  parameters.SetScalingModSize(dcrtBits);
  parameters.SetBase(2);

  CryptoContextSFDK<DCRTPoly> cc = GenCryptoContext(parameters);

  //double sigma = 3.19;

  //CryptoContextSFDK<DCRTPoly> cc =
  //    CryptoContextFactorySFDK<DCRTPoly>::genCryptoContextBFVrnsSFDK(
  //        ptm, HEStd_128_classic, sigma, 0, 0, 0, OPTIMIZED, 2, 0, dcrtBits);

  cc->Enable(PKE);
  cc->Enable(KEYSWITCH);
  cc->Enable(LEVELEDSHE);
  cc->Enable(SFDK);

  KeyPairSFDK kp = cc->KeyGenSFDK();

  usint vecsize = 8;
  std::vector<int64_t> vectorOfInts(8);
  for (usint i = 0; i < vecsize; ++i) {
    if (ptm == 2) {
      vectorOfInts[i] = rand() % ptm;
    } else {
      vectorOfInts[i] = (rand() % ptm) / 2;
    }
  }

  Plaintext plaintext;
  if (!(ptm & (ptm - 1)))
    plaintext = cc->MakeCoefPackedPlaintext(vectorOfInts);
  else
    plaintext = cc->MakePackedPlaintext(vectorOfInts);
  Plaintext result;
  Ciphertext<DCRTPoly> ciphertext = cc->Encrypt(kp.publicKey, plaintext);
  cc->Decrypt(kp.secretKey, ciphertext, &result);

  if (!(ptm & (ptm - 1))) {
    auto tmp_a = plaintext->GetCoefPackedValue();
    auto tmp_b = result->GetCoefPackedValue();
    checkEquality(tmp_a, tmp_b, vecsize, "BFVrns Decrypt fails");
  } else {
    auto tmp_a = plaintext->GetPackedValue();
    auto tmp_b = result->GetPackedValue();
    checkEquality(tmp_a, tmp_b, vecsize, "BFVrns Decrypt fails");
  }
}

/*
 * Our tuples are (t, qMSB)
 * sizeQMSB is small (1-2 bits)
 * We test several instanses:
 * - t is a power of two
 *   - (qMSB + sizeQMSB) <  52
 *     - (qMSB + tMSB + sizeQMSB) <  63   (A)
 *     - (qMSB + tMSB + sizeQMSB) >= 63   (B)
 *   - (qMSB + sizeQMSB) >= 52
 *     - (qMSBHf + tMSB + sizeQMSB) <  62 (C)
 *     - (qMSBHf + tMSB + sizeQMSB) >= 62 (D)
 * - t it not a power of two
 *   - (qMSB + sizeQMSB) <  52
 *     - (qMSB + tMSB + sizeQMSB) <  52   (E)
 *     - (qMSB + tMSB + sizeQMSB) >= 52   (F)
 *   - (qMSB + sizeQMSB) >= 52
 *     - (qMSBHf + tMSB + sizeQMSB) <  52 (G)
 *     - (qMSBHf + tMSB + sizeQMSB) >= 52 (H)
 *
 * log2(65537) = 16.00002
 * log2(5308417) = 22.34
 * log2(3221225473) = 31.58
 */
INSTANTIATE_TEST_SUITE_P(
    BFVrns_Decrypt, UTBFVrnsDecrypt,
    ::testing::Values(std::make_tuple(1 << 1, 30),        // A
                      std::make_tuple(1 << 15, 30),       // A
                      std::make_tuple(1 << 31, 30),       // A
                      std::make_tuple(1 << 1, 35),        // A
                      std::make_tuple(1 << 15, 35),       // A
                      std::make_tuple(1 << 31, 35),       // B
                      std::make_tuple(1 << 1, 40),        // A
                      std::make_tuple(1 << 15, 40),       // A
                      std::make_tuple(1 << 31, 40),       // B
                      std::make_tuple(1 << 1, 45),        // A
                      std::make_tuple(1 << 15, 45),       // A
                      std::make_tuple(1 << 31, 45),       // B
                      std::make_tuple(1 << 1, 50),        // A
                      std::make_tuple(1 << 15, 50),       // B
                      std::make_tuple(1 << 31, 50),       // B
                      std::make_tuple(1 << 1, 55),        // C
                      std::make_tuple(1 << 15, 55),       // C
                      std::make_tuple(1 << 31, 55),       // D
                      std::make_tuple(1 << 1, 60),        // C
                      std::make_tuple(1 << 15, 60),       // C
                      std::make_tuple(1 << 31, 60),       // D
                      std::make_tuple(65537, 30),         // E
                      std::make_tuple(5308417, 30),       // F
                      std::make_tuple(65537, 35),         // E
                      std::make_tuple(5308417, 35),       // F
                      std::make_tuple(3221225473, 35),    // F
                      std::make_tuple(65537, 40),         // F
                      std::make_tuple(5308417, 40),       // F
                      std::make_tuple(3221225473, 40),    // F
                      std::make_tuple(65537, 45),         // F
                      std::make_tuple(5308417, 45),       // F
                      std::make_tuple(3221225473, 45),    // F
                      std::make_tuple(65537, 50),         // F
                      std::make_tuple(5308417, 50),       // F
                      std::make_tuple(3221225473, 50),    // F
                      std::make_tuple(65537, 55),         // G
                      std::make_tuple(5308417, 55),       // G
                      std::make_tuple(3221225473, 55),    // H
                      std::make_tuple(65537, 60),         // G
                      std::make_tuple(5308417, 60),       // H
                      std::make_tuple(3221225473, 60)));  // H
