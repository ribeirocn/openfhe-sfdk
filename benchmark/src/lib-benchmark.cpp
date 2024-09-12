/*
 * @file lib-benchmark : library benchmark routines for comparison by build
 * @author Carlos Ribeiro
 *
 *
 */

/*
 * This file benchmarks a small number of operations in order to exercise large
 * pieces of the library
 */

#define PROFILE
#define _USE_MATH_DEFINES
#include "benchmark/benchmark.h"

#include <fstream>
#include <iostream>
#include <iterator>
#include <limits>
#include <random>

#include "pke/openfhe.h"

//#include "pke/cryptocontextgen.h"
//#include "pke/cryptocontexthelper.h"
#include "cryptocontext-sfdk.h"

#include "core/utils/debug.h"

using namespace std;
using namespace lbcrypto;

/*
 * Context setup utility methods
 */

uint GetPSMDepth(uint p) {
    uint depth = 0;
    for(uint mask=1;mask<=p; mask <<= 1){
      depth++;
      if((mask&p)>0) depth++;
    }
    return depth-1;
}

CryptoContextSFDK<DCRTPoly> GenerateBFVrnsSFDKContext(uint32_t _depth = 1) {

// Set the main parameters
  //int plaintextModulus = 65537;
  //double sigma = 3.2;
  //SecurityLevel securityLevel = HEStd_128_classic;
  //uint32_t depth = _depth;

  CCParams<CryptoContextBFVRNSSFDK> parameters;
  parameters.SetPlaintextModulus(65537);
  parameters.SetMultiplicativeDepth(_depth);
  parameters.SetBase(4194304);

  CryptoContextSFDK<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
  

  // Instantiate the crypto context
  //CryptoContextSFDK<DCRTPoly> cryptoContext =
  //    CryptoContextFactorySFDK<DCRTPoly>::genCryptoContextBFVrnsSFDK(
  //        plaintextModulus, securityLevel, sigma, 0, depth, 0, RLWE, 2, 0, 44, 0, 4194304);

  // Enable features that you wish to use
  cryptoContext->Enable(PKE);
  cryptoContext->Enable(KEYSWITCH);
  cryptoContext->Enable(LEVELEDSHE);
  cryptoContext->Enable(SFDK);

  return cryptoContext;
}


/*
 * BFVrns benchmarks
 */

void BFVrnsSFDK_KeyGen(benchmark::State &state) {
  CryptoContextSFDK<DCRTPoly> cryptoContext = GenerateBFVrnsSFDKContext();

  KeyPairSFDK<DCRTPoly> keyPair;

  while (state.KeepRunning()) {
    keyPair = cryptoContext->KeyGenSFDK();
  }
}

BENCHMARK(BFVrnsSFDK_KeyGen)->Unit(benchmark::kMicrosecond);

void BFVrnsSFDK_MultKeyGen(benchmark::State &state) {
  CryptoContextSFDK<DCRTPoly> cc = GenerateBFVrnsSFDKContext();

  KeyPairSFDK<DCRTPoly> keyPair;
  keyPair = cc->KeyGenSFDK();

  while (state.KeepRunning()) {
    cc->EvalMultKeyGen(keyPair.secretKey);
  }
}

BENCHMARK(BFVrnsSFDK_MultKeyGen)->Unit(benchmark::kMicrosecond);

void BFVrnsSFDK_EvalAtIndexKeyGen(benchmark::State &state) {
  CryptoContextSFDK<DCRTPoly> cc = GenerateBFVrnsSFDKContext();

  KeyPairSFDK<DCRTPoly> keyPair;
  keyPair = cc->KeyGenSFDK();

  std::vector<int32_t> indexList(1);
  for (usint i = 0; i < 1; i++) {
    indexList[i] = 1;
  }

  while (state.KeepRunning()) {
    cc->EvalAtIndexKeyGen(keyPair.secretKey, indexList);
  }
}

BENCHMARK(BFVrnsSFDK_EvalAtIndexKeyGen)->Unit(benchmark::kMicrosecond);

void BFVrnsSFDK_Encryption(benchmark::State &state) {
  CryptoContextSFDK<DCRTPoly> cryptoContext = GenerateBFVrnsSFDKContext();

  KeyPairSFDK<DCRTPoly> keyPair = cryptoContext->KeyGenSFDK();

  std::vector<int64_t> vectorOfInts1 = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
  Plaintext plaintext1 = cryptoContext->MakePackedPlaintext(vectorOfInts1);

  while (state.KeepRunning()) {
    auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
  }
}

BENCHMARK(BFVrnsSFDK_Encryption)->Unit(benchmark::kMicrosecond);

void BFVrnsSFDK_Decryption(benchmark::State &state) {
  CryptoContextSFDK<DCRTPoly> cryptoContext = GenerateBFVrnsSFDKContext();

  KeyPairSFDK<DCRTPoly> keyPair = cryptoContext->KeyGenSFDK();

  std::vector<int64_t> vectorOfInts1 = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
  Plaintext plaintext1 = cryptoContext->MakePackedPlaintext(vectorOfInts1);

  auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
  Plaintext plaintextDec1;

  while (state.KeepRunning()) {
    cryptoContext->Decrypt(keyPair.secretKey, ciphertext1, &plaintextDec1);
  }
}

BENCHMARK(BFVrnsSFDK_Decryption)->Unit(benchmark::kMicrosecond);

void BFVrnsSFDK_Add(benchmark::State &state) {
  ofstream myfile;
  myfile.open ("/Users/carlosribeiro/example.txt");
  myfile << "Writing this to a file.\n";
  myfile.close();
  CryptoContextSFDK<DCRTPoly> cc = GenerateBFVrnsSFDKContext();

  KeyPairSFDK<DCRTPoly> keyPair = cc->KeyGenSFDK();

  std::vector<int64_t> vectorOfInts1 = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
  std::vector<int64_t> vectorOfInts2 = {0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1};

  auto plaintext1 = cc->MakePackedPlaintext(vectorOfInts1);
  auto plaintext2 = cc->MakePackedPlaintext(vectorOfInts2);



  auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);
  auto ciphertext2 = cc->Encrypt(keyPair.publicKey, plaintext2);

  while (state.KeepRunning()) {
    auto ciphertextAdd = cc->EvalAdd(ciphertext1, ciphertext2);
  }
}

BENCHMARK(BFVrnsSFDK_Add)->Unit(benchmark::kMicrosecond);

void BFVrnsSFDK_AddInPlace(benchmark::State &state) {
  CryptoContextSFDK<DCRTPoly> cc = GenerateBFVrnsSFDKContext();

  KeyPairSFDK<DCRTPoly> keyPair = cc->KeyGenSFDK();

  std::vector<int64_t> vectorOfInts1 = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
  std::vector<int64_t> vectorOfInts2 = {0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1};

  auto plaintext1 = cc->MakePackedPlaintext(vectorOfInts1);
  auto plaintext2 = cc->MakePackedPlaintext(vectorOfInts2);

  auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);
  auto ciphertext2 = cc->Encrypt(keyPair.publicKey, plaintext2);

  while (state.KeepRunning()) {
    cc->EvalAddInPlace(ciphertext1, ciphertext2);
  }
}

BENCHMARK(BFVrnsSFDK_AddInPlace)->Unit(benchmark::kMicrosecond);

void BFVrnsSFDK_MultNoRelin(benchmark::State &state) {
  CryptoContextSFDK<DCRTPoly> cryptoContext = GenerateBFVrnsSFDKContext();

  KeyPairSFDK<DCRTPoly> keyPair = cryptoContext->KeyGenSFDK();

  std::vector<int64_t> vectorOfInts1 = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
  Plaintext plaintext1 = cryptoContext->MakePackedPlaintext(vectorOfInts1);

  std::vector<int64_t> vectorOfInts2 = {1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0};
  Plaintext plaintext2 = cryptoContext->MakePackedPlaintext(vectorOfInts2);

  auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
  auto ciphertext2 = cryptoContext->Encrypt(keyPair.publicKey, plaintext2);

  while (state.KeepRunning()) {
    auto ciphertextMul =
        cryptoContext->EvalMultNoRelin(ciphertext1, ciphertext2);
  }
}

BENCHMARK(BFVrnsSFDK_MultNoRelin)->Unit(benchmark::kMicrosecond);

void BFVrnsSFDK_MultRelin(benchmark::State &state) {
  CryptoContextSFDK<DCRTPoly> cryptoContext = GenerateBFVrnsSFDKContext();

  KeyPairSFDK<DCRTPoly> keyPair = cryptoContext->KeyGenSFDK();
  cryptoContext->EvalMultKeyGen(keyPair.secretKey);

  std::vector<int64_t> vectorOfInts1 = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
  Plaintext plaintext1 = cryptoContext->MakePackedPlaintext(vectorOfInts1);

  std::vector<int64_t> vectorOfInts2 = {1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0};
  Plaintext plaintext2 = cryptoContext->MakePackedPlaintext(vectorOfInts2);

  auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
  auto ciphertext2 = cryptoContext->Encrypt(keyPair.publicKey, plaintext2);

  while (state.KeepRunning()) {
    auto ciphertextMul = cryptoContext->EvalMult(ciphertext1, ciphertext2);
  }
}

BENCHMARK(BFVrnsSFDK_MultRelin)->Unit(benchmark::kMicrosecond);

void BFVrnsSFDK_EvalAtIndex(benchmark::State &state) {
  CryptoContextSFDK<DCRTPoly> cc = GenerateBFVrnsSFDKContext();

  KeyPairSFDK<DCRTPoly> keyPair = cc->KeyGenSFDK();
  cc->EvalMultKeyGen(keyPair.secretKey);

  std::vector<int32_t> indexList(1);
  for (usint i = 0; i < 1; i++) {
    indexList[i] = 1;
  }

  cc->EvalAtIndexKeyGen(keyPair.secretKey, indexList);

  std::vector<int64_t> vectorOfInts1 = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
  std::vector<int64_t> vectorOfInts2 = {0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1};

  auto plaintext1 = cc->MakePackedPlaintext(vectorOfInts1);
  auto plaintext2 = cc->MakePackedPlaintext(vectorOfInts2);

  auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);
  auto ciphertext2 = cc->Encrypt(keyPair.publicKey, plaintext2);

  auto ciphertextMul = cc->EvalMult(ciphertext1, ciphertext2);

  while (state.KeepRunning()) {
    auto ciphertext3 = cc->EvalAtIndex(ciphertextMul, 1);
  }
}

BENCHMARK(BFVrnsSFDK_EvalAtIndex)->Unit(benchmark::kMicrosecond);

void BFVrnsSFDK_sfdkKeyGen(benchmark::State &state) {
  CryptoContextSFDK<DCRTPoly> cryptoContext = GenerateBFVrnsSFDKContext();

  KeyPairSFDK<DCRTPoly> keyPair = cryptoContext->KeyGenSFDK();

  std::vector<int64_t> vectorOfInts1 = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
  Plaintext plaintext1 = cryptoContext->MakePackedPlaintext(vectorOfInts1);

  auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);

  while (state.KeepRunning()) {
    cryptoContext->GenDecKeyFor(ciphertext1,  keyPair.cipherKeyGen, keyPair.publicKey);
  }
}

BENCHMARK(BFVrnsSFDK_sfdkKeyGen)->Unit(benchmark::kMicrosecond);

void BFVrnsSFDK_sfdkDecrypt(benchmark::State &state) {
  CryptoContextSFDK<DCRTPoly> cryptoContext = GenerateBFVrnsSFDKContext();

  KeyPairSFDK<DCRTPoly> keyPair = cryptoContext->KeyGenSFDK();

  std::vector<int64_t> vectorOfInts1 = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
  Plaintext plaintext1 = cryptoContext->MakePackedPlaintext(vectorOfInts1);

  auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
  Plaintext plaintextDec1;

  auto cipherKey = cryptoContext->GenDecKeyFor(ciphertext1,  keyPair.cipherKeyGen, keyPair.publicKey);
  while (state.KeepRunning()) {
    cryptoContext->DecryptSFDK(ciphertext1, cipherKey, keyPair.publicKey, &plaintextDec1);
  }
}

BENCHMARK(BFVrnsSFDK_sfdkDecrypt)->Unit(benchmark::kMicrosecond);

void BFVrnsSFDK_psm(benchmark::State &state) {
  CryptoContextSFDK<DCRTPoly> cryptoContext = GenerateBFVrnsSFDKContext(16);
  KeyPairSFDK<DCRTPoly> keyPair = cryptoContext->KeyGenSFDK();
  
  cryptoContext->EvalMultKeyGen(keyPair.secretKey);

  std::vector<int64_t> testset = {1,2,3,4,5,6,7,8, 9};
  cryptoContext->PreparePSM(keyPair.secretKey, testset.size());

  std::vector<int64_t> vectorOfInts2 = {8};
  Plaintext plaintext2 = cryptoContext->MakePackedPlaintext(vectorOfInts2);
  auto ciphertext2 = cryptoContext->Encrypt(keyPair.publicKey, plaintext2);

  while (state.KeepRunning()) {
    auto result = cryptoContext->PrivateSetMembership(ciphertext2, testset);
  }
}

BENCHMARK(BFVrnsSFDK_psm)->Unit(benchmark::kMicrosecond);

BENCHMARK_MAIN();
