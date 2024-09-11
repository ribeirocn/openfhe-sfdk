#ifndef SRC_SFDK_SFDKUTILS_H_
#define SRC_SFDK_SFDKUTILS_H_

#include "openfhe.h"

namespace lbcrypto {
class SdfkUtils  {
 public:

 static DCRTPoly dotProd(const Matrix<DCRTPoly> &_a, const Matrix<DCRTPoly> &_b) {
    std::vector<std::vector<DCRTPoly>> a = _a.GetData();
    std::vector<std::vector<DCRTPoly>> b = _b.GetData();
    if(a.size() == 0 || b.size() == 0) {
        OPENFHE_THROW(config_error,"First or Second DCRTPolys is empty");
    }

    DCRTPoly result = a[0][0]*b[0][0];
    if(a.size() == 1 && b.size() == 1) {
        if(a[0].size() != b[0].size()) {
            OPENFHE_THROW(config_error,"Vectors are not of the same size");
        }
        size_t size{a[0].size()};
#pragma omp parallel for // reduction(+:result) //num_threads(OpenFHEParallelControls.GetThreadLimit(size))        
        for(usint i=1; i<size; i++) {
            auto x = a[0][i]*b[0][i];
#pragma omp critical
            result += x;
        }
    } else if(a[0].size() == 1 && b[0].size() == 1) {
        if(a.size() != b.size()) {
            OPENFHE_THROW(config_error,"Vectors are not of the same size");
        }
        size_t size{a.size()};
#pragma omp parallel for //reduction(+:result) //num_threads(OpenFHEParallelControls.GetThreadLimit(size))
        for(usint i=1; i<size; i++) {
            auto x = a[i][0]*b[i][0];
#pragma omp critical
            result += x;
        }
    } else if(a.size() == 1 && b[0].size() == 1) {
        if(a[0].size() != b.size()) {
            OPENFHE_THROW(config_error,"Vectors are not of the same size");
        }
        size_t size{a[0].size()};
#pragma omp parallel for // reduction(+:result) //num_threads(OpenFHEParallelControls.GetThreadLimit(size))
        for(usint i=1; i<size; i++) {
            auto x = a[0][i]*b[i][0];
#pragma omp critical
            result += x;
        }
    } else if(a[0].size() == 1 && b.size() == 1) {
        if(a[0].size() != b.size()) {
            OPENFHE_THROW(config_error,"Vectors are not of the same size");
        }
        size_t size{a.size()};
#pragma omp parallel for // reduction(+:result) //num_threads(OpenFHEParallelControls.GetThreadLimit(size))
        for(usint i=1; i<size; i++) {
            auto x = a[i][0]*b[0][i];
#pragma omp critical
            result += x;
        }
    } else {
        OPENFHE_THROW(config_error,"First or Second DCRTPoly is not a vector");
    }

    return result;
 }
};
}
#endif // SRC_SFDK_SFDKUTILS_H_