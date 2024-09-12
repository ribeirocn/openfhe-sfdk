FROM ubuntu:20.04

ARG fherepository="openfhe-development"
ARG sfdkrepository="openfhe-sfdk"
ARG fhebranch=main
ARG sfdkbranch=main
#ARG fhetag=v0.9.1
ARG CC_param=/usr/bin/gcc-10
ARG CXX_param=/usr/bin/g++-10
ARG no_threads=4

ENV DEBIAN_FRONTEND=noninteractive
ENV CC=$CC_param
ENV CXX=$CXX_para

#install pre-requisites for OpenFHE
RUN apt update && apt install -y git \
                                 build-essential \
                                 gcc-10 \
                                 g++-10 \
                                 cmake \
                                 autoconf \
                                 clang-10 \
                                 libomp5 \
                                 libomp-dev \
                                 doxygen \
                                 graphviz \
                                 libboost-all-dev=1.71.0.0ubuntu2

RUN apt-get clean && rm -rf /var/lib/apt/lists/*

#git clone the openfhe-development repository and its submodules (this always clones the most latest commit)
RUN git clone https://github.com/openfheorg/$fherepository.git && cd $fherepository && git checkout $fhebranch && git submodule sync --recursive && git submodule update --init  --recursive

#installing OpenFHE and running tests
RUN mkdir /$fherepository/build && cd /$fherepository/build && cmake .. && make -j $no_threads && make install && make testall

#git clone the openfhe-development repository and its submodules (this always clones the most latest commit)
RUN git clone https://github.com/ribeirocn/$sfdkrepository.git && cd $sfdkrepository && git checkout $sfdkbranch

#installing OpenFHE and running tests
#RUN mkdir /$sfdkrepository/build && cd /$sfdkrepository/build && cmake .. && make -j $no_threads && make install