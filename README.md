Experimental Repository for 
Single-use Function Decryption Key for the PALISADE Library
=====================================

This library extends BFVrns from PALISADE

It adds two primitives
  * One-Time-Key Decryption
  * Private Set Membership Test
  
Check example
  * src/examples/simple-integers.cpp

Run Benchmark
  * benchmark/src/lib-benchmark



Build Instructions
=====================================
This repository has been tested to run with PALISADE development release 1.11.

* Install PALISADE from that release on your system. Full instructions
  for this are to be found in the `README.md` file in the PALISADE
  repo.

Run `make install` at the end to install the system to the default
location (you can change this location, but then you will have to
change the Makefile in this repo to reflect the new location).

Note you may have to execute the following on your system to
automatically find the installed libraries and include files:

> `sudo ldconfig`

  found in that repo. 

* Clone this repo on your system 

We use CMake to build abe. The high-level (platform-independent)
procedure for building PALISADE is as follows (for OS-specific
instructions, see the section "Detailed information about building
PALISADE" at the bottom of this page). Note PALISADE has similar
requirements, so if that builds on your system you are all set :

* Install system prerequisites (if not already installed), including a
  C++ compiler with OMP support, cmake, make, and autoconf.

* Create a directory where the binaries will be built. The typical choice is a subfolder "build". In this case, the commands are:
```
mkdir build
cd build
cmake ..
```

Note that CMake will check for any system dependencies that are needed
for the build process. If the CMake build does not complete
successfully, please review the error CMake shows at the end. If the
error does not go away (even though you installed the dependency), try
running "make clean" to clear the CMake cache.

In MacOS you may need to use the followin cmake flags
```
cmake .. -DCMAKE_CROSSCOMPILING=1 -DRUN_HAVE_STD_REGEX=0 -DRUN_HAVE_POSIX_REGEX=0
```

* Build the executables by running the following command (this will take few minutes; using the -j make command-line flag is suggested to speed up the build)
```
make
```
If you want to build only library files or some other subset of abe, please review the last paragraph of this page.

After the "make" completes, you should see the abe library file in the lib folder, binaries of examples in bin/examples and binaries for unit tests in the bin/unittest folder.

* Optionally, the library, `PALISADEsfdk`, can be installed.
```bash
make install
```
**Note** - The default installation path is `/usr/local/` and likely requires admin priviledges.

If this library is installed it must be found uniquely but with Palisade as well. See [CMakeLists.Users.txt](CMakeLists.User.txt) for how to use this library.

Testing and cleaning the build
-------------------

Run unit tests to make sure all capabilities operate as expected
```
make testsfdk
```

Run sample code to test, e.g.,
```
bin/examples/sfdk
```

Run benchmark to test the performance on your computer
```

bin/benchmark/lib-benchmark
```

To remove the files built by make, you can execute
```
make clean
```
