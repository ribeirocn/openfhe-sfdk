cmake_minimum_required (VERSION 3.5.1)

find_program(CCACHE_PROGRAM ccache)
if(CCACHE_PROGRAM)
    set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE "${CCACHE_PROGRAM}")
endif()

project(OpenFHEsfdk CXX)

# this version will get incremented only if new changes are made in this repo
set(SFDK_VERSION_MAJOR 0)
set(SFDK_VERSION_MINOR 1)
set(SFDK_VERSION_PATCH 0)
set(SFDK_VERSION ${SFDK_VERSION_MAJOR}.${SFDK_VERSION_MINOR}.${SFDK_VERSION_PATCH})

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

find_package(OpenFHE 1.2.0 REQUIRED)

set( CMAKE_CXX_FLAGS ${OpenFHE_CXX_FLAGS} )
set( CMAKE_EXE_LINKER_FLAGS ${OpenFHE_EXE_LINKER_FLAGS} )

include_directories( ${OPENMP_INCLUDES} )
include_directories( ${OpenFHE_INCLUDE} )
include_directories( ${OpenFHE_INCLUDE}/third-party/include )
include_directories( ${OpenFHE_INCLUDE}/core )
include_directories( ${OpenFHE_INCLUDE}/pke )
include_directories( ${OpenFHE_INCLUDE}/binfhe )

#--------------------------------------------------------------------
# Compiler logic
#--------------------------------------------------------------------
if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    # require at least gcc 6.1
    if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS 6.1)
        message(WARNING "GCC version should be at least 6.1.")
    endif()
elseif ("${CMAKE_CXX_COMPILER_ID}" MATCHES "Clang")
    # require at least clang 6
    if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS 6)
        message(WARNING "Clang version should be at least 6.")
    endif()
else()
	message(WARNING "You are using ${CMAKE_CXX_COMPILER_ID} version ${CMAKE_CXX_COMPILER_VERSION}, which is unsupported.")
endif()

# use, i.e. don't skip the full RPATH for the build tree
set(CMAKE_SKIP_BUILD_RPATH  FALSE)

# when building, don't use the install RPATH already
# (but later on when installing)
set(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)

set(CMAKE_INSTALL_RPATH "${LIBINSTALL}")

# add the automatically determined parts of the RPATH
# which point to directories outside the build tree to the install RPATH
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

# the RPATH to be used when installing, but only if it's not a system directory
LIST(FIND CMAKE_PLATFORM_IMPLICIT_LINK_DIRECTORIES "${LIBINSTALL}" isSystemDir)
if("${isSystemDir}" STREQUAL "-1")
   set(CMAKE_INSTALL_RPATH "${LIBINSTALL}")
endif("${isSystemDir}" STREQUAL "-1")

# Compiler flags

# Added -Wno-parentheses for compatibility with g++
if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    set (IGNORE_WARNINGS "-Wno-parentheses")
    # we can use GNU built-in functions provided by GCC for debugging. ex: __builtin_LINE (), __builtin_FUNCTION (), __builtin_FILE ()
    add_definitions(-DBUILTIN_INFO_AVAILABLE)
    message (STATUS "BUILTIN_INFO_AVAILABLE is defined")
endif()

if("${CMAKE_CXX_COMPILER_ID}" MATCHES "Clang")
	set(IGNORE_WARNINGS "${IGNORE_WARNINGS} -Wno-unused-private-field -Wno-shift-op-parentheses")
endif()

set(C_COMPILE_FLAGS "-Wall -Werror -O3 ")
set(CXX_COMPILE_FLAGS "-Wall -Werror -O3 ${NATIVE_OPT} ${IGNORE_WARNINGS}")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${C_COMPILE_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CXX_COMPILE_FLAGS}")

#--------------------------------------------------------------------
# Installation logic
#--------------------------------------------------------------------
set(INSTALL_LIB_DIR lib CACHE PATH
	"Installation directory for libraries")
set(INSTALL_INCLUDE_DIR include/OpenFHE-sfdk CACHE PATH
	"Installation directory for headers")
if(WIN32 AND NOT CYGWIN)
  set(DEF_INSTALL_CMAKE_DIR CMake)
else()
  set(DEF_INSTALL_CMAKE_DIR lib/OpenFHEsfdk)
endif()
set(INSTALL_CMAKE_DIR ${DEF_INSTALL_CMAKE_DIR} CACHE PATH
  "Installation directory for CMake files")

foreach(p LIB INCLUDE CMAKE)
  set(var INSTALL_${p}_DIR)
  if(NOT IS_ABSOLUTE "${${var}}")
    set(${var} "${CMAKE_INSTALL_PREFIX}/${${var}}")
  endif()
endforeach()

message("***** INSTALL IS AT ${CMAKE_INSTALL_PREFIX}; to change, run cmake with -DCMAKE_INSTALL_PREFIX=/your/path")
set (CMAKE_INSTALL_MESSAGE LAZY)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

#--------------------------------------------------------------------
# Machine-specific checks
#--------------------------------------------------------------------
# determine the architecture on a Linux/Unix/macOS/MinGW system
if(CMAKE_HOST_UNIX OR MINGW)
  EXECUTE_PROCESS( COMMAND uname -m COMMAND tr -d '\n' OUTPUT_VARIABLE ARCHITECTURE )
else()
  set(ARCHITECTURE "unknown")
endif()

if(ARCHITECTURE)
  message(STATUS "Architecture is " ${ARCHITECTURE})
endif()

# third party directories

include_directories( third-party/google-test/googletest third-party/google-test/googletest/include )

### add directories for other OpenFHE modules

link_directories( ${OpenFHE_LIBDIR} )
link_directories( ${OPENMP_LIBRARIES} )
link_libraries( ${OpenFHE_LIBRARIES} )
message(STATUS "OpenFHE_LIBRARIES found: ${OpenFHE_LIBRARIES}")

option( BUILD_UNITTESTS "Set to ON to build unit tests for the library" ON)
option( BUILD_EXAMPLES "Set to ON to build examples for the library" ON)
option( GIT_SUBMOD_AUTO "Submodules auto-update" ON)

message( STATUS "BUILD_UNITTESTS:  ${BUILD_UNITTESTS}")
message( STATUS "BUILD_EXAMPLES:   ${BUILD_EXAMPLES}")
message( STATUS "GIT_SUBMOD_AUTO:  ${GIT_SUBMOD_AUTO}")

message("***** INSTALL IS AT ${CMAKE_INSTALL_PREFIX}; to change, run cmake with -DCMAKE_INSTALL_PREFIX=/your/path")
set (CMAKE_INSTALL_MESSAGE LAZY)



# when running "make clean", additionally deletes the CMake cache file
set(ADDITIONAL_CLEAN_FILES "")
LIST(APPEND ADDITIONAL_CLEAN_FILES ${CMAKE_CURRENT_BINARY_DIR}/CMakeCache.txt)

# Add the additional "make clean" files
GET_DIRECTORY_PROPERTY(clean_files ADDITIONAL_CLEAN_FILES)
LIST(APPEND            clean_files ${ADDITIONAL_CLEAN_FILES})
LIST(REMOVE_DUPLICATES clean_files)
LIST(REMOVE_ITEM       clean_files "")
SET_DIRECTORY_PROPERTIES(PROPERTIES ADDITIONAL_CLEAN_FILES "${clean_files}")
message(STATUS "clean files ${clean_files}")

add_subdirectory(src/sfdk)

# auto-update git submodules
find_package (Git REQUIRED)
if(GIT_SUBMOD_AUTO AND EXISTS "${PROJECT_SOURCE_DIR}/.git")
    # Update submodules as needed
    message(STATUS "Submodule update")
    if(NOT GIT_SUBMODULE_SYNCED)
        # "git submodule sync --recursive" should run only once, when CMakeCache.txt doesn't exist'
        execute_process(COMMAND ${GIT_EXECUTABLE} submodule sync --recursive
                WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
                RESULT_VARIABLE GIT_SUBMODULE_RESULT)
        if(NOT GIT_SUBMODULE_RESULT EQUAL "0")
            message(FATAL_ERROR "\"git submodule sync --recursive\" failed with ${GIT_SUBMODULE_RESULT}, please checkout submodules")
        endif()
    endif()

    execute_process(COMMAND ${GIT_EXECUTABLE} submodule update --init --recursive
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
            RESULT_VARIABLE GIT_SUBMODULE_RESULT)
    if(NOT GIT_SUBMODULE_RESULT EQUAL "0")
        if(NOT GIT_SUBMODULE_SYNCED)
            # print this message only if update has never happened
            message(FATAL_ERROR "\"git submodule update --init\" failed with ${GIT_SUBMODULE_RESULT}, please checkout submodules")
        else()
            message(SEND_ERROR "\"git submodule update --init\" failed with ${GIT_SUBMODULE_RESULT}, please checkout submodules or disable autoupdate with -DGIT_SUBMOD_AUTO=OFF")
        endif()
    endif()

    if(NOT GIT_SUBMODULE_SYNCED)
        set(GIT_SUBMODULE_SYNCED ON CACHE BOOL "" FORCE)
    endif()
endif()

#--------------------------------------------------------------------
# Create OpenFHEsfdk package
#--------------------------------------------------------------------
set(SFDK_SHARED_LIBS "OpenFHEsfdk")
set(SFDK_PACKAGE_LIBS ${SFDK_SHARED_LIBS})

export(EXPORT OpenFHEsfdkTargets FILE "${PROJECT_BINARY_DIR}/OpenFHEsfdkTargets.cmake")

export(PACKAGE OpenFHEsfdk)

# Create the OpenFHEsfdkConfig.cmake and OpenFHEsfdkConfigVersion files
file(RELATIVE_PATH REL_INCLUDE_DIR "${INSTALL_CMAKE_DIR}"
   "${INSTALL_INCLUDE_DIR}")
# ... for the build tree
set(CONF_INCLUDE_DIRS "${PROJECT_SOURCE_DIR}" "${PROJECT_BINARY_DIR}")
configure_file(OpenFHEsfdkConfig.cmake.in
  "${PROJECT_BINARY_DIR}/OpenFHEsfdkConfig.cmake" @ONLY)
# ... for the install tree
set(CONF_INCLUDE_DIRS "\${OpenFHE_CMAKE_DIR}/${REL_INCLUDE_DIR}")
configure_file(OpenFHEsfdkConfig.cmake.in
  "${PROJECT_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/OpenFHEsfdkConfig.cmake" @ONLY)
# ... for both
configure_file(OpenFHEsfdkConfigVersion.cmake.in
  "${PROJECT_BINARY_DIR}/OpenFHEsfdkConfigVersion.cmake" @ONLY)

# Install the OpenFHEsfdkConfig.cmake and OpenFHEsfdkConfigVersion.cmake
install(FILES
  "${PROJECT_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/OpenFHEsfdkConfig.cmake"
  "${PROJECT_BINARY_DIR}/OpenFHEsfdkConfigVersion.cmake"
  DESTINATION "${INSTALL_CMAKE_DIR}" COMPONENT dev)

# Install the export set for use with the install-tree
install(EXPORT OpenFHEsfdkTargets DESTINATION
  "${INSTALL_CMAKE_DIR}" COMPONENT dev)


add_custom_target( allmodules DEPENDS ${OpenFHE_SHARED_LIBS} )


### build the google benchmark handlers (just the parts we need)
set(CMAKE_THREAD_LIBS_INIT "-lpthread")
set(CMAKE_HAVE_THREADS_LIBRARY 1)
set(CMAKE_USE_WIN32_THREADS_INIT 0)
set(CMAKE_USE_PTHREADS_INIT 1)
set(THREADS_PREFER_PTHREAD_FLAG ON)

#if ( BUILD_BENCHMARKS )
	set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "Enable testing of the benchmark library." FORCE)
	set(BENCHMARK_ENABLE_INSTALL OFF CACHE BOOL "Enable installation of benchmark. (Projects embedding benchmark may want to turn this OFF.)" FORCE)
	set(BENCHMARK_ENABLE_GTEST_TESTS OFF CACHE BOOL "Enable building the unit tests which depend on gtest" FORCE)
	#add_subdirectory(third-party/google-benchmark EXCLUDE_FROM_ALL)
	add_subdirectory(third-party/google-benchmark)
  add_subdirectory(benchmark)
#endif()
