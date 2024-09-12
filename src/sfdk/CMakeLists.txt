#list all sources in this directory for the library (found in the lib subdirectory)
message(STATUS "CUR DIR " ${CMAKE_CURRENT_LIST_DIR})
file(GLOB SFDKLIB_SOURCES CONFIGURE_DEPENDS "lib/scheme/*/*.cpp")

include_directories(${CORE_INCLUDE_DIRS})
include_directories(${PKE_INCLUDE_DIRS})
list(APPEND SFDK_INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/include")
list(APPEND SFDK_INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/lib")
include_directories(${SFDK_INCLUDE_DIRS})

message(STATUS "LIB SOURCES ${SFDKLIB_SOURCES}")
add_library (sfdkobj OBJECT ${SFDKLIB_SOURCES})
add_dependencies(sfdkobj OPENFHEcore)
set_property(TARGET sfdkobj PROPERTY POSITION_INDEPENDENT_CODE 1)

add_library(OpenFHEsfdk SHARED $<TARGET_OBJECTS:sfdkobj>)
set_property(TARGET OpenFHEsfdk PROPERTY VERSION ${SFDK_VERSION})
set_property(TARGET OpenFHEsfdk PROPERTY SOVERSION ${SFDK_VERSION_MAJOR})
set_property(TARGET OpenFHEsfdk PROPERTY POSITION_INDEPENDENT_CODE 1)

#sets the local destination target for library output
#this creates the lib directory in build and puts OpenFHEsfdk there
#note without this we would build to build/src/lib
# this line is for non-Windows systems
set_property(TARGET OpenFHEsfdk PROPERTY LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
# this line is for Windows (MinGW) systems
set_property(TARGET OpenFHEsfdk PROPERTY RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

#these lines are needed for make install to work

install(
	TARGETS OpenFHEsfdk 
	EXPORT OpenFHEsfdkTargets 
	DESTINATION lib)
install(
	DIRECTORY include/
	DESTINATION include/OpenFHE-sfdk)

set (SFDKLIBS PUBLIC OpenFHEsfdk ${OpenFHE_LIBRARIES})

target_link_libraries (OpenFHEsfdk ${OpenFHE_LIBRARIES})

add_custom_target( allsfdk ) #special make target to make all sfdk files
add_dependencies( allsfdk OpenFHEsfdk) #add library to make allsfdk target

##########################################################
### now build all files in examples and put executables in bin/sfdk/examples
##########################################################

set (SFDKAPPS "")
if( BUILD_EXAMPLES ) #set during cmake with -D
  #for all src files in examples directory
  file (GLOB SFDK_EXAMPLES_SRC_FILES CONFIGURE_DEPENDS examples/*.cpp)
  foreach (app ${SFDK_EXAMPLES_SRC_FILES})
	get_filename_component ( exe ${app} NAME_WE )
	add_executable ( ${exe} ${app} )
	##this is out output directory under build
	set_property(TARGET ${exe} PROPERTY RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin/examples/sfdk)
	set( SFDKAPPS ${SFDKAPPS} ${exe} ) ##append this apname
	target_link_libraries ( ${exe} ${SFDKLIBS} )
	message(STATUS "************ ${SFDKLIBS} *************")
  endforeach()
  
  add_custom_target( allsfdkexamples ) #new make target
  add_dependencies( allsfdkexamples ${SFDKAPPS} ) #builds all example apps
  add_dependencies( allsfdk allsfdkexamples ) 
endif()

##########################################################
### now build unittests
##########################################################

if( BUILD_UNITTESTS )
	set(UNITTESTMAIN ${PROJECT_SOURCE_DIR}/test/Main_TestAll.cpp)

  file (GLOB SFDK_TEST_SRC_FILES CONFIGURE_DEPENDS unittest/*.cpp)
	add_executable (sfdk_tests ${SFDK_TEST_SRC_FILES} ${UNITTESTMAIN})
	set_property(TARGET sfdk_tests PROPERTY RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/unittest)
	target_link_libraries ( sfdk_tests ${SFDKLIBS} )
	if (NOT ${USE_OpenMP} )
		target_link_libraries ( sfdk_tests PRIVATE Threads::Threads)
	endif()
	add_dependencies( allsfdk sfdk_tests )

	add_custom_command( OUTPUT runsfdktests WORKING_DIRECTORY ${CMAKE_BINARY_DIR} COMMAND ${CMAKE_BINARY_DIR}/unittest/sfdk_tests )
	add_custom_target( testsfdk DEPENDS sfdk_tests runsfdktests )
endif()

add_custom_command( OUTPUT sfdkinfocmd COMMAND echo Builds OpenFHEsfdk and these apps: ${PKEAPPS} )
add_custom_target( sfdkinfo DEPENDS sfdkinfocmd )
