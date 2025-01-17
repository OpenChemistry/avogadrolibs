# Specify the name of each test (the Test will be appended where needed).
set(tests
  Cjson
  Cml
  FileFormatManager
  Lammps
  Mdl
  Pdb
  Vasp
  Xyz
  )

if(USE_HDF5)
  list(APPEND tests Hdf5)
endif()

if(USE_MMTF)
  list(APPEND tests MMTF)
endif()

include_directories("${CMAKE_CURRENT_BINARY_DIR}"
	"${AvogadroLibs_BINARY_DIR}/avogadro/io")

if(AVOGADRO_DATA_ROOT)
  set(AVOGADRO_DATA ${AVOGADRO_DATA_ROOT})
else()
  message("No data root found, please set to run the tests.")
  return()
endif()

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/iotests.h.in"
  "${CMAKE_CURRENT_BINARY_DIR}/iotests.h" @ONLY)

# Build up the source file names.
set(testSrcs "")
foreach(TestName ${tests})
  message(STATUS "Adding ${TestName} test.")
  string(TOLOWER ${TestName} testname)
  list(APPEND testSrcs ${testname}test.cpp)
endforeach()
message(STATUS "Test source files: ${testSrcs}")

# Add a single executable for all of our tests.
add_executable(AvogadroIOTests ${testSrcs})
target_link_libraries(AvogadroIOTests Avogadro::IO
  ${GTEST_BOTH_LIBRARIES} ${EXTRA_LINK_LIB})

# Now add all of the tests, using the gtest_filter argument so that only those
# cases are run in each test invocation.
foreach(TestName ${tests})
  add_test(NAME "Io-${TestName}"
    COMMAND AvogadroIOTests "--gtest_filter=${TestName}Test.*")
endforeach()

option(ENABLE_FUZZ "Enable fuzz testing." OFF)

if(ENABLE_FUZZ)
  add_definitions(-DFUZZTEST_FUZZING_MODE=on)
  # fuzztest uses abseil-cpp
  set(CMAKE_CXX_STANDARD 17)
  set(CMAKE_CXX_VISIBILITY_PRESET default)
  add_subdirectory(fuzztest)

  fuzztest_setup_fuzzing_flags()
  add_executable(AvogadroFuzzTests fuzztest.cpp)
  target_link_libraries(AvogadroFuzzTests PRIVATE Avogadro::IO)
  link_fuzztest(AvogadroFuzzTests)
endif()
