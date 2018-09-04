# Specify the name of each test (the Test will be appended where needed).
set(tests
  Cjson
  Cml
  FileFormatManager
  Lammps
  Mdl
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
target_link_libraries(AvogadroIOTests AvogadroIO
  ${GTEST_BOTH_LIBRARIES} ${EXTRA_LINK_LIB})

# Now add all of the tests, using the gtest_filter argument so that only those
# cases are run in each test invocation.
foreach(TestName ${tests})
  add_test(NAME "Io-${TestName}"
    COMMAND AvogadroIOTests "--gtest_filter=${TestName}Test.*")
endforeach()
