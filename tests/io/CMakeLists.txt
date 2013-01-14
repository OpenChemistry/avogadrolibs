# Specify the name of each test (the Test will be appended where needed).
set(tests
  Cjson
  Cml
  FileFormatManager
  Hdf5
  )

include_directories("${CMAKE_CURRENT_BINARY_DIR}"
	"${AvogadroLibs_BINARY_DIR}/avogadro/io")

# THe data repository should be at the side of ours.
find_path(AVOGADRO_DATA_ROOT .avogadro.data
  ${AvogadroLibs_SOURCE_DIR}/../avogadrodata
  $ENV{AVOGADRO_DATA_ROOT}
  DOC "The repository for data used for testing."
  )
mark_as_advanced(AVOGADRO_DATA_ROOT)

if(AVOGADRO_DATA_ROOT)
  set(AVOGADRO_DATA ${AVOGADRO_DATA_ROOT})
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
  add_test(NAME "${TestName}Test"
    COMMAND AvogadroIOTests "--gtest_filter=${TestName}Test.*")
endforeach()
