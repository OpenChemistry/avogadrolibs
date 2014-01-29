find_package(GTest REQUIRED)

include_directories("${CMAKE_CURRENT_BINARY_DIR}"
  "${AvogadroLibs_BINARY_DIR}/avogadro/io"
  "${AvogadroLibs_BINARY_DIR}/avogadro/protocall"
  "${AvogadroLibs_SOURCE_DIR}/avogadro/protocall"
)

find_package(protobuf REQUIRED NO_MODULE)
include_directories(SYSTEM ${protobuf_INCLUDE_DIRS})

find_package(ProtoCall REQUIRED NO_MODULE)
include_directories(SYSTEM ${ProtoCall_INCLUDE_DIRS})

if(AVOGADRO_DATA_ROOT)
  set(AVOGADRO_DATA ${AVOGADRO_DATA_ROOT})
else()
  message("No data root found, please set to run the tests.")
  return()
endif()

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/protocalltests.h.in"
  "${CMAKE_CURRENT_BINARY_DIR}/protocalltests.h" @ONLY)

set(tests
  MoleculeSerialization
  MatrixSerialization
  )

# Build up the source file names.
set(_test_srcs "")
foreach(_test ${tests})
  message(STATUS "Adding ${_test} test.")
  string(TOLOWER ${_test} testname)
  list(APPEND test_srcs ${testname}.cpp)
endforeach()
message(STATUS "Test source files: ${_test_srcs}")

# Add a single executable for all of our tests.
add_executable(AvogadroProtoCallTests ${test_srcs})
target_link_libraries(AvogadroProtoCallTests AvogadroProtoCall
  ${GTEST_BOTH_LIBRARIES} ${EXTRA_LINK_LIB})

# Now add all of the tests, using the gtest_filter argument so that only those
# cases are run in each test invocation.
foreach(_test ${tests})
  add_test(NAME "${_test}"
    COMMAND AvogadroProtoCallTests "--gtest_filter=${_test}Test.*")
endforeach()
