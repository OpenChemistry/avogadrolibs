# Specify the name of each test (the Test will be appended where needed).
set(tests
  Array
  Atom
  AtomTyper
  BasisSet
  Bond
  CoordinateBlockGenerator
  CoordinateSet
  CPP11
  Cube
  Eigen
  Element
  Graph
  Mesh
  Molecule
  Mutex
  RingPerceiver
  Spacegroup
  Utilities
  UnitCell
  Variant
  VariantMap
  )

# Build up the source file names.
set(testSrcs "")
foreach(TestName ${tests})
  message(STATUS "Adding ${TestName} test.")
  string(TOLOWER ${TestName} testname)
  list(APPEND testSrcs ${testname}test.cpp)
endforeach()
message(STATUS "Test source files: ${testSrcs}")

# Add a single executable for all of our tests.
add_executable(AvogadroTests ${testSrcs})
target_link_libraries(AvogadroTests AvogadroCore
  ${GTEST_BOTH_LIBRARIES} ${EXTRA_LINK_LIB})
# Additional libraries and compiler definitions necessary when using Boost to
# replace C++11.
if(AvogadroLibs_NEEDS_BOOST)
  target_link_libraries(AvogadroTests ${AvogadroLibs_MUTEX_BOOST_LIBRARIES})
  add_definitions(${AvogadroLibs_BOOST_DEFINITIONS})
endif()

# Now add all of the tests, using the gtest_filter argument so that only those
# cases are run in each test invocation.
foreach(TestName ${tests})
  add_test(NAME "Core-${TestName}"
    COMMAND AvogadroTests "--gtest_filter=${TestName}Test.*")
endforeach()
