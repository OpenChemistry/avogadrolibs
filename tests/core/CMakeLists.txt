# Specify the name of each test (the Test will be appended where needed).
set(tests
  AngleIterator
  Array
  Atom
  AtomTyper
  BasisSet
  Bond
  CoordinateBlockGenerator
  CoordinateSet
  Cube
  DihedralIterator
  Eigen
  Element
  GaussianSet
  Graph
  InternalCoordinates
  Mesh
  Molecule
  Mutex
  NeighborPerceiver
  Residue
  RingPerceiver
  SecondaryStructure
  Utilities
  UnitCell
  Variant
  VariantMap
  )
if(USE_SPGLIB)
  list(APPEND tests SpaceGroup)
endif()

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
target_link_libraries(AvogadroTests Avogadro::Core
  ${GTEST_BOTH_LIBRARIES} ${EXTRA_LINK_LIB})

# Now add all of the tests, using the gtest_filter argument so that only those
# cases are run in each test invocation.
foreach(TestName ${tests})
  add_test(NAME "Core-${TestName}"
    COMMAND AvogadroTests "--gtest_filter=${TestName}Test.*")
endforeach()

if (DEFINED ENV{LIB_FUZZING_ENGINE})
  option(ENABLE_FUZZ "Enable fuzz testing." ON)
else()
  option(ENABLE_FUZZ "Enable fuzz testing." OFF)
endif()

if(ENABLE_FUZZ OR DEFINED ENV{LIB_FUZZING_ENGINE})
  set(core_fuzz bond crystal graph molecule neighbor ring utilities)
  foreach(fuzzName ${core_fuzz})
    add_executable(fuzz_core_${fuzzName} fuzz-${fuzzName}.cpp)
    if(DEFINED ENV{LIB_FUZZING_ENGINE})
      target_link_libraries(fuzz_core_${fuzzName} PRIVATE Avogadro::Core $ENV{LIB_FUZZING_ENGINE})
    else()
      target_compile_options(fuzz_core_${fuzzName} PRIVATE -g -fsanitize=fuzzer)
      target_link_options(fuzz_core_${fuzzName} PRIVATE -fsanitize=fuzzer)
      target_link_libraries(fuzz_core_${fuzzName} PRIVATE Avogadro::Core)
    endif()
  endforeach()
endif()
