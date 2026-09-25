# Specify the name of each test (the Test will be appended where needed).
set(tests
  AngleIterator
  AngleTools
  Aromaticity
  Array
  Atom
  AtomTyper
  AtomUtilities
  BasisSet
  Bond
  Constraint
  ConformerQuantity
  CoordinateBlockGenerator
  CoordinateSet
  CrystalTools
  Cube
  DihedralIterator
  Eigen
  Element
  GaussianSet
  GaussianShellNormalization
  Graph
  InternalCoordinates
  Kekulize
  Layer
  LayerManager
  Mesh
  Molecule
  Mutex
  NeighborPerceiver
  PropertyMap
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
# Tests written as gtest parameterized suites (TEST_P). Their full case
# names are "Prefix/SuiteTest.case/index", which the plain "SuiteTest.*"
# filter below would not match -- ctest would then run zero cases and still
# report success.
set(parameterizedTests
  GaussianShellNormalization
  )

foreach(TestName ${tests})
  if(${TestName} IN_LIST parameterizedTests)
    set(testFilter "*${TestName}Test*")
  else()
    set(testFilter "${TestName}Test.*")
  endif()
  add_test(NAME "Core-${TestName}"
    COMMAND AvogadroTests "--gtest_filter=${testFilter}")
endforeach()

if (DEFINED ENV{LIB_FUZZING_ENGINE})
  option(ENABLE_FUZZ "Enable fuzz testing." ON)
else()
  option(ENABLE_FUZZ "Enable fuzz testing." OFF)
endif()

if(ENABLE_FUZZ OR DEFINED ENV{LIB_FUZZING_ENGINE})
  set(core_fuzz array bond coordinateblockgenerator crystal graph layer molecule neighbor residue ring secondarystructure utilities variant variantmap)
  foreach(fuzzName ${core_fuzz})
    add_executable(fuzz_core_${fuzzName} fuzz-${fuzzName}.cpp)
    if(DEFINED ENV{LIB_FUZZING_ENGINE})
      target_link_libraries(fuzz_core_${fuzzName} PRIVATE Avogadro::Core $ENV{LIB_FUZZING_ENGINE})
    else()
      target_compile_options(fuzz_core_${fuzzName} PRIVATE ${AvogadroLibs_FUZZ_COMPILE_OPTIONS})
      target_link_options(fuzz_core_${fuzzName} PRIVATE ${AvogadroLibs_FUZZ_LINK_OPTIONS})
      target_link_libraries(fuzz_core_${fuzzName} PRIVATE Avogadro::Core ${AvogadroLibs_FUZZ_LINK_LIBS})
    endif()
  endforeach()
endif()
