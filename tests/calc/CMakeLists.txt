# Specify the name of each test (the Test will be appended where needed).
set(tests
  ChargeManager
  ChargeModel
  EnergyManager
  EnergyCalculator
  EnergyOptimizer
  ForceFieldEdgeCase
  Gradient
  LennardJones
  UFF
)

include_directories("${CMAKE_CURRENT_BINARY_DIR}"
  "${AvogadroLibs_BINARY_DIR}/avogadro/calc")

if (DEFINED ENV{LIB_FUZZING_ENGINE})
  option(ENABLE_FUZZ "Enable fuzz testing." ON)
else()
  option(ENABLE_FUZZ "Enable fuzz testing." OFF)
endif()

# The fuzz target needs no data files, so it comes before the data-root check.
if(ENABLE_FUZZ OR DEFINED ENV{LIB_FUZZING_ENGINE})
  add_executable(fuzz_calc_forcefield fuzz-forcefield.cpp)
  # for fuzzhelpers.h
  target_include_directories(fuzz_calc_forcefield PRIVATE
    "${AvogadroLibs_SOURCE_DIR}/tests/core")
  if(DEFINED ENV{LIB_FUZZING_ENGINE})
    target_link_libraries(fuzz_calc_forcefield PRIVATE Avogadro::Calc $ENV{LIB_FUZZING_ENGINE})
  else()
    target_compile_options(fuzz_calc_forcefield PRIVATE ${AvogadroLibs_FUZZ_COMPILE_OPTIONS})
    target_link_options(fuzz_calc_forcefield PRIVATE ${AvogadroLibs_FUZZ_LINK_OPTIONS})
    target_link_libraries(fuzz_calc_forcefield PRIVATE Avogadro::Calc ${AvogadroLibs_FUZZ_LINK_LIBS})
  endif()
endif()

# we also read some example data files
if(AVOGADRO_DATA_ROOT)
  set(AVOGADRO_DATA ${AVOGADRO_DATA_ROOT})
else()
  message("No data root found, please set to run the tests.")
  return()
endif()

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/calctests.h.in"
  "${CMAKE_CURRENT_BINARY_DIR}/calctests.h" @ONLY)

# Build up the source file names.
set(testSrcs "")
foreach(TestName ${tests})
  message(STATUS "Adding ${TestName} test.")
  string(TOLOWER ${TestName} testname)
  list(APPEND testSrcs ${testname}test.cpp)
endforeach()
message(STATUS "Test source files: ${testSrcs}")

# Add a single executable for all of our tests.
add_executable(AvogadroCalcTests ${testSrcs})
target_link_libraries(AvogadroCalcTests Avogadro::Calc Avogadro::IO
  ${GTEST_BOTH_LIBRARIES} ${EXTRA_LINK_LIB})

# Now add all of the tests, using the gtest_filter argument so that only those
# cases are run in each test invocation.
foreach(TestName ${tests})
  if(TestName STREQUAL "Gradient")
    # Gradient tests use multiple suite names in gradienttest.cpp.
    add_test(NAME "Calc-Gradient-Angle"
      COMMAND AvogadroCalcTests "--gtest_filter=AngleGradientTest.*")
    add_test(NAME "Calc-Gradient-Dihedral"
      COMMAND AvogadroCalcTests "--gtest_filter=DihedralGradientTest.*")
    add_test(NAME "Calc-Gradient-OutOfPlane"
      COMMAND AvogadroCalcTests "--gtest_filter=OutOfPlaneGradientTest.*")
    add_test(NAME "Calc-Gradient-Stress"
      COMMAND AvogadroCalcTests "--gtest_filter=GradientStressTest.*")
  elseif(TestName STREQUAL "UFF")
    # Parameterized test suite name is UffGradientTest.
    add_test(NAME "Calc-UFF"
      COMMAND AvogadroCalcTests "--gtest_filter=UffTest/UffGradientTest.*")
  elseif(TestName STREQUAL "ForceFieldEdgeCase")
    # Parameterized test suite name is ForceFieldEdgeCaseTest.
    add_test(NAME "Calc-ForceFieldEdgeCase"
      COMMAND AvogadroCalcTests "--gtest_filter=*ForceFieldEdgeCaseTest*")
  elseif(TestName STREQUAL "EnergyCalculator")
    # energycalculatortest.cpp defines several suites; the optimizer ones
    # run under Calc-EnergyOptimizer.
    add_test(NAME "Calc-EnergyCalculator"
      COMMAND AvogadroCalcTests
      "--gtest_filter=EnergyCalculatorTest.*:CustomCalculatorTest.*:EnergyCalculatorBatchTest.*:EnergyCalculatorEvaluateTest.*:EnergyCalculatorFusedTest.*:RestraintTest.*")
  elseif(TestName STREQUAL "EnergyOptimizer")
    # split across energycalculatortest.cpp and energyoptimizertest.cpp
    add_test(NAME "Calc-EnergyOptimizer"
      COMMAND AvogadroCalcTests
      "--gtest_filter=EnergyOptimizerTest.*:AdaptChunkIterationsTest.*")
  else()
    add_test(NAME "Calc-${TestName}"
      COMMAND AvogadroCalcTests "--gtest_filter=${TestName}Test.*")
  endif()
endforeach()
