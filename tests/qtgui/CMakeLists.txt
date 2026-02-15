include_directories("${CMAKE_CURRENT_BINARY_DIR}"
  "${AvogadroLibs_BINARY_DIR}/avogadro/qtgui"
  "${AvogadroLibs_BINARY_DIR}/avogadro/molequeue"
  "${AvogadroLibs_SOURCE_DIR}/tests/core")

find_package(Qt${QT_VERSION} COMPONENTS Widgets Network Test REQUIRED)

# Find python interpreter for input generator
find_package(Python3 COMPONENTS Interpreter)

# Setup config file with data location
if(AVOGADRO_DATA_ROOT)
  set(AVOGADRO_DATA ${AVOGADRO_DATA_ROOT})
endif()
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/qtguitests.h.in"
  "${CMAKE_CURRENT_BINARY_DIR}/qtguitests.h" @ONLY)

# Specify the name of each test (the Test will be appended where needed).
set(tests
  ElementTranslator
  GenericHighlighter
  HydrogenTools
  MeshGenerator
  Molecule
  PackageManager
  RWMolecule
)

if (BUILD_MOLEQUEUE)
  # Pull in MoleQueue
  find_package(MoleQueue REQUIRED NO_MODULE)
  include_directories(${MoleQueue_INCLUDE_DIRS})
  list(APPEND tests
    MoleQueueQueueListModel
  )
  set(MoleQueueLink Avogadro::MoleQueue MoleQueueClient)
endif()

if(Python3_EXECUTABLE AND AVOGADRO_DATA)
  list(APPEND tests
    # these are still somewhat broken
    # but it's not crucial
    #FileBrowseWidget
    #InputGenerator
    #InputGeneratorWidget
  )
  list(APPEND MoleQueueLink Avogadro::MoleQueue)
endif()

# Build up the source file names.
set(testSrcs "")
foreach(TestName ${tests})
  message(STATUS "Adding ${TestName} test.")
  string(TOLOWER ${TestName} testname)
  list(APPEND testSrcs ${testname}test.cpp)
endforeach()

# Add a single executable for all of our tests.
add_executable(AvogadroQtGuiTests ${testSrcs})
target_link_libraries(AvogadroQtGuiTests Avogadro::QtGui ${MoleQueueLink}
 ${GTEST_BOTH_LIBRARIES} ${EXTRA_LINK_LIB}
 Qt${QT_VERSION}::Widgets Qt${QT_VERSION}::Test)

# Now add all of the tests, using the gtest_filter argument so that only those
# cases are run in each test invocation.
foreach(TestName ${tests})
  add_test(NAME "QtGui-${TestName}"
    COMMAND AvogadroQtGuiTests "--gtest_filter=${TestName}Test.*")
endforeach()

if (DEFINED ENV{LIB_FUZZING_ENGINE})
  option(ENABLE_FUZZ "Enable fuzz testing." ON)
else()
  option(ENABLE_FUZZ "Enable fuzz testing." OFF)
endif()

if(ENABLE_FUZZ OR DEFINED ENV{LIB_FUZZING_ENGINE})
  set(qtgui_fuzz rwmolecule generichighlighter jsonwidget interfacescript-json)
  foreach(fuzzName ${qtgui_fuzz})
    add_executable(fuzz_qtgui_${fuzzName} fuzz-${fuzzName}.cpp)
    if(DEFINED ENV{LIB_FUZZING_ENGINE})
      target_link_libraries(fuzz_qtgui_${fuzzName}
        PRIVATE Avogadro::QtGui
        Qt${QT_VERSION}::Widgets Qt${QT_VERSION}::Test
        $ENV{LIB_FUZZING_ENGINE})
    else()
      target_compile_options(fuzz_qtgui_${fuzzName} PRIVATE -g -fsanitize=fuzzer)
      target_link_options(fuzz_qtgui_${fuzzName} PRIVATE -fsanitize=fuzzer)
      target_link_libraries(fuzz_qtgui_${fuzzName}
        PRIVATE Avogadro::QtGui
        Qt${QT_VERSION}::Widgets Qt${QT_VERSION}::Test)
    endif()
  endforeach()
endif()
