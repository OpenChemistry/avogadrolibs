include_directories("${CMAKE_CURRENT_BINARY_DIR}"
  "${AvogadroLibs_BINARY_DIR}/avogadro/qtgui"
  "${AvogadroLibs_BINARY_DIR}/avogadro/molequeue"
  "${AvogadroLibs_SOURCE_DIR}/tests/core")

find_package(Qt5 COMPONENTS Widgets Network Test REQUIRED)

# Pull in MoleQueue for QtJson
find_package(MoleQueue REQUIRED NO_MODULE)
include_directories(${MoleQueue_INCLUDE_DIRS})

# Find python interpreter for input generator
find_package(PythonInterp 3)

# Setup config file with data location
if(AVOGADRO_DATA_ROOT)
  set(AVOGADRO_DATA ${AVOGADRO_DATA_ROOT})
endif()
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/qtguitests.h.in"
  "${CMAKE_CURRENT_BINARY_DIR}/qtguitests.h" @ONLY)

# Specify the name of each test (the Test will be appended where needed).
set(tests
  GenericHighlighter
  HydrogenTools
  # GitHub is showing this as a free() bug
  # TODO: Fix this
  # Molecule
  MoleQueueQueueListModel
  RWMolecule
  )

if(PYTHON_EXECUTABLE AND AVOGADRO_DATA)
  list(APPEND tests
# FIXME: These tests are broken
#    FileBrowseWidget
#    InputGenerator
#    InputGeneratorWidget
  )
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
target_link_libraries(AvogadroQtGuiTests AvogadroQtGui AvogadroMoleQueue
  MoleQueueClient ${GTEST_BOTH_LIBRARIES} ${EXTRA_LINK_LIB} Qt5::Widgets Qt5::Test)

# Now add all of the tests, using the gtest_filter argument so that only those
# cases are run in each test invocation.
foreach(TestName ${tests})
  add_test(NAME "QtGui-${TestName}"
    COMMAND AvogadroQtGuiTests "--gtest_filter=${TestName}Test.*")
endforeach()
