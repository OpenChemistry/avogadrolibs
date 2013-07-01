include_directories("${CMAKE_CURRENT_BINARY_DIR}"
  "${AvogadroLibs_BINARY_DIR}/avogadro/qtgui")

find_package(Qt4 COMPONENTS QtCore QtGui REQUIRED)
include_directories(SYSTEM ${QT_INCLUDES})
add_definitions(${QT_DEFINITIONS})

# Specify the name of each test (the Test will be appended where needed).
set(tests
  Molecule
  )

# Build up the source file names.
set(testSrcs "")
foreach(TestName ${tests})
  message(STATUS "Adding ${TestName} test.")
  string(TOLOWER ${TestName} testname)
  list(APPEND testSrcs ${testname}test.cpp)
endforeach()

# Add a single executable for all of our tests.
add_executable(AvogadroQtGuiTests ${testSrcs})
target_link_libraries(AvogadroQtGuiTests AvogadroQtGui
  ${GTEST_BOTH_LIBRARIES} ${EXTRA_LINK_LIB})

# Now add all of the tests, using the gtest_filter argument so that only those
# cases are run in each test invocation.
foreach(TestName ${tests})
  add_test(NAME "QtGui-${TestName}"
    COMMAND AvogadroQtGuiTests "--gtest_filter=${TestName}Test.*")
endforeach()
