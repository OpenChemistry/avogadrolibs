include_directories("${MolCore_SOURCE_DIR}/src"
  "${MolCore_BINARY_DIR}/src")

# find google test
find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS})

include(CheckIncludeFileCXX)
include(CheckCXXSymbolExists)
check_include_file_cxx("gtest/gtest.h" HAVE_GTEST_HPP)
if(HAVE_GTEST_HPP)
  check_cxx_symbol_exists(GTEST_HAS_PTHREAD "gtest/gtest.h" GTEST_HAS_PTHREAD)
  check_cxx_symbol_exists(GTEST_IS_THREADSAFE "gtest/gtest.h" GTEST_IS_THREADSAFE)
endif()

if(GTEST_HAS_PTHREAD)
  message("GTest claims it has pthreads, we need to link to it.")
  find_package(Threads)
  set(EXTRA_LINK_LIB ${CMAKE_THREAD_LIBS_INIT})
else()
  set(EXTRA_LINK_LIB "")
endif()

add_executable(atomtest atomtest.cpp)
target_link_libraries(atomtest MolCore ${GTEST_BOTH_LIBRARIES}
  ${EXTRA_LINK_LIB})
add_test(NAME AtomTest COMMAND atomtest)

add_executable(graphtest graphtest.cpp)
target_link_libraries(graphtest MolCore ${GTEST_BOTH_LIBRARIES}
  ${EXTRA_LINK_LIB})
add_test(NAME GraphTest COMMAND graphtest)

add_executable(moleculetest moleculetest.cpp)
target_link_libraries(moleculetest MolCore ${GTEST_BOTH_LIBRARIES}
  ${EXTRA_LINK_LIB})
add_test(NAME MoleculeTest COMMAND moleculetest)

add_executable(ringperceivertest ringperceivertest.cpp)
target_link_libraries(ringperceivertest MolCore ${GTEST_BOTH_LIBRARIES}
  ${EXTRA_LINK_LIB})
add_test(NAME RingPerceiverTest COMMAND ringperceivertest)

add_executable(varianttest varianttest.cpp)
target_link_libraries(varianttest MolCore ${GTEST_BOTH_LIBRARIES}
  ${EXTRA_LINK_LIB})
add_test(NAME VariantTest COMMAND varianttest)

add_executable(variantmaptest variantmaptest.cpp)
target_link_libraries(variantmaptest MolCore ${GTEST_BOTH_LIBRARIES}
  ${EXTRA_LINK_LIB})
add_test(NAME VariantMapTest COMMAND variantmaptest)
