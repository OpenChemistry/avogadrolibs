include_directories("${MolCore_SOURCE_DIR}/src")

# find google test
find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS})

add_executable(graphtest graphtest.cpp)
target_link_libraries(graphtest MolCore ${GTEST_BOTH_LIBRARIES} pthread)
add_test(GraphTest graphtest)

add_executable(moleculetest moleculetest.cpp)
target_link_libraries(moleculetest MolCore ${GTEST_BOTH_LIBRARIES} pthread)
add_test(MoleculeTest moleculetest)

add_executable(ringperceivertest ringperceivertest.cpp)
target_link_libraries(ringperceivertest MolCore ${GTEST_BOTH_LIBRARIES} pthread)
add_test(RingPerceiverTest ringperceivertest)

add_executable(varianttest varianttest.cpp)
target_link_libraries(varianttest MolCore ${GTEST_BOTH_LIBRARIES} pthread)
add_test(VariantTest varianttest)

add_executable(variantmaptest variantmaptest.cpp)
target_link_libraries(variantmaptest MolCore ${GTEST_BOTH_LIBRARIES} pthread)
add_test(VariantMapTest variantmaptest)
