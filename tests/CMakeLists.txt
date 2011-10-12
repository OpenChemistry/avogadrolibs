include(../src)

# find google test
find_package(GTest)
include(${GTEST_INCLUDE_DIRS})

add_executable(graphtest graphtest.cpp)
target_link_libraries(graphtest MolCore ${GTEST_BOTH_LIBRARIES} pthread)
add_test(GraphTest graphtest)

add_executable(moleculetest moleculetest.cpp)
target_link_libraries(moleculetest MolCore ${GTEST_BOTH_LIBRARIES} pthread)
add_test(MoleculeTest moleculetest)

add_executable(varianttest varianttest.cpp)
target_link_libraries(varianttest MolCore ${GTEST_BOTH_LIBRARIES} pthread)
add_test(VariantTest varianttest)

add_executable(variantmaptest variantmaptest.cpp)
target_link_libraries(variantmaptest MolCore ${GTEST_BOTH_LIBRARIES} pthread)
add_test(VariantMapTest variantmaptest)

