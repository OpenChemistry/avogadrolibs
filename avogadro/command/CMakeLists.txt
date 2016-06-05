find_package(Eigen3 REQUIRED)
include_directories(SYSTEM "${EIGEN3_INCLUDE_DIR}")
find_package(SymSPG REQUIRED)
include_directories(SYSTEM "${SymSPG_INCLUDE_DIR}")

add_executable(avocjsontocml cjsontocml.cpp)
target_link_libraries(avocjsontocml AvogadroIO)

add_executable(avobabel avobabel.cpp)
target_link_libraries(avobabel AvogadroIO)

add_executable(qube qube.cpp)
target_link_libraries(qube AvogadroQuantumIO AvogadroIO)

add_executable(cell cell.cpp)
target_link_libraries(cell AvogadroIO)
