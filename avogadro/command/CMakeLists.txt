find_package(Eigen3 REQUIRED)

add_executable(avocjsontocml cjsontocml.cpp)
target_link_libraries(avocjsontocml AvogadroIO)

add_executable(avobabel avobabel.cpp)
target_link_libraries(avobabel AvogadroIO)

add_executable(qube qube.cpp)
target_link_libraries(qube AvogadroQuantumIO AvogadroIO Eigen3::Eigen)
