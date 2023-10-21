add_executable(avocjsontocml cjsontocml.cpp)
target_link_libraries(avocjsontocml Avogadro::IO)

add_executable(avobabel avobabel.cpp)
target_link_libraries(avobabel Avogadro::IO)

add_executable(qube qube.cpp)
target_link_libraries(qube Avogadro::QuantumIO)
