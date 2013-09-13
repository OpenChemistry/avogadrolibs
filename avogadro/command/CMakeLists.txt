include_directories(SYSTEM "${EIGEN3_INCLUDE_DIR}")

add_executable(avocjsontocml cjsontocml.cpp)
target_link_libraries(avocjsontocml AvogadroIO)