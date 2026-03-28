set(_benchmark_data_root "${AvogadroLibs_SOURCE_DIR}/../avogadrodata")
if(DEFINED AVOGADRO_DATA_ROOT AND NOT "${AVOGADRO_DATA_ROOT}" STREQUAL "")
  set(_benchmark_data_root "${AVOGADRO_DATA_ROOT}")
endif()

add_executable(AvogadroUFFBenchmark uffbenchmark.cpp)
target_link_libraries(AvogadroUFFBenchmark PRIVATE Avogadro::Calc Avogadro::IO)
target_compile_definitions(AvogadroUFFBenchmark
  PRIVATE AVOGADRO_BENCHMARK_DATA_ROOT="${_benchmark_data_root}")

add_executable(AvogadroGaussianBenchmark gaussianbenchmark.cpp)
target_link_libraries(AvogadroGaussianBenchmark
  PRIVATE Avogadro::Core Avogadro::IO Avogadro::QuantumIO)
target_compile_definitions(AvogadroGaussianBenchmark
  PRIVATE AVOGADRO_BENCHMARK_DATA_ROOT="${_benchmark_data_root}")
