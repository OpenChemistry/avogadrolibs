set(_benchmark_data_root "${AvogadroLibs_SOURCE_DIR}/../avogadrodata")
if(DEFINED AVOGADRO_DATA_ROOT AND NOT "${AVOGADRO_DATA_ROOT}" STREQUAL "")
  set(_benchmark_data_root "${AVOGADRO_DATA_ROOT}")
endif()

add_executable(AvogadroUFFBenchmark uffbenchmark.cpp)
target_link_libraries(AvogadroUFFBenchmark PRIVATE Avogadro::Calc Avogadro::IO)
target_compile_definitions(AvogadroUFFBenchmark
  PRIVATE AVOGADRO_BENCHMARK_DATA_ROOT="${_benchmark_data_root}")
