set(_benchmark_data_root "${AvogadroLibs_SOURCE_DIR}/../avogadrodata")
if(DEFINED AVOGADRO_DATA_ROOT AND NOT "${AVOGADRO_DATA_ROOT}" STREQUAL "")
  set(_benchmark_data_root "${AVOGADRO_DATA_ROOT}")
endif()

if(ENABLE_CALC_BENCHMARKS)
  add_executable(AvogadroUFFBenchmark uffbenchmark.cpp)
  target_link_libraries(AvogadroUFFBenchmark
    PRIVATE Avogadro::Calc Avogadro::IO cppoptlib)
  target_compile_definitions(AvogadroUFFBenchmark
    PRIVATE AVOGADRO_BENCHMARK_DATA_ROOT="${_benchmark_data_root}")

  add_executable(AvogadroOptimizerBenchmark optimizerbenchmark.cpp)
  target_link_libraries(AvogadroOptimizerBenchmark
    PRIVATE Avogadro::Calc Avogadro::IO)
  target_compile_definitions(AvogadroOptimizerBenchmark
    PRIVATE AVOGADRO_BENCHMARK_DATA_ROOT="${_benchmark_data_root}")

  add_executable(AvogadroGaussianBenchmark gaussianbenchmark.cpp)
  target_link_libraries(AvogadroGaussianBenchmark
    PRIVATE Avogadro::Core Avogadro::IO Avogadro::QuantumIO)
  target_compile_definitions(AvogadroGaussianBenchmark
    PRIVATE AVOGADRO_BENCHMARK_DATA_ROOT="${_benchmark_data_root}")
endif()

if(ENABLE_RENDERING_BENCHMARKS)
  find_package(Qt6 REQUIRED COMPONENTS Widgets Gui OpenGL)
  add_executable(AvogadroRenderBenchmark renderbenchmark.cpp)
  target_link_libraries(AvogadroRenderBenchmark
    PRIVATE Avogadro::QtGui Avogadro::QtPlugins Avogadro::Rendering
            Avogadro::IO Avogadro::Core Qt6::Widgets Qt6::Gui Qt6::OpenGL)
endif()
