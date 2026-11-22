add_subdirectory(bodr)
add_subdirectory(encodefile)
add_subdirectory(resdata)

if(ENABLE_CALC_BENCHMARKS OR ENABLE_RENDERING_BENCHMARKS)
  add_subdirectory(benchmarks)
endif()
