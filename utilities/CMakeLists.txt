add_subdirectory(bodr)
add_subdirectory(encodefile)
add_subdirectory(resdata)

if(ENABLE_CALC_BENCHMARKS)
  add_subdirectory(benchmarks)
endif()
