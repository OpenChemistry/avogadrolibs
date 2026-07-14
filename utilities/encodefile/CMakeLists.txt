add_executable(encodefile encodefile.cxx)
if(EMSCRIPTEN)
  target_link_options(encodefile PRIVATE "-sNODERAWFS=1")
endif()
