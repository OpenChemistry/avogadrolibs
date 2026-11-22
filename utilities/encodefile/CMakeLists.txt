add_executable(encodefile encodefile.cxx)
if(EMSCRIPTEN)
  # Allow the WASM build tool, run under Node.js, to read shader files and
  # write generated headers directly to the host filesystem.
  target_link_options(encodefile PRIVATE "-sNODERAWFS=1")
endif()
