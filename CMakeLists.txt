include_directories(${CMAKE_CURRENT_BINARY_DIR})

set(LINK_LIBS avogadro)
set(PLUGIN_LABEL extensions)
set(PLUGIN_TARGET extensions)

set(qtaimextension_SRCS
  qtaimmathutilities.cpp
  )

avogadro_plugin_nogl(qtaimextension 
  "${qtaimextension_SRCS}"
  )
