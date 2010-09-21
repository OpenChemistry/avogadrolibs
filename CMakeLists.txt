include_directories(${CMAKE_CURRENT_BINARY_DIR})

set(LINK_LIBS avogadro)
set(PLUGIN_LABEL extensions)
set(PLUGIN_TARGET extensions)

set(qtaimextension_SRCS
    qtaimextension.cpp
#    qtaimdialog.cpp
    qtaimwavefunction.cpp
    qtaimwavefunctionevaluator.cpp
    qtaimodeintegrator.cpp
    qtaimcriticalpointlocator.cpp
    qtaimmathutilities.cpp
    qtaimodeintegrator.cpp
    qtaimlsodaintegrator.cpp
#    qtaimintegrator.cpp
)

#set(qtaim_UIS
#  qtaimdialog.ui
#)

avogadro_plugin_nogl(qtaimextension 
  "${qtaimextension_SRCS}"
#  "${qtaimextension_UIS}"
 )
