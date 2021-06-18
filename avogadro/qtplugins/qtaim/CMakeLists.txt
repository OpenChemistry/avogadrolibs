set(qtaimextension_SRCS
    qtaimextension.cpp
    qtaimwavefunction.cpp
    qtaimwavefunctionevaluator.cpp
    qtaimodeintegrator.cpp
    qtaimcriticalpointlocator.cpp
    qtaimmathutilities.cpp
    qtaimodeintegrator.cpp
    qtaimlsodaintegrator.cpp
    qtaimcubature.cpp
)

avogadro_plugin(QTAIMExtension
  "QTAIM extension"
  ExtensionPlugin
  qtaimextension.h
  QTAIMExtension
  "${qtaimextension_SRCS}"
)

target_link_libraries(QTAIMExtension
  PRIVATE
    Qt5::Concurrent)

# The settings widget is not built -- its settings weren't actually used by the
# engine in Avogadro 1. The sources are kept for later if we decide to use it.
avogadro_plugin(QTAIMScenePlugin
  "QTAIM scene plugin"
  ScenePlugin
  qtaimengine.h
  QTAIMEngine
  qtaimengine.cpp
)

target_link_libraries(QTAIMScenePlugin
  PRIVATE
    AvogadroRendering)
