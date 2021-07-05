find_package(libmsym NO_MODULE)
if(NOT DEFINED LIBMSYM_INCLUDE_DIRS)
  find_package(libmsym REQUIRED)
endif()
include_directories(${LIBMSYM_INCLUDE_DIRS})

message("msym include dir " ${LIBMSYM_INCLUDE_DIRS})

set(symmetry_srcs
  symmetry.cpp
  symmetrywidget.cpp
  operationstablemodel.cpp
  richtextdelegate.cpp
  symmetryutil.cpp
)

set(symmetry_uis
  symmetrywidget.ui
)


avogadro_plugin(Symmetry
  "Provide symmetry functionality."
  ExtensionPlugin
  symmetry.h
  Symmetry
  "${symmetry_srcs}"
  "${symmetry_uis}"
)

avogadro_plugin(SymmetryScene
  "Render symmetry elements."
  ScenePlugin
  symmetryscene.h
  SymmetryScene
  symmetryscene.cpp)

target_link_libraries(Symmetry PRIVATE ${LIBMSYM_LIBRARIES})
target_link_libraries(SymmetryScene PRIVATE AvogadroRendering)

