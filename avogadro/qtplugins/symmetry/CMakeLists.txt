find_package(libmsym REQUIRED)
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

target_link_libraries(Symmetry LINK_PRIVATE ${LIBMSYM_LIBRARIES})
target_link_libraries(SymmetryScene LINK_PRIVATE AvogadroRendering)


#[[
add_subdirectory(libmsym)


need this in libmsym
install(TARGETS libmsym
    EXPORT "AvogadroLibsTargets"
    RUNTIME DESTINATION "${INSTALL_RUNTIME_DIR}"
    LIBRARY DESTINATION "${INSTALL_LIBRARY_DIR}/avogadro2/plugins"
    ARCHIVE DESTINATION "${INSTALL_ARCHIVE_DIR}/avogadro2/staticplugins")
]]
