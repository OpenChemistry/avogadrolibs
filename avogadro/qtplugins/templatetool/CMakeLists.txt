include(ExternalProject)

find_package(Qt${QT_VERSION} REQUIRED COMPONENTS Svg)

set(template_srcs
  templatetool.cpp
  templatetoolwidget.cpp
)

set(template_uis
  templatetoolwidget.ui
)

set(template_rcs
  template.qrc
)

avogadro_plugin(TemplateTool
  "Template tool"
  ToolPlugin
  templatetool.h
  TemplateTool
  "${template_srcs}"
  "${template_uis}"
  "${template_rcs}"
)

# Install the fragments
set(_fragments "${AvogadroLibs_SOURCEDATA_DIR}/fragments")

# Look in parallel directory for the molecule fragment repository
if(NOT EXISTS "${_fragments}")
# download molecules...
ExternalProject_Add(fragments
    GIT_REPOSITORY https://github.com/openchemistry/fragments
    GIT_TAG main
    # or https://github.com/OpenChemistry/molecules/archive/refs/heads/master.zip
    SOURCE_DIR "${AvogadroLibs_SOURCEDATA_DIR}/fragments"
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ""
    INSTALL_COMMAND ""
)
endif()

install(DIRECTORY "${AvogadroLibs_SOURCEDATA_DIR}/fragments"
  DESTINATION "${INSTALL_DATA_DIR}/avogadro2"
  PATTERN ".git" EXCLUDE
  PATTERN ".gitignore" EXCLUDE
  PATTERN "README.md" EXCLUDE
  PATTERN "LICENSE" EXCLUDE
  PATTERN "*.smi" EXCLUDE
)

target_link_libraries(TemplateTool
  PRIVATE
    Avogadro::QtOpenGL
    Qt::Svg
)
