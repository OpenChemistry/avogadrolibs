include_directories("${AvogadroLibs_SOURCE_DIR}/thirdparty")

set(constraints
  constraintsextension.cpp
  constraintsdialog.cpp
  constraintsmodel.cpp
  constraint.cpp
)

set(constraints_uis
  constraintsdialog.ui
)

avogadro_plugin(ConstraintsExtension
  "Constraints extension"
  ExtensionPlugin
  constraintsextension.h
  ConstraintsExtension
  "${constraints}"
  "${constraints_uis}"
)

target_link_libraries(ConstraintsExtension)
