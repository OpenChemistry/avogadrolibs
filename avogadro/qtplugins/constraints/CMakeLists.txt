
set(constraints
  constraintsextension.cpp
  constraintsdialog.cpp
  constraintsmodel.cpp
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
