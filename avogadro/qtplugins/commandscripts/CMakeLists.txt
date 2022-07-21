# Needed to find avogadroioexport.h:
include_directories("${AvogadroLibs_BINARY_DIR}/avogadro/io/")

# Extension
set(command_srcs
  command.cpp
)

avogadro_plugin(commands
  "Script commands"
  ExtensionPlugin
  command.h
  Command
  "${command_srcs}"
)

target_link_libraries(commands PRIVATE AvogadroIO)

# We no longer bundle scripts because they should be downloaded separately.
# This also helps base translations.