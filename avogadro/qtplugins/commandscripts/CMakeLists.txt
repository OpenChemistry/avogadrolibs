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

# Bundled command scripts
set(commands
  scripts/scale.py
)

option(INSTALL_TEST_COMMANDS
  "Install a dummy command that is to test scripts."
  OFF
)

if(INSTALL_TEST_COMMANDS)
  list(APPEND commands scripts/test.py)
endif()

install(PROGRAMS ${commands}
DESTINATION "${INSTALL_LIBRARY_DIR}/avogadro2/scripts/commands/")
