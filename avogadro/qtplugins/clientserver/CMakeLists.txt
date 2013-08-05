find_package(protobuf REQUIRED NO_MODULE)
include_directories(SYSTEM ${protobuf_INCLUDE_DIRS})

find_package(ProtoCall REQUIRED NO_MODULE)
include_directories(SYSTEM ${ProtoCall_INCLUDE_DIRS})

find_package(VTK COMPONENTS vtkParallelCore)
set_property(DIRECTORY APPEND PROPERTY COMPILE_DEFINITIONS ${VTK_DEFINITIONS})
include_directories(${VTK_INCLUDE_DIRS})

protocallc(_protocall_common_source
  _protocall_service_source
  _protocall_proxy_source
  _protocall_include_dir
  "remote.proto")

include_directories(${_protocall_include_dir}
  ${CMAKE_SOURCE_DIR}/avogadro/protocall
  ${CMAKE_BINARY_DIR}/avogadro/protocall)

# Build server
set(_server_source
  avogadroserver.cpp
  avoremotemoleculeservice.cpp
  )

add_executable(avogadroserver
  ${_protocall_common_source}
  ${_protocall_service_source}
  ${_server_source}
  )

target_link_libraries(avogadroserver
  vtkParallelCore AvogadroProtoCall)

# Build plugin
foreach(_file ${_protocall_common_source} ${_protocall_proxy_source})
  set_source_files_properties(${_file} PROPERTIES SKIP_AUTOMOC TRUE)
endforeach()

set(_plugin_src "clientserver.cpp;connectionsettingsdialog.cpp")
list(APPEND _plugin_src  ${_protocall_common_source})
list(APPEND _plugin_src ${_protocall_proxy_source})

avogadro_plugin(ClientServer
  "Client server operations."
  ExtensionPlugin
  "clientserver.h"
  ClientServer
  "${_plugin_src}"
  "connectionsettingsdialog.ui"
  )

target_link_libraries(ClientServer
  AvogadroIO
  vtkParallelCore
  AvogadroProtoCall
  )

