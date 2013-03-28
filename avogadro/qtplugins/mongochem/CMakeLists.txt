include_directories(${CMAKE_CURRENT_BINARY_DIR})

find_package(MoleQueue REQUIRED)
include_directories(${MoleQueue_INCLUDE_DIRS})

avogadro_plugin(MongoChem
  "Interact with MongoChem."
  ExtensionPlugin
  mongochem.h
  MongoChem
  "mongochem.cpp"
  ""
)
target_link_libraries(MongoChem AvogadroIO MoleQueueClient)
