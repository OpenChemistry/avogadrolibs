if(NOT TARGET gif-h)
  add_library(gif-h INTERFACE IMPORTED GLOBAL)
  target_include_directories(gif-h INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/gif-h>)
endif(NOT TARGET gif-h)

# Only used by Qt plugin
if (USE_QT)
  add_subdirectory(libgwavi)
endif()

if(USE_EXTERNAL_NLOHMANN)
  find_package(nlohmann_json 3.3.0 REQUIRED GLOBAL)
else()
  add_library(nlohmann_json INTERFACE IMPORTED GLOBAL)
  target_include_directories(nlohmann_json
    INTERFACE $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>)
  add_library(nlohmann_json::nlohmann_json ALIAS nlohmann_json)
endif(USE_EXTERNAL_NLOHMANN)

if(USE_EXTERNAL_PUGIXML)
  find_package(pugixml 1.12 REQUIRED GLOBAL)
else()
  set(_PUGIXML_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/pugixml)
  add_library(pugixml STATIC ${_PUGIXML_ROOT}/pugixml.cpp)
  set_target_properties(pugixml PROPERTIES POSITION_INDEPENDENT_CODE ON)
  target_include_directories(pugixml PUBLIC $<BUILD_INTERFACE:${_PUGIXML_ROOT}>)
  add_library(pugixml::pugixml ALIAS pugixml)
  unset(_PUGIXML_ROOT)
endif(USE_EXTERNAL_PUGIXML)

if(USE_EXTERNAL_STRUCT)
  find_package(struct REQUIRED GLOBAL)
else()
  set(_STRUCT_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/struct)
  add_library(struct STATIC
    ${_STRUCT_ROOT}/struct.c
    ${_STRUCT_ROOT}/struct_endian.c
  )
  set_target_properties(struct PROPERTIES POSITION_INDEPENDENT_CODE TRUE)
  target_include_directories(struct PUBLIC $<BUILD_INTERFACE:${_STRUCT_ROOT}>)
  unset(_STRUCT_ROOT)
endif(USE_EXTERNAL_STRUCT)

if(NOT TARGET cppoptlib)
  add_library(cppoptlib INTERFACE IMPORTED GLOBAL)
  target_include_directories(cppoptlib INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>)
endif(NOT TARGET cppoptlib)

if(USE_EXTERNAL_TOMLPLUSPLUS)
  find_package(tomlplusplus 3.4.0 REQUIRED GLOBAL)
else()
  add_library(tomlplusplus INTERFACE IMPORTED GLOBAL)
  target_include_directories(tomlplusplus
    INTERFACE $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>)
  add_library(tomlplusplus::tomlplusplus ALIAS tomlplusplus)
endif(USE_EXTERNAL_TOMLPLUSPLUS)

if(NOT TARGET tinycolormap)
  add_library(tinycolormap INTERFACE IMPORTED GLOBAL)
  target_include_directories(tinycolormap INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/tinycolormap/include>)
endif(NOT TARGET tinycolormap)
