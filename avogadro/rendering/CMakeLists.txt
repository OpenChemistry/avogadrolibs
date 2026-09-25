find_package(OpenGL REQUIRED)
find_package(GLEW REQUIRED)

# GLEW_STATIC switches glew.h from __declspec(dllimport) to plain externs, so
# it has to describe how the GLEW we found was built. BUILD_SHARED_LIBS says
# how *we* build our own libraries and nothing at all about GLEW: a static
# avogadrolibs against a system GLEW DLL -- which is what the Windows fuzz job
# builds -- defined it wrongly and left every __glew* symbol undefined.
get_target_property(_glew_type GLEW::GLEW TYPE)
if(WIN32)
  if(_glew_type STREQUAL "STATIC_LIBRARY")
    add_definitions(-DGLEW_STATIC)
  elseif(_glew_type STREQUAL "UNKNOWN_LIBRARY" AND NOT BUILD_SHARED_LIBS)
    # FindGLEW in module mode records no type. The superbuild builds its own
    # GLEW to follow BUILD_SHARED_LIBS, so fall back to that inference there.
    add_definitions(-DGLEW_STATIC)
  endif()
endif()
unset(_glew_type)

add_library(Rendering)

avogadro_headers(Rendering
  arcsector.h
  arcstrip.h
  arrowgeometry.h
  avogadrogl.h
  avogadrorendering.h
  beziergeometry.h
  bsplinegeometry.h
  bufferobject.h
  camera.h
  cartoongeometry.h
  curvegeometry.h
  cylindergeometry.h
  dashedlinegeometry.h
  drawable.h
  geometrynode.h
  geometryvisitor.h
  groupnode.h
  glrenderer.h
  glrendervisitor.h
  linestripgeometry.h
  meshgeometry.h
  node.h
  packedvertex.h
  plyvisitor.h
  povrayvisitor.h
  primitive.h
  quad.h
  quadoutline.h
  scene.h
  shader.h
  shaderprogram.h
  solidpipeline.h
  spheregeometry.h
  textlabel2d.h
  textlabel3d.h
  textlabelbase.h
  textproperties.h
  textrenderstrategy.h
  texture2d.h
  transformnode.h
  vertexarrayobject.h
  visitor.h
  volumegeometry.h
  widelinegeometry.h
  vrmlvisitor.h
)

target_sources(Rendering PRIVATE
  arcsector.cpp
  arcstrip.cpp
  arrowgeometry.cpp
  beziergeometry.cpp
  bufferobject.cpp
  bsplinegeometry.cpp
  cartoongeometry.cpp
  camera.cpp
  curvegeometry.cpp
  cylindergeometry.cpp
  dashedlinegeometry.cpp
  drawable.cpp
  geometrynode.cpp
  geometryvisitor.cpp
  groupnode.cpp
  glrenderer.cpp
  glrendervisitor.cpp
  linestripgeometry.cpp
  meshgeometry.cpp
  node.cpp
  plyvisitor.cpp
  povrayvisitor.cpp
  quad.cpp
  quadoutline.cpp
  scene.cpp
  shader.cpp
  shaderprogram.cpp
  solidpipeline.cpp
  spheregeometry.cpp
  textlabel2d.cpp
  textlabel3d.cpp
  textlabelbase.cpp
  textproperties.cpp
  textrenderstrategy.cpp
  texture2d.cpp
  transformnode.cpp
  vertexarrayobject.cpp
  visitor.cpp
  volumegeometry.cpp
  vrmlvisitor.cpp
  widelinegeometry.cpp
)

set(shader_files
  "arrow_vs.glsl"
  "cylinders_fs.glsl"
  "cylinders_vs.glsl"
  "dashedline_fs.glsl"
  "dashedline_vs.glsl"
  "linestrip_fs.glsl"
  "linestrip_vs.glsl"
  "mesh_fs.glsl"
  "mesh_vs.glsl"
  "solid_vs.glsl"
  "solid_first_fs.glsl"
  "solid_ao_fs.glsl"
  "volume_box_fs.glsl"
  "volume_box_vs.glsl"
  "volume_fs.glsl"
  "volume_vs.glsl"
  "wideline_fs.glsl"
  "wideline_vs.glsl"
  "spheres_fs.glsl"
  "spheres_vs.glsl"
  "textlabelbase_fs.glsl"
  "textlabelbase_vs.glsl"
)
foreach(file ${shader_files})
  get_filename_component(file_we ${file} NAME_WE)
  set(src  ${CMAKE_CURRENT_SOURCE_DIR}/${file})
  set(resh ${CMAKE_CURRENT_BINARY_DIR}/${file_we}.h)
  list(APPEND shader_h_files ${resh})
  add_custom_command(
    OUTPUT ${resh}
    DEPENDS ${src} encodefile
    COMMAND ${CMAKE_CROSSCOMPILING_EMULATOR} $<TARGET_FILE:encodefile>
    ARGS ${src} ${resh} ${file_we}
    COMMENT "Encoding ${src}"
    )
endforeach()
target_sources(Rendering PRIVATE
  FILE_SET shaders TYPE HEADERS
  BASE_DIRS ${CMAKE_CURRENT_BINARY_DIR}
  FILES ${shader_h_files})

avogadro_add_library(Rendering)
target_link_libraries(Rendering
  PUBLIC
    Avogadro::Headers
  PRIVATE
    Avogadro::Core # Needed for an emum in residue.h that we should move, maybe others.
    GLEW::GLEW
    OpenGL::GL)

if(USE_3DCONNEXION AND (WIN32 OR APPLE))
  target_compile_definitions(Rendering PUBLIC _3DCONNEXION)
endif()
