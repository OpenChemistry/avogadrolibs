find_package(OpenGL REQUIRED)
find_package(GLEW REQUIRED)

if(WIN32 AND NOT BUILD_SHARED_LIBS)
  add_definitions(-DGLEW_STATIC)
endif()

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
  visitor.h
  volumegeometry.h
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
  visitor.cpp
  volumegeometry.cpp
  vrmlvisitor.cpp
  ambientocclusionspheregeometry.cpp
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
  "mesh_opaque_fs.glsl"
  "mesh_vs.glsl"
  "solid_vs.glsl"
  "solid_first_fs.glsl"
  "spheres_fs.glsl"
  "spheres_vs.glsl"
  "sphere_ao_depth_vs.glsl"
  "sphere_ao_depth_fs.glsl"
  "sphere_ao_bake_vs.glsl"
  "sphere_ao_bake_fs.glsl"
  "sphere_ao_render_vs.glsl"
  "sphere_ao_render_fs.glsl"
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
    COMMAND encodefile
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
