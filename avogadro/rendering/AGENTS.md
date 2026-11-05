# avogadro/rendering

The OpenGL 4.0 Core Profile renderer: the scene graph (`Scene`, `GroupNode`,
`GeometryNode`, `Drawable`), geometry types (spheres, cylinders, meshes,
curves, labels, volumes), `Camera`, `GLRenderer` and its render passes, GLSL
shaders, and visitors that export the scene (POV-Ray, PLY, VRML,
tessellation).

See the top-level [AGENTS.md](../../AGENTS.md) for the module map and the
rules that apply everywhere.

## Why it is separate

- **All OpenGL calls live here.** Nothing else in the libraries talks to GL
  directly; `qtopengl` only provides the Qt widget and context around it.
- **No Qt.** `Rendering` is built even when `USE_QT=OFF` and links only the
  core headers and Eigen publicly. Do not add Qt types.
- **It draws geometry, not molecules.** The renderer never sees a `Molecule`.
  Scene plugins in `qtplugins/` (ball-and-stick, cartoons, surfaces, labels)
  turn the molecule into nodes in `ScenePlugin::process()`. A new way of
  *showing* a molecule is usually a new scene plugin built from existing
  geometry types; a new geometry type is needed only for a new primitive.
- Export visitors walk the same scene graph, so a new geometry type is
  silently missing from exports until you add it to the visitors that should
  handle it (POV-Ray, VRML, PLY, tessellation).

## Things to know

- Target OpenGL 4.0 Core Profile. Shaders start with `#version 400`. No
  fixed-function or compatibility-profile calls: macOS offers only a 2.1
  compatibility context or a core profile.
- Shaders are `.glsl` files embedded as strings in generated headers at build
  time. To add one, add it to `shader_files` in [CMakeLists.txt](CMakeLists.txt).
- Leave GL state as you found it. Use the RAII guards (for example
  [blendstateguard_p.h](blendstateguard_p.h)) rather than hand-written
  enable/disable pairs that an early return can skip.
- Rendering runs every frame, and molecules can have hundreds of thousands of
  atoms. Avoid per-frame allocation and per-atom virtual calls in hot loops,
  and upload buffers only when the data changes. Measure performance in a
  Release build, plugged in to power.
- Translucent geometry is drawn in a separate pass; set the drawable's render
  pass rather than changing blending yourself.

## Tests

`tests/rendering/` runs **without a GL context**, so it can only test code
that makes no GL calls: cameras, nodes, geometry generation, curves and
visitors. Some classes (text labels, for example) call GL from their
constructors and cannot be tested there. Keep GL calls out of constructors
and geometry generation where you can, so the logic stays testable. GL-context
tests live in `tests/qtopengl/`.
