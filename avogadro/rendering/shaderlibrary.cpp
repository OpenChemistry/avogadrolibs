/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "shaderlibrary_p.h"

#include "shader.h"
#include "shaderprogram.h"

namespace {
#include "curves_vs.h"
#include "cylinders_fs.h"
#include "cylinders_vs.h"
#include "dashedline_fs.h"
#include "dashedline_vs.h"
#include "linestrip_fs.h"
#include "linestrip_vs.h"
#include "mesh_fs.h"
#include "mesh_vs.h"
#include "spheres_fs.h"
#include "spheres_vs.h"
#include "textlabelbase_fs.h"
#include "textlabelbase_vs.h"
#include "wideline_fs.h"
#include "wideline_vs.h"
} // namespace

#include <cstddef>
#include <iostream>

namespace Avogadro::Rendering {

namespace {

struct Sources
{
  const char* vertex;
  const char* fragment;
};

Sources sourcesFor(ShaderId id)
{
  switch (id) {
    case ShaderId::Spheres:
      return { spheres_vs, spheres_fs };
    case ShaderId::Cylinders:
      return { cylinders_vs, cylinders_fs };
    case ShaderId::Mesh:
      return { mesh_vs, mesh_fs };
    case ShaderId::Curves:
      // CurveGeometry shades with the cylinder fragment shader.
      return { curves_vs, cylinders_fs };
    case ShaderId::TextLabel:
      return { textlabelbase_vs, textlabelbase_fs };
    case ShaderId::LineStrip:
      return { linestrip_vs, linestrip_fs };
    case ShaderId::WideLine:
      return { wideline_vs, wideline_fs };
    case ShaderId::DashedLine:
      return { dashedline_vs, dashedline_fs };
    default:
      return { nullptr, nullptr };
  }
}

} // namespace

ShaderLibrary::ShaderLibrary() = default;

ShaderLibrary::~ShaderLibrary()
{
  releaseResources();
}

ShaderProgram* ShaderLibrary::program(ShaderId id)
{
  const auto index = static_cast<std::size_t>(id);
  if (index >= m_entries.size())
    return nullptr;

  Entry& entry = m_entries[index];
  if (entry.program)
    return entry.program.get();
  if (entry.failed)
    return nullptr;

  const Sources sources = sourcesFor(id);
  if (sources.vertex == nullptr || sources.fragment == nullptr) {
    entry.failed = true;
    return nullptr;
  }

  Shader vertexShader(Shader::Vertex, sources.vertex);
  Shader fragmentShader(Shader::Fragment, sources.fragment);
  auto program = std::make_unique<ShaderProgram>();

  bool ok = true;
  if (!vertexShader.compile()) {
    std::cout << vertexShader.error() << '\n';
    ok = false;
  }
  if (!fragmentShader.compile()) {
    std::cout << fragmentShader.error() << '\n';
    ok = false;
  }
  if (ok && (!program->attachShader(vertexShader) ||
             !program->attachShader(fragmentShader))) {
    std::cout << program->error() << '\n';
    ok = false;
  }
  if (ok && !program->link()) {
    std::cout << program->error() << '\n';
    ok = false;
  }

  // The linked program no longer needs the shader objects. Detach them so the
  // driver can free them, and delete them (cleanup() ignores a shader that
  // never compiled).
  if (ok) {
    program->detachShader(vertexShader);
    program->detachShader(fragmentShader);
  }
  vertexShader.cleanup();
  fragmentShader.cleanup();

  if (!ok) {
    entry.failed = true;
    return nullptr; // ~ShaderProgram deletes any half-built program.
  }

  entry.program = std::move(program);
  return entry.program.get();
}

void ShaderLibrary::releaseResources()
{
  for (Entry& entry : m_entries) {
    entry.program.reset();
    entry.failed = false;
  }
}

} // namespace Avogadro::Rendering
