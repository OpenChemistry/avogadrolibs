/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "plyvisitor.h"

#include <sstream>

namespace Avogadro::Rendering {

PLYVisitor::PLYVisitor(const Camera& c)
  : m_camera(c), m_backgroundColor(255, 255, 255),
    m_ambientColor(100, 100, 100), m_aspectRatio(800.0f / 600.0f)
{
}

PLYVisitor::~PLYVisitor() = default;

std::string PLYVisitor::end()
{
  size_t vertexCount = 0;
  size_t faceCount = 0;
  for (const auto& mesh : meshes()) {
    vertexCount += mesh.positions.size();
    faceCount += mesh.indices.size() / 3;
  }

  std::ostringstream out;
  out << "ply\n"
      << "format ascii 1.0\n"
      << "element vertex " << vertexCount << '\n'
      << "property float x\n"
      << "property float y\n"
      << "property float z\n"
      << "property float nx\n"
      << "property float ny\n"
      << "property float nz\n"
      << "property float red\n"
      << "property float green\n"
      << "property float blue\n"
      << "property float alpha\n"
      << "element face " << faceCount << '\n'
      << "property list uchar uint vertex_index\n"
      << "end_header\n";

  for (const auto& mesh : meshes()) {
    for (size_t i = 0; i < mesh.positions.size(); ++i) {
      const Vector3f& p = mesh.positions[i];
      const Vector3f& n = mesh.normals[i];
      const Vector4ub& c = mesh.colors[i];
      out << p[0] << ' ' << p[1] << ' ' << p[2] << ' ' << n[0] << ' ' << n[1]
          << ' ' << n[2] << ' ' << c[0] / 255.0f << ' ' << c[1] / 255.0f << ' '
          << c[2] / 255.0f << ' ' << c[3] / 255.0f << '\n';
    }
  }

  // Faces refer to the global vertex numbering.
  size_t offset = 0;
  for (const auto& mesh : meshes()) {
    for (size_t i = 0; i + 2 < mesh.indices.size(); i += 3) {
      out << "3 " << mesh.indices[i] + offset << ' '
          << mesh.indices[i + 1] + offset << ' ' << mesh.indices[i + 2] + offset
          << '\n';
    }
    offset += mesh.positions.size();
  }

  return out.str();
}

} // namespace Avogadro::Rendering
