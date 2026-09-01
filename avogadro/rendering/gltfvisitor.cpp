/******************************************************************************
 This source file is part of the Avogadro project.
******************************************************************************/

#include "gltfvisitor.h"

#include "ambientocclusionspheregeometry.h"
#include "cylindergeometry.h"
#include "linestripgeometry.h"
#include "meshgeometry.h"
#include "spheregeometry.h"

#include <Eigen/Geometry>

#include <cmath>
#include <iostream>
#include <sstream>

namespace Avogadro::Rendering {

using std::ostringstream;
using std::string;

GltfVisitor::GltfVisitor(const Camera& c)
  : m_camera(c), m_opacity(1.0f)
{
}

GltfVisitor::~GltfVisitor() {}

void GltfVisitor::begin()
{
  // Clear all buffers for a fresh export
  m_spheres.clear();
  m_cylinders.clear();
  m_meshVertices.clear();
  m_meshColors.clear();
  m_meshIndices.clear();
}

string GltfVisitor::end()
{
  // Build the final glTF JSON from collected geometry data
  return buildJson();
}

void GltfVisitor::visit(Drawable&) {}

void GltfVisitor::visit(SphereGeometry& geometry)
{
  // Collect all sphere data directly from the rendered scene geometry.
  // This captures live color, radius, opacity, and position — including
  // any user customizations — which FileFormat-based export misses.
  for (const auto& s : geometry.spheres()) {
    SphereData sd;
    sd.center = s.center;
    sd.radius = s.radius;
    sd.color  = s.color;
    m_spheres.push_back(sd);
  }
}

void GltfVisitor::visit(AmbientOcclusionSphereGeometry& geometry)
{
  // Treat AO spheres the same as regular spheres for export purposes
  for (const auto& s : geometry.spheres()) {
    SphereData sd;
    sd.center = s.center;
    sd.radius = s.radius;
    sd.color  = s.color;
    m_spheres.push_back(sd);
  }
}

void GltfVisitor::visit(CylinderGeometry& geometry)
{
  // Collect cylinder (bond) data with full scene color information
  for (const auto& c : geometry.cylinders()) {
    CylinderData cd;
    cd.end1   = c.end1;
    cd.end2   = c.end2;
    cd.radius = c.radius;
    cd.color  = c.color;
    m_cylinders.push_back(cd);
  }
}

void GltfVisitor::visit(MeshGeometry& geometry)
{
  // Collect mesh geometry (orbitals, surfaces, etc.)
  const auto& verts = geometry.vertices();
  if (verts.empty())
    return;

  unsigned int indexOffset = static_cast<unsigned int>(m_meshVertices.size());

  for (const auto& v : verts) {
    m_meshVertices.push_back(v.vertex);
    m_meshColors.push_back(v.color);
  }

  // Build triangle index list
  for (unsigned int i = 0; i < verts.size(); i += 3) {
    m_meshIndices.push_back(indexOffset + i);
    m_meshIndices.push_back(indexOffset + i + 1);
    m_meshIndices.push_back(indexOffset + i + 2);
  }
}

void GltfVisitor::visit(LineStripGeometry&)
{
  // Not currently exported to glTF
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

namespace {

// Write a compact JSON float array from a flat vector of floats
string floatArrayJson(const std::vector<float>& data)
{
  ostringstream os;
  os << "[";
  for (size_t i = 0; i < data.size(); ++i) {
    os << data[i];
    if (i + 1 < data.size())
      os << ",";
  }
  os << "]";
  return os.str();
}

// Approximate a sphere as an icosphere (1 subdivision) and emit triangles
// into position/color/index flat arrays.
void tessellateSphere(const Vector3f& center, float radius,
                      const Vector3ub& color,
                      std::vector<float>& positions,
                      std::vector<float>& colors,
                      std::vector<unsigned int>& indices)
{
  // Icosahedron vertices (unit sphere)
  const float t = (1.0f + std::sqrt(5.0f)) / 2.0f;
  const float s = 1.0f / std::sqrt(1.0f + t * t);

  const float vdata[12][3] = {
    {-s,  t*s, 0}, { s,  t*s, 0}, {-s, -t*s, 0}, { s, -t*s, 0},
    { 0, -s,  t*s}, { 0,  s,  t*s}, { 0, -s, -t*s}, { 0,  s, -t*s},
    { t*s, 0, -s}, { t*s, 0,  s}, {-t*s, 0, -s}, {-t*s, 0,  s}
  };

  const unsigned int tdata[20][3] = {
    {0,11,5},{0,5,1},{0,1,7},{0,7,10},{0,10,11},
    {1,5,9},{5,11,4},{11,10,2},{10,7,6},{7,1,8},
    {3,9,4},{3,4,2},{3,2,6},{3,6,8},{3,8,9},
    {4,9,5},{2,4,11},{6,2,10},{8,6,7},{9,8,1}
  };

  unsigned int base = static_cast<unsigned int>(positions.size() / 3);

  float r = color[0] / 255.0f;
  float g = color[1] / 255.0f;
  float b = color[2] / 255.0f;

  for (int i = 0; i < 12; ++i) {
    positions.push_back(center[0] + vdata[i][0] * radius);
    positions.push_back(center[1] + vdata[i][1] * radius);
    positions.push_back(center[2] + vdata[i][2] * radius);
    colors.push_back(r);
    colors.push_back(g);
    colors.push_back(b);
  }

  for (int i = 0; i < 20; ++i) {
    indices.push_back(base + tdata[i][0]);
    indices.push_back(base + tdata[i][1]);
    indices.push_back(base + tdata[i][2]);
  }
}

// Approximate a cylinder as a prism with N sides
void tesselateCylinder(const Vector3f& end1, const Vector3f& end2,
                       float radius, const Vector3ub& color,
                       std::vector<float>& positions,
                       std::vector<float>& colors,
                       std::vector<unsigned int>& indices,
                       int sides = 8)
{
  Vector3f axis = (end2 - end1).normalized();

  // Build an orthonormal basis around the axis
  Vector3f up = std::abs(axis[1]) < 0.9f ? Vector3f(0, 1, 0)
                                          : Vector3f(1, 0, 0);
  Vector3f u = axis.cross(up).normalized();
  Vector3f v = axis.cross(u);

  unsigned int base = static_cast<unsigned int>(positions.size() / 3);

  float r = color[0] / 255.0f;
  float g = color[1] / 255.0f;
  float b = color[2] / 255.0f;

  // Emit ring vertices at both ends
  for (int cap = 0; cap < 2; ++cap) {
    const Vector3f& center = (cap == 0) ? end1 : end2;
    for (int i = 0; i < sides; ++i) {
      float angle = 2.0f * M_PI * i / sides;
      Vector3f pt = center + radius * (std::cos(angle) * u + std::sin(angle) * v);
      positions.push_back(pt[0]);
      positions.push_back(pt[1]);
      positions.push_back(pt[2]);
      colors.push_back(r);
      colors.push_back(g);
      colors.push_back(b);
    }
  }

  // Side quads as two triangles each
  for (int i = 0; i < sides; ++i) {
    unsigned int a = base + i;
    unsigned int b2 = base + (i + 1) % sides;
    unsigned int c  = base + sides + i;
    unsigned int d  = base + sides + (i + 1) % sides;
    indices.push_back(a);  indices.push_back(b2); indices.push_back(c);
    indices.push_back(b2); indices.push_back(d);  indices.push_back(c);
  }
}

} // anonymous namespace

string GltfVisitor::buildJson() const
{
  // Flatten all geometry into a single position/color/index buffer
  std::vector<float> positions, colors;
  std::vector<unsigned int> indices;

  for (const auto& s : m_spheres)
    tessellateSphere(s.center, s.radius, s.color, positions, colors, indices);

  for (const auto& c : m_cylinders)
    tesselateCylinder(c.end1, c.end2, c.radius, c.color,
                      positions, colors, indices);

  // Append mesh geometry collected from MeshGeometry visitors
  unsigned int meshBase = static_cast<unsigned int>(positions.size() / 3);
  for (const auto& v : m_meshVertices) {
    positions.push_back(v[0]);
    positions.push_back(v[1]);
    positions.push_back(v[2]);
  }
  for (const auto& c : m_meshColors) {
    colors.push_back(c[0] / 255.0f);
    colors.push_back(c[1] / 255.0f);
    colors.push_back(c[2] / 255.0f);
  }
  for (auto idx : m_meshIndices)
    indices.push_back(meshBase + idx);

  // ---- glTF JSON assembly ----
  // Buffer sizes (in bytes)
  const size_t posBytes   = positions.size() * sizeof(float);
  const size_t colorBytes = colors.size()    * sizeof(float);
  const size_t idxBytes   = indices.size()   * sizeof(unsigned int);
  const size_t totalBytes = posBytes + colorBytes + idxBytes;

  // Byte offsets within the single buffer
  const size_t posOffset   = 0;
  const size_t colorOffset = posBytes;
  const size_t idxOffset   = posBytes + colorBytes;

  // Vertex count and index count
  const size_t vertCount = positions.size() / 3;
  const size_t idxCount  = indices.size();

  ostringstream json;
  json << "{\n"
       << "  \"asset\": {\"version\": \"2.0\", \"generator\": \"Avogadro2 GltfVisitor\"},\n"
       << "  \"scene\": 0,\n"
       << "  \"scenes\": [{\"nodes\": [0]}],\n"
       << "  \"nodes\": [{\"mesh\": 0}],\n"
       << "  \"meshes\": [{\n"
       << "    \"name\": \"molecule\",\n"
       << "    \"primitives\": [{\n"
       << "      \"attributes\": {\n"
       << "        \"POSITION\": 0,\n"
       << "        \"COLOR_0\": 1\n"
       << "      },\n"
       << "      \"indices\": 2,\n"
       << "      \"mode\": 4\n"  // TRIANGLES
       << "    }]\n"
       << "  }],\n"
       << "  \"accessors\": [\n"
       // Accessor 0: POSITION (VEC3 FLOAT)
       << "    {\n"
       << "      \"bufferView\": 0,\n"
       << "      \"byteOffset\": 0,\n"
       << "      \"componentType\": 5126,\n"  // FLOAT
       << "      \"count\": " << vertCount << ",\n"
       << "      \"type\": \"VEC3\"\n"
       << "    },\n"
       // Accessor 1: COLOR_0 (VEC3 FLOAT)
       << "    {\n"
       << "      \"bufferView\": 1,\n"
       << "      \"byteOffset\": 0,\n"
       << "      \"componentType\": 5126,\n"  // FLOAT
       << "      \"count\": " << vertCount << ",\n"
       << "      \"type\": \"VEC3\"\n"
       << "    },\n"
       // Accessor 2: indices (SCALAR UNSIGNED_INT)
       << "    {\n"
       << "      \"bufferView\": 2,\n"
       << "      \"byteOffset\": 0,\n"
       << "      \"componentType\": 5125,\n"  // UNSIGNED_INT
       << "      \"count\": " << idxCount << ",\n"
       << "      \"type\": \"SCALAR\"\n"
       << "    }\n"
       << "  ],\n"
       << "  \"bufferViews\": [\n"
       // BufferView 0: positions
       << "    {\"buffer\": 0, \"byteOffset\": " << posOffset
       << ", \"byteLength\": " << posBytes << "},\n"
       // BufferView 1: colors
       << "    {\"buffer\": 0, \"byteOffset\": " << colorOffset
       << ", \"byteLength\": " << colorBytes << "},\n"
       // BufferView 2: indices
       << "    {\"buffer\": 0, \"byteOffset\": " << idxOffset
       << ", \"byteLength\": " << idxBytes << "}\n"
       << "  ],\n"
       << "  \"buffers\": [{\n"
       << "    \"byteLength\": " << totalBytes << "\n"
       // Note: binary buffer (.bin) is written separately by the plugin
       << "  }]\n"
       << "}\n";

  return json.str();
}

} // namespace Avogadro::Rendering
