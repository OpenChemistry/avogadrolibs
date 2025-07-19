/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "mesh.h"

#include "mutex.h"
#include "neighborperceiver.h"

namespace Avogadro::Core {

Mesh::Mesh() : m_stable(true), m_other(0), m_cube(0), m_lock(new Mutex)
{
  m_vertices.reserve(100);
  m_normals.reserve(100);
  m_colors.reserve(1);
}

Mesh::Mesh(const Mesh& other)
  : m_vertices(other.m_vertices), m_normals(other.m_normals),
    m_colors(other.m_colors), m_triangles(other.m_triangles),
    m_name(other.m_name), m_stable(true), m_isoValue(other.m_isoValue),
    m_other(other.m_other), m_cube(other.m_cube), m_lock(new Mutex)
{
}

Mesh::~Mesh()
{
  delete m_lock;
  m_lock = nullptr;
}

bool Mesh::reserve(unsigned int size, bool useColors)
{
  m_vertices.reserve(size);
  m_normals.reserve(size);
  if (useColors)
    m_colors.reserve(size);
  return true;
}

void Mesh::setStable(bool isStable)
{
  m_stable = isStable;
}

bool Mesh::stable()
{
  return m_stable;
}

const Core::Array<Vector3f>& Mesh::vertices() const
{
  return m_vertices;
}

const Vector3f* Mesh::vertex(int n) const
{
  return &(m_vertices[n * 3]);
}

bool Mesh::setTriangles(const Core::Array<Vector3f>& values)
{
  m_triangles.clear();
  m_triangles = values;
  return true;
}

const Core::Array<Vector3f>& Mesh::triangles() const
{
  return m_triangles;
}

bool Mesh::setVertices(const Core::Array<Vector3f>& values)
{
  m_vertices.clear();
  m_vertices = values;
  return true;
}

bool Mesh::addVertices(const Core::Array<Vector3f>& values)
{
  if (m_vertices.capacity() < m_vertices.size() + values.size())
    m_vertices.reserve(m_vertices.capacity() * 2);
  if (values.size() % 3 == 0) {
    for (const auto& value : values)
      m_vertices.push_back(value);
    return true;
  } else {
    return false;
  }
}

const Core::Array<Vector3f>& Mesh::normals() const
{
  return m_normals;
}

const Vector3f* Mesh::normal(int n) const
{
  return &(m_normals[n * 3]);
}

bool Mesh::setNormals(const Core::Array<Vector3f>& values)
{
  m_normals.clear();
  m_normals = values;
  return true;
}

bool Mesh::addNormals(const Core::Array<Vector3f>& values)
{
  if (m_normals.capacity() < m_normals.size() + values.size())
    m_normals.reserve(m_normals.capacity() * 2);
  if (values.size() % 3 == 0) {
    for (const auto& value : values)
      m_normals.push_back(value);
    return true;
  } else {
    return false;
  }
}

const Core::Array<Color3f>& Mesh::colors() const
{
  return m_colors;
}

const Color3f* Mesh::color(int n) const
{
  // If there is only one color return that, otherwise colored by vertex.
  if (m_colors.size() == 1)
    return m_colors.data();
  else
    return &(m_colors[n * 3]);
}

bool Mesh::setColors(const Core::Array<Color3f>& values)
{
  m_colors.clear();
  m_colors = values;
  return true;
}

bool Mesh::addColors(const Core::Array<Color3f>& values)
{
  if (m_colors.capacity() < m_colors.size() + values.size())
    m_colors.reserve(m_colors.capacity() * 2);
  if (values.size() % 3 == 0) {
    for (auto value : values)
      m_colors.push_back(value);
    return true;
  } else {
    return false;
  }
}

bool Mesh::valid() const
{
  return (m_vertices.size() == m_normals.size()) &&
         (m_colors.size() == 1 || m_colors.size() == m_vertices.size());
}

bool Mesh::clear()
{
  m_vertices.clear();
  m_normals.clear();
  m_colors.clear();
  return true;
}

Mesh& Mesh::operator=(const Mesh& other)
{
  m_vertices = other.m_vertices;
  m_normals = other.m_normals;
  m_colors = other.m_colors;
  m_name = other.m_name;
  m_isoValue = other.m_isoValue;
  m_triangles = other.m_triangles;

  return *this;
}

void Mesh::smooth(int iterationCount)
{
  if (m_vertices.empty() || iterationCount <= 0)
    return;

  // Build vertex adjacency information from triangles (1-ring)
  std::vector<std::vector<size_t>> adjacencyList(m_vertices.size());
  for (const auto& tri : m_triangles) {
    size_t i = static_cast<size_t>(tri.x());
    size_t j = static_cast<size_t>(tri.y());
    size_t k = static_cast<size_t>(tri.z());

    adjacencyList[i].push_back(j);
    adjacencyList[i].push_back(k);
    adjacencyList[j].push_back(i);
    adjacencyList[j].push_back(k);
    adjacencyList[k].push_back(i);
    adjacencyList[k].push_back(j);
  }

  // Remove duplicate neighbors and sort for faster lookups later (if needed)
  for (auto& neighbors : adjacencyList) {
    std::sort(neighbors.begin(), neighbors.end());
    neighbors.erase(std::unique(neighbors.begin(), neighbors.end()),
                    neighbors.end());
  }

  float weight = 1.0f;
  for (int iteration = 0; iteration < iterationCount; ++iteration) {
    Array<Vector3f> newVertices = m_vertices; // Store smoothed vertices

    for (size_t i = 0; i < m_vertices.size(); ++i) {
      Vector3f sum(0.0f, 0.0f, 0.0f);
      size_t neighborCount = adjacencyList[i].size();

      if (neighborCount > 0) { // Prevent division by zero for isolated vertices
        for (size_t neighbor : adjacencyList[i]) {
          sum += m_vertices[neighbor];
        }
        sum += weight * m_vertices[i];
        newVertices[i] = sum / (weight + neighborCount);
      } // Else keep the original vertex position if isolated
    }
    m_vertices = newVertices; // Update vertices after processing all
  }

  m_normals.clear();
  m_normals.resize(m_vertices.size(), Vector3f(0.0f, 0.0f, 0.0f));

  for (const auto& tri : m_triangles) {
    size_t i = static_cast<size_t>(tri.x());
    size_t j = static_cast<size_t>(tri.y());
    size_t k = static_cast<size_t>(tri.z());

    Vector3f a = m_vertices[i];
    Vector3f b = m_vertices[j];
    Vector3f c = m_vertices[k];
    Vector3f triangleNormal = (b - a).cross(c - a).normalized();

    m_normals[i] += triangleNormal;
    m_normals[j] += triangleNormal;
    m_normals[k] += triangleNormal;
  }

  for (auto& normal : m_normals) {
    normal.normalize();
  }
}

} // End namespace Avogadro::Core
