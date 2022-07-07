/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "mesh.h"

#include "mutex.h"
#include "neighborperceiver.h"

using std::vector;

namespace Avogadro::Core {

Mesh::Mesh() : m_stable(true), m_other(0), m_cube(0), m_lock(new Mutex)
{
  m_vertices.reserve(100);
  m_normals.reserve(100);
  m_colors.reserve(1);
}

Mesh::Mesh(const Mesh& other)
  : m_vertices(other.m_vertices), m_normals(other.m_normals),
    m_colors(other.m_colors), m_name(other.m_name), m_stable(true),
    m_isoValue(other.m_isoValue), m_other(other.m_other), m_cube(other.m_cube),
    m_lock(new Mutex)
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
    for (const auto & value : values)
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
    for (const auto & value : values)
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
    return &(m_colors[0]);
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
  if (m_vertices.size() == m_normals.size()) {
    if (m_colors.size() == 1 || m_colors.size() == m_vertices.size())
      return true;
    else
      return false;
  } else {
    return false;
  }
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
  m_normals = other.m_vertices;
  m_colors = other.m_colors;
  m_name = other.m_name;
  m_isoValue = other.m_isoValue;

  return *this;
}

void Mesh::smooth(int iterationCount)
{
  if (m_vertices.size() == 0)
    return;
  if (iterationCount <= 0)
    return;

  // Map vertices to a plane and pass them to NeighborPerceiver
  // a line gives less performance, and a volume offers no more benefit
  Array<Vector3> planarList(m_vertices.size());
  for (size_t i = 0; i < m_vertices.size(); i++)
    // Empirical constant to make the distribution more homogeneous
    planarList[i] = Vector3(
      double(m_vertices[i](0) + 1.31*m_vertices[i](1)),
    0.0, m_vertices[i](2));
  NeighborPerceiver perceiver(planarList, 0.1);

  // Identify degenerate vertices
  std::vector<int> indexToVertexID(m_vertices.size(), -1);
  std::vector<std::vector<size_t>> vertexIDToIndices;
  Array<size_t> neighbors;
  for (size_t i = 0; i < m_vertices.size(); i++) {
    if (indexToVertexID[i] != -1)
      continue;
    perceiver.getNeighborsInclusiveInPlace(neighbors, planarList[i]);
    size_t vertexID = vertexIDToIndices.size();
    for (size_t n: neighbors) {
      if ((m_vertices[n] - m_vertices[i]).norm() < 0.0001) {
        if (vertexID == vertexIDToIndices.size())
          vertexIDToIndices.emplace_back();
        indexToVertexID[n] = vertexID;
        vertexIDToIndices[vertexID].push_back(n);
      }
    }
  }

  // Compute 1-ring
  std::vector<std::vector<size_t>> vertexIDTo1Ring(vertexIDToIndices.size());
  for (size_t id = 0; id < vertexIDToIndices.size(); id++) {
    for (size_t v: vertexIDToIndices[id]) {
      size_t relative = v % 3;
      size_t triangle = v - relative;
      std::array<size_t, 2> candidates{{
        triangle + (relative + 1) % 3,
        triangle + (relative + 2) % 3
      }};
      for (size_t candidate: candidates) {
        size_t newID = indexToVertexID[candidate];
        if (std::find(vertexIDToIndices[id].begin(), vertexIDToIndices[id].end(), newID)
        == vertexIDToIndices[id].end())
          vertexIDTo1Ring[id].push_back(newID);
      }
    }
  }

  float weight = 1.0f;
  for (int iteration = iterationCount; iteration > 0; iteration--) {
    // Copy vertices by ID into source array
    std::vector<Vector3f> inputVertices(vertexIDToIndices.size());
    for (size_t id = 0; id < vertexIDToIndices.size(); id++)
      inputVertices[id] = m_vertices[vertexIDToIndices[id][0]];

    // Apply Laplacian smoothing
    for (size_t id = 0; id < inputVertices.size(); id++) {
      Vector3f output(0.0f, 0.0f, 0.0f);
      for (size_t neighbor: vertexIDTo1Ring[id])
        output += inputVertices[neighbor];
      output += weight * inputVertices[id];
      output *= 1.0f / (weight + vertexIDTo1Ring[id].size());
      if (iteration == 1)
        for (size_t i: vertexIDToIndices[id])
          m_vertices[i] = output;
      else
        m_vertices[vertexIDToIndices[id][0]] = output;
    }
  }

  // Recompute normals
  for (auto & vertexIDToIndice : vertexIDToIndices) {
    Vector3f normal(0.0f, 0.0f, 0.0f);
    for (size_t v: vertexIDToIndice) {
      size_t relative = v % 3;
      size_t triangle = v - relative;
      Vector3f &a = m_vertices[v];
      Vector3f &b = m_vertices[triangle + (relative + 1) % 3];
      Vector3f &c = m_vertices[triangle + (relative + 2) % 3];
      Vector3f triangleNormal = (b - a).cross(c - a);
      normal += triangleNormal.normalized();
    }
    for (size_t i: vertexIDToIndice)
      m_normals[i] = normal.normalized();
  }
}

} // End namespace Avogadro
