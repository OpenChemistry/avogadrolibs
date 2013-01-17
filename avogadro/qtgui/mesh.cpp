/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2008 Marcus D. Hanwell
  Copyright 2012 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "mesh.h"

#include <QReadWriteLock>
#include <QDebug>

using Eigen::Vector3f;
using std::vector;

namespace Avogadro {
namespace QtGui {

Mesh::Mesh() : m_stable(true), m_other(0), m_cube(0), m_lock(new QReadWriteLock)
{
  m_vertices.reserve(100);
  m_normals.reserve(100);
  m_colors.reserve(1);
}

Mesh::~Mesh()
{
  delete m_lock;
  m_lock = 0;
}

bool Mesh::reserve(unsigned int size, bool useColors)
{
  QWriteLocker locker(m_lock);
  m_vertices.reserve(size);
  m_normals.reserve(size);
  if (useColors)
    m_colors.reserve(size);
  return true;
}

void Mesh::setStable(bool isStable)
{
  QWriteLocker locker(m_lock);
  m_stable = isStable;
}

bool Mesh::stable()
{
  QReadLocker locker(m_lock);
  return m_stable;
}

const vector<Vector3f> & Mesh::vertices() const
{
  QReadLocker locker(m_lock);
  return m_vertices;
}

const Vector3f * Mesh::vertex(int n) const
{
  QReadLocker locker(m_lock);
  return &(m_vertices[n]);
}

bool Mesh::setVertices(const vector<Vector3f> &values)
{
  QWriteLocker locker(m_lock);
  m_vertices.clear();
  m_vertices = values;
  return true;
}

bool Mesh::addVertices(const vector<Vector3f> &values)
{
  QWriteLocker locker(m_lock);
  if (m_vertices.capacity() < m_vertices.size() + values.size())
    m_vertices.reserve(m_vertices.capacity() * 2);
  if (values.size() % 3 == 0) {
    for (unsigned int i = 0; i < values.size(); ++i)
      m_vertices.push_back(values.at(i));
    return true;
  }
  else {
    qDebug() << "Error adding vertices." << values.size();
    return false;
  }
}

const vector<Vector3f> & Mesh::normals() const
{
  QReadLocker locker(m_lock);
  return m_normals;
}

const Vector3f * Mesh::normal(int n) const
{
  QReadLocker locker(m_lock);
  return &(m_normals[n * 3]);
}

bool Mesh::setNormals(const vector<Vector3f> &values)
{
  QWriteLocker locker(m_lock);
  m_normals.clear();
  m_normals = values;
  return true;
}

bool Mesh::addNormals(const vector<Vector3f> &values)
{
  QWriteLocker locker(m_lock);
  if (m_normals.capacity() < m_normals.size() + values.size())
    m_normals.reserve(m_normals.capacity() * 2);
  if (values.size() % 3 == 0) {
    for (unsigned int i = 0; i < values.size(); ++i)
      m_normals.push_back(values.at(i));
    return true;
  }
  else {
    qDebug() << "Error adding normals." << values.size();
    return false;
  }
}

const vector<Color3f> & Mesh::colors() const
{
  QReadLocker locker(m_lock);
  return m_colors;
}

const Color3f * Mesh::color(int n) const
{
  QReadLocker locker(m_lock);
  // If there is only one color return that, otherwise colored by vertex.
  if (m_colors.size() == 1)
    return &(m_colors[0]);
  else
    return &(m_colors[n*3]);
}

bool Mesh::setColors(const vector<Color3f> &values)
{
  QWriteLocker locerk(m_lock);
  m_colors.clear();
  m_colors = values;
  return true;
}

bool Mesh::addColors(const vector<Color3f> &values)
{
  QWriteLocker locker(m_lock);
  if (m_colors.capacity() < m_colors.size() + values.size())
    m_colors.reserve(m_colors.capacity() * 2);
  if (values.size() % 3 == 0) {
    for (unsigned int i = 0; i < values.size(); ++i)
      m_colors.push_back(values.at(i));
    return true;
  }
  else {
    qDebug() << "Error adding colors." << values.size();
    return false;
  }
}

bool Mesh::valid() const
{
  QWriteLocker locker(m_lock);
  if (m_vertices.size() == m_normals.size()) {
    if (m_colors.size() == 1 || m_colors.size() == m_vertices.size())
      return true;
    else
      return false;
  }
  else {
    return false;
  }
}

bool Mesh::clear()
{
  QWriteLocker locker(m_lock);
  m_vertices.clear();
  m_normals.clear();
  m_colors.clear();
  return true;
}

Mesh& Mesh::operator=(const Mesh& other)
{
  QWriteLocker locker(m_lock);
  QReadLocker oLock(other.m_lock);
  m_vertices = other.m_vertices;
  m_normals = other.m_vertices;
  m_colors = other.m_colors;
  m_name = other.m_name;
  return *this;
}

QReadWriteLock * Mesh::lock() const
{
  return m_lock;
}

} // End namespace QtGui
} // End namespace Avogadro
