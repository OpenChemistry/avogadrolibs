/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "volumegeometry.h"

#include "avogadrogl.h"
#include "bufferobject.h"
#include "camera.h"
#include "scene.h"
#include "shader.h"
#include "shaderprogram.h"
#include "visitor.h"

namespace Avogadro::Rendering {

VolumeGeometry::VolumeGeometry()
  : m_positiveColor(0, 255, 0), m_negativeColor(255, 0, 0)
{
}

VolumeGeometry::~VolumeGeometry() {}

VolumeGeometry::VolumeGeometry(const VolumeGeometry& other)
  : Drawable(other), m_positiveColor(other.m_positiveColor),
    m_negativeColor(other.m_negativeColor)
{
}

VolumeGeometry& VolumeGeometry::operator=(VolumeGeometry other)
{
  swap(*this, other);
  return *this;
}

void swap(VolumeGeometry& lhs, VolumeGeometry& rhs)
{
  using std::swap;
  swap(lhs.m_positiveColor, rhs.m_positiveColor);
  swap(lhs.m_negativeColor, rhs.m_negativeColor);
  swap(static_cast<Drawable&>(lhs), static_cast<Drawable&>(rhs));
}

void VolumeGeometry::accept(Visitor& visitor)
{
  visitor.visit(*this);
}

void VolumeGeometry::render(const Camera& camera)
{
  if (!m_cube || m_dirty)
    return;
}

void VolumeGeometry::clear()
{
  m_cube = nullptr;
  m_dirty = true;
}

void VolumeGeometry::setCube(const Core::Cube& cube)
{
  m_cube = &cube;
  m_dirty = true;

  Vector3f min = cube.min().cast<float>();
  Vector3f max = cube.max().cast<float>();

  // Update the bounding box
  // Front face
  m_boundingVertices[0] = min.x();
  m_boundingVertices[1] = min.y();
  m_boundingVertices[2] = max.z();

  m_boundingVertices[3] = max.x();
  m_boundingVertices[4] = min.y();
  m_boundingVertices[5] = max.z();

  m_boundingVertices[6] = max.x();
  m_boundingVertices[7] = max.y();
  m_boundingVertices[8] = max.z();

  m_boundingVertices[9] = min.x();
  m_boundingVertices[10] = max.y();
  m_boundingVertices[11] = max.z();

  // back face
  m_boundingVertices[12] = min.x();
  m_boundingVertices[13] = min.y();
  m_boundingVertices[14] = min.z();

  m_boundingVertices[15] = max.x();
  m_boundingVertices[16] = min.y();
  m_boundingVertices[17] = min.z();

  m_boundingVertices[18] = max.x();
  m_boundingVertices[19] = max.y();
  m_boundingVertices[20] = min.z();

  m_boundingVertices[21] = min.x();
  m_boundingVertices[22] = max.y();
  m_boundingVertices[23] = min.z();
}

} // End namespace Avogadro
