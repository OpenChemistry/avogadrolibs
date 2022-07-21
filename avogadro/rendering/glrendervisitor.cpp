/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "glrendervisitor.h"

#include "ambientocclusionspheregeometry.h"
#include "curvegeometry.h"
#include "cylindergeometry.h"
#include "linestripgeometry.h"
#include "meshgeometry.h"
#include "spheregeometry.h"
#include "textlabel2d.h"
#include "textlabel3d.h"

namespace Avogadro::Rendering {

GLRenderVisitor::GLRenderVisitor(const Camera& camera_,
                                 const TextRenderStrategy* trs)
  : m_camera(camera_), m_textRenderStrategy(trs), m_renderPass(NotRendering)
{
}

GLRenderVisitor::~GLRenderVisitor()
{
}

void GLRenderVisitor::visit(Drawable& geometry)
{
  if (geometry.renderPass() == m_renderPass)
    geometry.render(m_camera);
}

void GLRenderVisitor::visit(SphereGeometry& geometry)
{
  if (geometry.renderPass() == m_renderPass)
    geometry.render(m_camera);
}

void GLRenderVisitor::visit(AmbientOcclusionSphereGeometry& geometry)
{
  if (geometry.renderPass() == m_renderPass)
    geometry.render(m_camera);
}

void GLRenderVisitor::visit(CurveGeometry& geometry)
{
  if (geometry.renderPass() == m_renderPass)
    geometry.render(m_camera);
}

void GLRenderVisitor::visit(CylinderGeometry& geometry)
{
  if (geometry.renderPass() == m_renderPass)
    geometry.render(m_camera);
}

void GLRenderVisitor::visit(MeshGeometry& geometry)
{
  if (geometry.renderPass() == m_renderPass)
    geometry.render(m_camera);
}

void GLRenderVisitor::visit(TextLabel2D& geometry)
{
  if (geometry.renderPass() == m_renderPass) {
    if (m_textRenderStrategy)
      geometry.buildTexture(*m_textRenderStrategy);
    geometry.render(m_camera);
  }
}

void GLRenderVisitor::visit(TextLabel3D& geometry)
{
  if (geometry.renderPass() == m_renderPass) {
    if (m_textRenderStrategy)
      geometry.buildTexture(*m_textRenderStrategy);
    geometry.render(m_camera);
  }
}

void GLRenderVisitor::visit(LineStripGeometry& geometry)
{
  if (geometry.renderPass() == m_renderPass)
    geometry.render(m_camera);
}

} // End namespace Avogadro
