/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "glrendervisitor.h"

#include "arrowgeometry.h"
#include "curvegeometry.h"
#include "cylindergeometry.h"
#include "dashedlinegeometry.h"
#include "drawable.h"
#include "linestripgeometry.h"
#include "widelinegeometry.h"
#include "meshgeometry.h"
#include "spheregeometry.h"
#include "textlabel2d.h"
#include "textlabel3d.h"
#include "volumegeometry.h"

namespace Avogadro::Rendering {

GLRenderVisitor::GLRenderVisitor(const Camera& camera_,
                                 const TextRenderStrategy* trs)
  : m_camera(camera_), m_textRenderStrategy(trs), m_renderPass(NotRendering)
{
}

GLRenderVisitor::~GLRenderVisitor() {}

bool GLRenderVisitor::shouldRender(const Drawable& drawable) const
{
  return drawable.isVisible() && drawable.renderPass() == m_renderPass;
}

void GLRenderVisitor::visit(Drawable& geometry)
{
  if (shouldRender(geometry))
    geometry.render(m_camera);
}

void GLRenderVisitor::visit(SphereGeometry& geometry)
{
  if (shouldRender(geometry))
    geometry.render(m_camera);
}

void GLRenderVisitor::visit(CurveGeometry& geometry)
{
  if (shouldRender(geometry))
    geometry.render(m_camera);
}

void GLRenderVisitor::visit(CylinderGeometry& geometry)
{
  if (shouldRender(geometry))
    geometry.render(m_camera);
}

void GLRenderVisitor::visit(MeshGeometry& geometry)
{
  if (shouldRender(geometry))
    geometry.render(m_camera);
}

void GLRenderVisitor::visit(TextLabel2D& geometry)
{
  if (shouldRender(geometry)) {
    if (m_textRenderStrategy) {
      geometry.setPixelRatio(m_pixelRatio);
      geometry.buildTexture(*m_textRenderStrategy);
    }
    geometry.render(m_camera);
  }
}

void GLRenderVisitor::visit(TextLabel3D& geometry)
{
  if (shouldRender(geometry)) {
    if (m_textRenderStrategy) {
      geometry.setPixelRatio(m_pixelRatio);
      geometry.buildTexture(*m_textRenderStrategy);
    }
    geometry.render(m_camera);
  }
}

void GLRenderVisitor::visit(LineStripGeometry& geometry)
{
  if (shouldRender(geometry))
    geometry.render(m_camera);
}

void GLRenderVisitor::visit(WideLineGeometry& geometry)
{
  if (shouldRender(geometry))
    geometry.render(m_camera);
}

void GLRenderVisitor::visit(DashedLineGeometry& geometry)
{
  if (shouldRender(geometry))
    geometry.render(m_camera);
}

void GLRenderVisitor::visit(ArrowGeometry& geometry)
{
  if (shouldRender(geometry))
    geometry.render(m_camera);
}

void GLRenderVisitor::visit(VolumeGeometry& geometry)
{
  if (shouldRender(geometry))
    geometry.render(m_camera);
}

} // namespace Avogadro::Rendering
