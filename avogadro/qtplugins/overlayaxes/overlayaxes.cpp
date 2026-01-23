/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "overlayaxes.h"

#include <avogadro/rendering/arrowgeometry.h>
#include <avogadro/rendering/avogadrogl.h>
#include <avogadro/rendering/camera.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/groupnode.h>
#include <avogadro/rendering/scene.h>
#include <avogadro/qtopengl/glwidget.h>

#include <avogadro/core/vector.h>

using Avogadro::Vector3f;
using Avogadro::Vector3ub;
using Avogadro::Rendering::ArrowGeometry;
using Avogadro::Rendering::Camera;
using Avogadro::Rendering::GeometryNode;
using Avogadro::Rendering::GroupNode;
using Eigen::Affine3f;

namespace {

// Arrow geometry class that overrides the camera used in rendering
// to display in a corner of the screen.
class OverlayArrowGeometry : public ArrowGeometry
{
public:
  OverlayArrowGeometry() { setRenderPass(Avogadro::Rendering::Overlay3DPass); }
  ~OverlayArrowGeometry() override {}

  void render(const Camera& camera) override;
};

void OverlayArrowGeometry::render(const Camera& camera)
{
  // Swap in a new viewport/camera for the overlay
  // Keep the rotation, lose the translation:
  Affine3f mv(camera.modelView());
  mv.matrix().block<3, 1>(0, 3) = Vector3f::Zero();

  // Save the actual viewport - works better on high resolution screens
  GLint viewport[4];
  glGetIntegerv(GL_VIEWPORT, viewport);

  // The largest window dimension, used to scale the axes
  const int maxDim = std::max(viewport[2], viewport[3]);

  Camera arrowCamera(camera);
  arrowCamera.setViewport(maxDim / 10, maxDim / 10);
  arrowCamera.setModelView(mv);
  // Reset orthographic scale so axes are constant size regardless of zoom
  arrowCamera.setOrthographicScale(1.0f);
  arrowCamera.calculateOrthographic(-1.f, 1.f, -1.f, 1.f, -1.f, 1.f);

  glViewport(static_cast<GLint>(10), static_cast<GLsizei>(10),
             static_cast<GLint>(arrowCamera.width()),
             static_cast<GLsizei>(arrowCamera.height()));

  ArrowGeometry::render(arrowCamera);

  glViewport(viewport[0], viewport[1], viewport[2], viewport[3]);
}

} // namespace

namespace Avogadro::QtPlugins {

class OverlayAxes::RenderImpl
{
public:
  RenderImpl();
  ~RenderImpl();

  OverlayArrowGeometry* arrows;
};

OverlayAxes::RenderImpl::RenderImpl() : arrows(new OverlayArrowGeometry)
{
  // Use thicker arrows for the overlay (closer to original mesh-based axes)
  arrows->setRadiusScale(3.0f);
  // Add the three axes arrows (origin to unit axis, each with its own color)
  const Vector3f origin(0.f, 0.f, 0.f);
  arrows->addSingleArrow(origin, Vector3f(1.f, 0.f, 0.f), Vector3ub(255, 0, 0));
  arrows->addSingleArrow(origin, Vector3f(0.f, 1.f, 0.f), Vector3ub(0, 255, 0));
  arrows->addSingleArrow(origin, Vector3f(0.f, 0.f, 1.f), Vector3ub(0, 0, 255));
}

OverlayAxes::RenderImpl::~RenderImpl()
{
  delete arrows;
}

OverlayAxes::OverlayAxes(QObject* p) : ScenePlugin(p), m_render(new RenderImpl)
{
  m_layerManager = QtGui::PluginLayerManager(m_name);
}

OverlayAxes::~OverlayAxes() {}

void OverlayAxes::process(const QtGui::Molecule&, Rendering::GroupNode& node)
{
  auto* geo = new GeometryNode;
  // Since our geometry doesn't change, we just make a copy of the pre-built
  // set of axes.
  geo->addDrawable(new OverlayArrowGeometry(*m_render->arrows));
  node.addChild(geo);
}

} // namespace Avogadro::QtPlugins
