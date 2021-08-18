/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "overlayaxes.h"

#include <avogadro/rendering/avogadrogl.h>
#include <avogadro/rendering/camera.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/groupnode.h>
#include <avogadro/rendering/meshgeometry.h>
#include <avogadro/rendering/scene.h>
#include <avogadro/qtopengl/glwidget.h>

#include <avogadro/core/array.h>
#include <avogadro/core/vector.h>

#include <QtCore/QSettings>
#include <QtWidgets/QAction>

#include <Eigen/Geometry>

using Avogadro::Vector3f;
using Avogadro::Core::Array;
using Avogadro::Rendering::Camera;
using Avogadro::Rendering::GeometryNode;
using Avogadro::Rendering::GroupNode;
using Avogadro::Rendering::MeshGeometry;
using Eigen::Affine3f;

namespace {
const static float M_PI_F = 3.14159265358979323846f;

// Mesh class that overrides the camera used in rendering.
class CustomMesh : public MeshGeometry
{
public:
  CustomMesh() { setRenderPass(Avogadro::Rendering::Overlay3DPass); }
  ~CustomMesh() override {}

  void render(const Camera& camera) override;
};

void CustomMesh::render(const Camera& camera)
{
  // Swap in a new viewport/camera for the overlay
  /// @todo This is messy, it would be better to specify camera/viewport in a
  /// group/geometry node that the renderer could apply to all children.

  // Keep the rotation, lose the translation:
  Affine3f mv(camera.modelView());
  mv.matrix().block<3, 1>(0, 3) = Vector3f::Zero();

  // Save the actual viewport - works better on high resolution screens
  GLint viewport[4];
  glGetIntegerv(GL_VIEWPORT, viewport);

  // The largest window dimension, used to scale the axes
  // (again, grab from the actual viewport)
  const int maxDim = std::max(viewport[2], viewport[3]);

  Camera meshCamera(camera);
  meshCamera.setViewport(maxDim / 10, maxDim / 10);
  meshCamera.setModelView(mv);
  meshCamera.calculateOrthographic(-1.f, 1.f, -1.f, 1.f, -1.f, 1.f);

  glViewport(static_cast<GLint>(10), static_cast<GLsizei>(10),
             static_cast<GLint>(meshCamera.width()),
             static_cast<GLsizei>(meshCamera.height()));

  MeshGeometry::render(meshCamera);

  glViewport(viewport[0], viewport[1], viewport[2], viewport[3]);
}
} // namespace

namespace Avogadro {
namespace QtPlugins {

class OverlayAxes::RenderImpl
{
public:
  RenderImpl();
  ~RenderImpl();

  CustomMesh* mesh;

private:
  void buildMesh();
  // axis must be normalized:
  void addAxis(const Vector3f& axis, const Vector3ub& color);
};

OverlayAxes::RenderImpl::RenderImpl() : mesh(new CustomMesh)
{
  buildMesh();
}

OverlayAxes::RenderImpl::~RenderImpl()
{
  delete mesh;
}

void OverlayAxes::RenderImpl::buildMesh()
{
  addAxis(Vector3f(1.f, 0.f, 0.f), Vector3ub(255, 0, 0));
  addAxis(Vector3f(0.f, 1.f, 0.f), Vector3ub(0, 255, 0));
  addAxis(Vector3f(0.f, 0.f, 1.f), Vector3ub(0, 0, 255));
}

void OverlayAxes::RenderImpl::addAxis(const Vector3f& axis,
                                      const Vector3ub& color)
{
  mesh->setColor(color);

  // Number of angular samples:
  const unsigned int res = 12;
  const float resf = static_cast<float>(res);
  // Cylinder length:
  const float cylLength = .75f;
  // Cylinder radius:
  const float cylRadius = 0.0625f;
  // Cone length:
  const float coneLength = .25f;
  // Cone radius:
  const float coneRadius = .125f;

  // Some vectors that will simplify things later:
  const Vector3f origin(0.f, 0.f, 0.f);
  const Vector3f cylVector(axis * cylLength);
  const Vector3f coneVector(axis * coneLength);
  const Vector3f axisVector(coneVector + cylVector);
  const Vector3f radialUnit(axis.unitOrthogonal());

  // Index offsets:
  const unsigned int coneBaseOffset = 0;
  const unsigned int coneBaseRadialsOffset = coneBaseOffset + 1;
  const unsigned int coneSideRadialsOffset = coneBaseRadialsOffset + res;
  const unsigned int coneTipsOffset = coneSideRadialsOffset + res;
  const unsigned int cylBaseRadialsOffset = coneTipsOffset + res;
  const unsigned int cylTopRadialsOffset = cylBaseRadialsOffset + res;
  const unsigned int numVertices = cylTopRadialsOffset + res;

  // Allocate arrays:
  Array<Vector3f> vertices(numVertices);
  Array<Vector3f> normals(numVertices);

  // This point doesn't change:
  vertices[coneBaseOffset] = origin + cylVector;
  normals[coneBaseOffset] = -axis;

  // Initial radial:
  Vector3f radial(radialUnit);

  // Create radial transform:
  Eigen::Affine3f xform(Eigen::AngleAxisf(2.f * M_PI_F / resf, axis));

  // Build vertex list:
  const Vector3f coneTip(origin + axisVector);
  Vector3f coneRadial;
  Vector3f coneSideNormal;
  Vector3f cylRadial;
  for (unsigned int i = 0; i < res; ++i) {
    coneRadial = origin + cylVector + (radial * coneRadius);
    // Calculating the cone side normal:
    //
    //       /|  (z points out of screen)  z = coneVector x coneRadial
    //      / |                            a = coneVector - coneRadial
    //  a  /  | coneVector                 n = z x a
    //    /   |
    //   /    |     (n is the normal for vector a)
    //  /_____|
    //    coneRadial
    coneSideNormal = -(coneVector.cross(coneRadial))
                        .cross(coneVector - coneRadial)
                        .normalized();

    vertices[coneBaseRadialsOffset + i] = coneRadial;
    normals[coneBaseRadialsOffset + i] = -axis;

    vertices[coneSideRadialsOffset + i] = coneRadial;
    normals[coneSideRadialsOffset + i] = coneSideNormal;

    cylRadial = origin + (radial * cylRadius);
    vertices[cylBaseRadialsOffset + i] = cylRadial;
    normals[cylBaseRadialsOffset + i] = radial;

    vertices[cylTopRadialsOffset + i] = cylVector + cylRadial;
    normals[cylTopRadialsOffset + i] = radial;

    radial = xform * radial;
  }

  // Cone tip normals are averages of the side radial normals:
  for (unsigned int i = 0; i < res; ++i) {
    unsigned int ind1 = coneSideRadialsOffset + i;
    unsigned int ind2 = coneSideRadialsOffset + ((i + 1) % res);
    vertices[coneTipsOffset + i] = coneTip;
    normals[coneTipsOffset + i] = (normals[ind1] + normals[ind2]).normalized();
  }

  // Add the vertices and get our index offset:
  const unsigned int baseOffset = mesh->addVertices(vertices, normals);

  // Stitch the vertices together:
  Array<unsigned int> triangles(3 * 4 * res); // 3 verts * 4 tri * nsamples
  unsigned int* ptr = triangles.data();
  for (unsigned int i = 0; i < res; ++i) {
    unsigned int i2 = (i + 1) % res;
    // Cone sides:
    *ptr++ = baseOffset + coneTipsOffset + i;
    *ptr++ = baseOffset + coneSideRadialsOffset + i;
    *ptr++ = baseOffset + coneSideRadialsOffset + i2;

    // Cone base:
    *ptr++ = baseOffset + coneBaseRadialsOffset + i;
    *ptr++ = baseOffset + coneBaseOffset;
    *ptr++ = baseOffset + coneBaseRadialsOffset + i2;

    // Cylinder side quad:
    *ptr++ = baseOffset + cylTopRadialsOffset + i;
    *ptr++ = baseOffset + cylBaseRadialsOffset + i;
    *ptr++ = baseOffset + cylTopRadialsOffset + i2;

    *ptr++ = baseOffset + cylBaseRadialsOffset + i;
    *ptr++ = baseOffset + cylTopRadialsOffset + i2;
    *ptr++ = baseOffset + cylBaseRadialsOffset + i2;
  }

  // Add the indices to the mesh
  mesh->addTriangles(triangles);
}

OverlayAxes::OverlayAxes(QObject* parent_)
  : Avogadro::QtGui::ExtensionPlugin(parent_), m_render(new RenderImpl),
    m_axesAction(new QAction(tr("Reference Axes"), this)), m_initialized(false)
{
  connect(m_axesAction, SIGNAL(triggered()), SLOT(processAxes()));

  QSettings settings;
  m_enabled = settings.value("overlayAxes/enabled", true).toBool();
  m_axesAction->setCheckable(true);
  m_axesAction->setChecked(m_enabled);

  // processAxes() will flip the value when called
  //   so we need to invert it here
  m_enabled = !m_enabled;
}

OverlayAxes::~OverlayAxes()
{
  delete m_render;
}

QList<QAction*> OverlayAxes::actions() const
{
  QList<QAction*> result;
  return result << m_axesAction;
}

QStringList OverlayAxes::menuPath(QAction*) const
{
  return QStringList() << tr("&View");
}

void OverlayAxes::processAxes()
{
  m_enabled = !m_enabled;
  QSettings settings;
  settings.setValue("overlayAxes/enabled", m_enabled);
  m_axesAction->setChecked(m_enabled);

  Rendering::GroupNode* engineNode = m_widgetToNode[m_glWidget];
  GroupNode& node = m_scene->rootNode();
  if (node.hasChild(engineNode)) {
    engineNode->clearUI();
    m_scene->rootNode().removeChild(engineNode);
    delete engineNode;
    m_widgetToNode[m_glWidget] = nullptr;
  }

  if (m_enabled) {
    engineNode = new Rendering::GroupNode(&node);
    m_widgetToNode[m_glWidget] = engineNode;
    process(*m_molecule, *engineNode);
  }
} // namespace QtPlugins

void OverlayAxes::setActiveWidget(QWidget* widget)
{
  if (widget != nullptr) {
    m_glWidget = widget;
    connect(this, SIGNAL(updateRequested()), m_glWidget, SLOT(requestUpdate()));

    if (m_widgetToNode.find(m_glWidget) == m_widgetToNode.end()) {
      m_widgetToNode[m_glWidget] = nullptr;
    }
  }
}

void OverlayAxes::process(const Core::Molecule& mol, Rendering::GroupNode& node)
{
  GeometryNode* geo = new GeometryNode;
  // Since our geometry doesn't change, we just make a copy of the pre-built
  // set of axes.
  geo->addDrawable(new CustomMesh(*m_render->mesh));
  node.addChild(geo, GroupNode::NodeType::UI);

  emit updateRequested();
}

void OverlayAxes::setMolecule(QtGui::Molecule* molecule)
{
  m_molecule = molecule;
}

void OverlayAxes::setScene(Rendering::Scene* scene)
{
  m_scene = scene;
  if (!m_initialized) {
    m_initialized = true;
    processAxes();
  }
}

} // namespace QtPlugins
} // namespace Avogadro
