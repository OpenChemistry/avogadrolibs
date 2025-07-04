/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "meshes.h"

#include <avogadro/core/array.h>
#include <avogadro/core/mesh.h>
#include <avogadro/qtgui/colorbutton.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/groupnode.h>
#include <avogadro/rendering/meshgeometry.h>

#include <QtCore/QDebug>
#include <QtCore/QSettings>
#include <QtWidgets/QFormLayout>
#include <QtWidgets/QSlider>
#include <QtWidgets/QVBoxLayout>

#include <algorithm>

namespace Avogadro::QtPlugins {

using Core::Mesh;
using Rendering::GeometryNode;
using Rendering::GroupNode;
using Rendering::MeshGeometry;

Meshes::Meshes(QObject* p) : ScenePlugin(p), m_setupWidget(nullptr)
{
  m_layerManager = QtGui::PluginLayerManager(m_name);

  QSettings settings;
  // out of 255
  m_opacity = settings.value("meshes/opacity", 150).toUInt();

  auto color = settings.value("meshes/color1", QColor(Qt::red)).value<QColor>();
  m_color1[0] = static_cast<unsigned char>(color.red());
  m_color1[1] = static_cast<unsigned char>(color.green());
  m_color1[2] = static_cast<unsigned char>(color.blue());

  color = settings.value("meshes/color2", QColor(Qt::blue)).value<QColor>();
  m_color2[0] = static_cast<unsigned char>(color.red());
  m_color2[1] = static_cast<unsigned char>(color.green());
  m_color2[2] = static_cast<unsigned char>(color.blue());
}

Meshes::~Meshes() {}

// Generator for std::generate call below:
namespace {
struct Sequence
{
  Sequence() : i(0) {}
  unsigned int operator()() { return i++; }
  void reset() { i = 0; }
  unsigned int i;
};
} // namespace

void Meshes::process(const QtGui::Molecule& mol, GroupNode& node)
{
  if (mol.meshCount()) {
    auto* geometry = new GeometryNode;
    node.addChild(geometry);

    // Handle the first mesh
    const Mesh* mesh = mol.mesh(0);
    Core::Array<Vector3f> triangles = mesh->triangles();

    bool hasColors = (mesh->colors().size() != 0);

    auto* mesh1 = new MeshGeometry;
    geometry->addDrawable(mesh1);
    mesh1->setOpacity(m_opacity);

    if (hasColors) {
      auto colors = mesh->colors();
      Core::Array<Vector3ub> colorsRGB(colors.size());
      for (size_t i = 0; i < colors.size(); i++)
        colorsRGB[i] =
          Vector3ub(static_cast<unsigned char>(colors[i].red() * 255),
                    static_cast<unsigned char>(colors[i].green() * 255),
                    static_cast<unsigned char>(colors[i].blue() * 255));
      mesh1->addVertices(mesh->vertices(), mesh->normals(), colorsRGB);
    } else {
      mesh1->setColor(m_color1);
      mesh1->addVertices(mesh->vertices(), mesh->normals());
    }

    // Add the triangles for the first mesh
    for (size_t i = 0; i < triangles.size(); ++i) {
      mesh1->addTriangle(triangles[i][0], triangles[i][1], triangles[i][2]);
    }

    mesh1->setRenderPass(m_opacity == 255 ? Rendering::SolidPass
                                          : Rendering::TranslucentPass);

    // Handle the second mesh if present
    if (mol.meshCount() >= 2) {
      auto* mesh2 = new MeshGeometry;
      geometry->addDrawable(mesh2);

      mesh = mol.mesh(1);

      // Retrieve the second mesh’s triangles
      Core::Array<Vector3f> triangles2 = mesh->triangles();

      mesh2->setColor(m_color2);
      mesh2->setOpacity(m_opacity);
      mesh2->addVertices(mesh->vertices(), mesh->normals());

      // Add the correct triangles for the second mesh
      for (size_t i = 0; i < triangles2.size(); ++i) {
        mesh2->addTriangle(triangles2[i][0], triangles2[i][1],
                           triangles2[i][2]);
      }

      mesh2->setRenderPass(m_opacity == 255 ? Rendering::SolidPass
                                            : Rendering::TranslucentPass);
    }
  }
}

void Meshes::setOpacity(int opacity)
{
  m_opacity = opacity;
  emit drawablesChanged();

  QSettings settings;
  settings.setValue("meshes/opacity", m_opacity);
}

void Meshes::setColor1(const QColor& color)
{
  m_color1[0] = static_cast<unsigned char>(color.red());
  m_color1[1] = static_cast<unsigned char>(color.green());
  m_color1[2] = static_cast<unsigned char>(color.blue());

  emit drawablesChanged();

  QSettings settings;
  settings.setValue("meshes/color1", color);
}

void Meshes::setColor2(const QColor& color)
{
  m_color2[0] = static_cast<unsigned char>(color.red());
  m_color2[1] = static_cast<unsigned char>(color.green());
  m_color2[2] = static_cast<unsigned char>(color.blue());

  emit drawablesChanged();

  QSettings settings;
  settings.setValue("meshes/color2", color);
}

QWidget* Meshes::setupWidget()
{
  if (!m_setupWidget) {
    m_setupWidget = new QWidget(qobject_cast<QWidget*>(parent()));
    auto* v = new QVBoxLayout;

    // Opacity
    auto* slide = new QSlider(Qt::Horizontal);
    slide->setRange(0, 255);
    slide->setTickInterval(5);
    slide->setValue(m_opacity);
    connect(slide, SIGNAL(valueChanged(int)), SLOT(setOpacity(int)));

    auto* form = new QFormLayout;
    form->addRow(tr("Opacity:"), slide);

    auto* color1 = new QtGui::ColorButton;
    color1->setColor(QColor(m_color1[0], m_color1[1], m_color1[2]));
    connect(color1, SIGNAL(colorChanged(const QColor&)),
            SLOT(setColor1(const QColor&)));
    form->addRow(tr("Color:"), color1);

    auto* color2 = new QtGui::ColorButton;
    color2->setColor(QColor(m_color2[0], m_color2[1], m_color2[2]));
    connect(color2, SIGNAL(colorChanged(const QColor&)),
            SLOT(setColor2(const QColor&)));
    form->addRow(tr("Color:"), color2);

    v->addLayout(form);

    v->addStretch(1);
    m_setupWidget->setLayout(v);
  }
  return m_setupWidget;
}

} // namespace Avogadro::QtPlugins
