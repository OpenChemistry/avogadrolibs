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
#include <QtWidgets/QSlider>
#include <QtWidgets/QFormLayout>
#include <QtWidgets/QVBoxLayout>

#include <algorithm>

namespace Avogadro {
namespace QtPlugins {

using Core::Mesh;
using Core::Molecule;
using Rendering::GeometryNode;
using Rendering::GroupNode;
using Rendering::MeshGeometry;

Meshes::Meshes(QObject* p) : ScenePlugin(p), m_enabled(true), m_setupWidget(nullptr)
{
  QSettings settings;
  // out of 255
  m_opacity = settings.value("meshes/opacity", 150).toUInt();

  QColor color =
    settings.value("meshes/color1", QColor(Qt::red)).value<QColor>();
  m_color1[0] = static_cast<unsigned char>(color.red());
  m_color1[1] = static_cast<unsigned char>(color.green());
  m_color1[2] = static_cast<unsigned char>(color.blue());

  color =
    settings.value("meshes/color2", QColor(Qt::blue)).value<QColor>();
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
    GeometryNode* geometry = new GeometryNode;
    node.addChild(geometry);
 
    const Mesh* mesh = mol.mesh(0);

    /// @todo Allow use of MeshGeometry without an index array when all vertices
    /// form explicit triangles.
    // Create index array:
    Sequence indexGenerator;
    Core::Array<unsigned int> indices(mesh->numVertices());
    std::generate(indices.begin(), indices.end(), indexGenerator);

    MeshGeometry* mesh1 = new MeshGeometry;
    geometry->addDrawable(mesh1);
    //mesh1->setColor(m_color1);
    mesh1->setOpacity(m_opacity);
    auto colors = mesh->colorsRGB();
    mesh1->addVertices(mesh->vertices(), mesh->normals(), *colors);
    mesh1->addTriangles(indices);
    mesh1->setRenderPass(m_opacity == 255 ? Rendering::OpaquePass
                                        : Rendering::TranslucentPass);

    if (mol.meshCount() >= 2) {
      MeshGeometry* mesh2 = new MeshGeometry;
      geometry->addDrawable(mesh2);
      mesh = mol.mesh(1);
      if (mesh->numVertices() < indices.size()) {
        indices.resize(mesh->numVertices());
      } else if (mesh->numVertices() > indices.size()) {
        indexGenerator.reset();
        indices.resize(mesh->numVertices());
        std::generate(indices.begin(), indices.end(), indexGenerator);
      }
      mesh2->setColor(m_color2);
      mesh2->setOpacity(m_opacity);
      mesh2->addVertices(mesh->vertices(), mesh->normals());
      mesh2->addTriangles(indices);
      mesh2->setRenderPass(m_opacity == 255 ? Rendering::OpaquePass
                                          : Rendering::TranslucentPass);
    }
  }
}

bool Meshes::isEnabled() const
{
  return m_enabled;
}

bool Meshes::isActiveLayerEnabled() const
{
  return m_enabled;
}

void Meshes::setEnabled(bool enable)
{
  m_enabled = enable;
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
    QVBoxLayout* v = new QVBoxLayout;

    // Opacity
    QSlider* slide = new QSlider(Qt::Horizontal);
    slide->setRange(0, 255);
    slide->setTickInterval(5);
    slide->setValue(m_opacity);
    connect(slide, SIGNAL(valueChanged(int)), SLOT(setOpacity(int)));

    QFormLayout* form = new QFormLayout;
    form->addRow(tr("Opacity:"), slide);

    QtGui::ColorButton* color1 = new QtGui::ColorButton;
    color1->setColor(QColor(m_color1[0], m_color1[1], m_color1[2]));
    connect(color1, SIGNAL(colorChanged(const QColor&)),
            SLOT(setColor1(const QColor&)));
    form->addRow(tr("Color:"), color1);

    QtGui::ColorButton* color2 = new QtGui::ColorButton;
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

} // namespace QtPlugins
} // namespace Avogadro
