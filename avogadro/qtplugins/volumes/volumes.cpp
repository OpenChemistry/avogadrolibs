/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "volumes.h"

#include <avogadro/core/array.h>
#include <avogadro/core/mesh.h>
#include <avogadro/qtgui/colorbutton.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/groupnode.h>
#include <avogadro/rendering/volumegeometry.h>

#include <QtCore/QDebug>
#include <QtCore/QSettings>
#include <QtWidgets/QFormLayout>
#include <QtWidgets/QSlider>
#include <QtWidgets/QVBoxLayout>

#include <algorithm>

namespace Avogadro::QtPlugins {

using Rendering::GeometryNode;
using Rendering::GroupNode;
using Rendering::VolumeGeometry;

Volumes::Volumes(QObject* p) : ScenePlugin(p), m_setupWidget(nullptr)
{
  m_layerManager = QtGui::PluginLayerManager(m_name);

  QSettings settings;

  auto color = settings.value("volumes/color1", QColor(Qt::red)).value<QColor>();
  m_color1[0] = static_cast<unsigned char>(color.red());
  m_color1[1] = static_cast<unsigned char>(color.green());
  m_color1[2] = static_cast<unsigned char>(color.blue());

  color = settings.value("volumes/color2", QColor(Qt::blue)).value<QColor>();
  m_color2[0] = static_cast<unsigned char>(color.red());
  m_color2[1] = static_cast<unsigned char>(color.green());
  m_color2[2] = static_cast<unsigned char>(color.blue());
}

Volumes::~Volumes() {}

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

void Volumes::process(const QtGui::Molecule& mol, GroupNode& node)
{
  if (mol.cubeCount() < 1)
    return;

  const Core::Cube* cube = mol.cube(0);
  if (cube == nullptr)
    return;

  auto* geometry = new GeometryNode;
  node.addChild(geometry);

  auto* volume = new VolumeGeometry;
  qDebug() << "Volume data size: " << cube->data()->size();
  // volume->initialize(800,600);
  volume->setCube(*cube);
  volume->setRenderPass(Rendering::TranslucentPass);
  // TODO: better support for color ramps
  // Also, do we need separate volumes for positive and negative values?
  volume->setPositiveColor(m_color1);
  volume->setNegativeColor(m_color2);

  geometry->addDrawable(volume);
}

void Volumes::setColor1(const QColor& color)
{
  m_color1[0] = static_cast<unsigned char>(color.red());
  m_color1[1] = static_cast<unsigned char>(color.green());
  m_color1[2] = static_cast<unsigned char>(color.blue());

  emit drawablesChanged();

  QSettings settings;
  settings.setValue("volumes/color1", color);
}

void Volumes::setColor2(const QColor& color)
{
  m_color2[0] = static_cast<unsigned char>(color.red());
  m_color2[1] = static_cast<unsigned char>(color.green());
  m_color2[2] = static_cast<unsigned char>(color.blue());

  emit drawablesChanged();

  QSettings settings;
  settings.setValue("volumes/color2", color);
}

QWidget* Volumes::setupWidget()
{
  if (!m_setupWidget) {
    m_setupWidget = new QWidget(qobject_cast<QWidget*>(parent()));
    auto* v = new QVBoxLayout;
    auto* form = new QFormLayout;
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