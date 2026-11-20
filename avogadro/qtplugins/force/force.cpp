/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "force.h"

#include <avogadro/core/elements.h>
#include <avogadro/qtgui/colorbutton.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/rendering/arrowgeometry.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/groupnode.h>

#include <QtCore/QSettings>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QDoubleSpinBox>
#include <QtWidgets/QFormLayout>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>

namespace Avogadro::QtPlugins {

using QtGui::Molecule;
using Rendering::ArrowGeometry;
using Rendering::GeometryNode;
using Rendering::GroupNode;

Force::Force(QObject* p) : ScenePlugin(p), m_setupWidget(nullptr)
{
  m_layerManager = QtGui::PluginLayerManager(m_name);

  QSettings settings;
  m_length = settings.value("force/length", 1.0).toDouble();
  m_arrowWidth = settings.value("force/arrowWidth", 1.0).toDouble();

  auto color = settings.value("force/color", QColor(Qt::green)).value<QColor>();
  m_color[0] = static_cast<unsigned char>(color.red());
  m_color[1] = static_cast<unsigned char>(color.green());
  m_color[2] = static_cast<unsigned char>(color.blue());
}

Force::~Force() {}

void Force::process(const QtGui::Molecule& molecule, Rendering::GroupNode& node)
{
  auto* geometry = new GeometryNode;
  node.addChild(geometry);

  auto* arrows = new ArrowGeometry;
  arrows->setColor(m_color);
  arrows->setRadiusScale(m_arrowWidth);
  arrows->identifier().molecule = &molecule;
  geometry->addDrawable(arrows);
  for (Index i = 0; i < molecule.atomCount(); ++i) {
    if (!m_layerManager.atomEnabled(i))
      continue; // ignore hidden atoms

    Core::Atom atom1 = molecule.atom(i);
    Vector3f pos1 = atom1.position3d().cast<float>();
    Vector3f forceVector = atom1.forceVector().cast<float>();
    arrows->addSingleArrow(pos1, pos1 + (m_length * forceVector));
  }
}

void Force::setColor(const QColor& color)
{
  m_color[0] = static_cast<unsigned char>(color.red());
  m_color[1] = static_cast<unsigned char>(color.green());
  m_color[2] = static_cast<unsigned char>(color.blue());

  emit drawablesChanged();

  QSettings settings;
  settings.setValue("force/color", color);
}

void Force::setLength(double scale)
{
  m_length = static_cast<float>(scale);
  emit drawablesChanged();

  QSettings settings;
  settings.setValue("force/length", scale);
}

void Force::setArrowWidth(double width)
{
  m_arrowWidth = static_cast<float>(width);
  emit drawablesChanged();

  QSettings settings;
  settings.setValue("force/arrowWidth", width);
}

QWidget* Force::setupWidget()
{
  if (!m_setupWidget) {
    m_setupWidget = new QWidget(qobject_cast<QWidget*>(parent()));
    auto* v = new QVBoxLayout;

    // arrow length
    auto* spin = new QDoubleSpinBox;
    spin->setRange(0.5, 5.0);
    spin->setSingleStep(0.25);
    spin->setDecimals(2);
    spin->setValue(m_length);
    connect(spin, SIGNAL(valueChanged(double)), SLOT(setLength(double)));
    auto* form = new QFormLayout;
    form->addRow(tr("Arrow length:"), spin);

    // arrow width
    auto* widthSpin = new QDoubleSpinBox;
    widthSpin->setRange(0.1, 2.0);
    widthSpin->setSingleStep(0.1);
    widthSpin->setDecimals(2);
    widthSpin->setValue(m_arrowWidth);
    connect(widthSpin, SIGNAL(valueChanged(double)),
            SLOT(setArrowWidth(double)));
    form->addRow(tr("Arrow width:"), widthSpin);

    // color button
    auto* colorButton = new QtGui::ColorButton;
    colorButton->setColor(QColor(m_color[0], m_color[1], m_color[2]));
    connect(colorButton, SIGNAL(colorChanged(const QColor&)),
            SLOT(setColor(const QColor&)));
    form->addRow(tr("Arrow color:"), colorButton);

    v->addLayout(form);

    v->addStretch(1);
    m_setupWidget->setLayout(v);
  }
  return m_setupWidget;
}

} // namespace Avogadro::QtPlugins
