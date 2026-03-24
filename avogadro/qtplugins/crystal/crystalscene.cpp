/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "crystalscene.h"

#include <avogadro/core/unitcell.h>
#include <avogadro/qtgui/colorbutton.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/rendering/cylindergeometry.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/groupnode.h>
#include <avogadro/rendering/spheregeometry.h>

#include <QtCore/QSettings>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QDoubleSpinBox>
#include <QtWidgets/QFormLayout>
#include <QtWidgets/QVBoxLayout>

#include <QDebug>

namespace Avogadro::QtPlugins {

using Core::UnitCell;
using Rendering::CylinderGeometry;
using Rendering::GeometryNode;
using Rendering::GroupNode;
using Rendering::SphereGeometry;

const Vector3ub red = { 255, 0, 0 };
const Vector3ub green = { 0, 255, 0 };
const Vector3ub blue = { 0, 0, 255 };

CrystalScene::CrystalScene(QObject* p) : ScenePlugin(p), m_setupWidget(nullptr)
{
  m_layerManager = QtGui::PluginLayerManager(m_name);

  QSettings settings;
  m_lineWidth = settings.value("crystal/lineWidth", 2.0).toDouble();

  auto color =
    settings.value("crystal/color", QColor(Qt::white)).value<QColor>();
  m_color[0] = static_cast<unsigned char>(color.red());
  m_color[1] = static_cast<unsigned char>(color.green());
  m_color[2] = static_cast<unsigned char>(color.blue());

  m_multiColor = settings.value("crystal/multiColor", true).toBool();
}

CrystalScene::~CrystalScene() {}

void CrystalScene::process(const QtGui::Molecule& molecule, GroupNode& node)
{
  if (const UnitCell* cell = molecule.unitCell()) {
    auto* geometry = new GeometryNode;
    node.addChild(geometry);

    auto* cylinders = new CylinderGeometry;
    geometry->addDrawable(cylinders);
    auto* spheres = new SphereGeometry;
    geometry->addDrawable(spheres);

    auto color = m_color;
    float radius = static_cast<float>(m_lineWidth) * 0.0125f;

    Vector3f a = cell->aVector().cast<float>();
    Vector3f b = cell->bVector().cast<float>();
    Vector3f c = cell->cVector().cast<float>();

    Vector3f o(Vector3f::Zero());

    // 8 corner spheres
    Vector3f corners[8] = { o,     o + a,     o + b,     o + a + b,
                            o + c, o + a + c, o + b + c, o + a + b + c };
    for (const auto& corner : corners)
      spheres->addSphere(corner, color, radius);

    // a-axis edges
    Vector3ub aColor = m_multiColor ? red : color;
    cylinders->addCylinder(o, o + a, radius, aColor);
    cylinders->addCylinder(o + c, o + a + c, radius, color);
    cylinders->addCylinder(o + b, o + a + b, radius, color);
    cylinders->addCylinder(o + b + c, o + a + b + c, radius, color);

    // b-axis edges
    Vector3ub bColor = m_multiColor ? green : color;
    cylinders->addCylinder(o, o + b, radius, bColor);
    cylinders->addCylinder(o + c, o + b + c, radius, color);
    cylinders->addCylinder(o + a, o + a + b, radius, color);
    cylinders->addCylinder(o + a + c, o + a + b + c, radius, color);

    // c-axis edges
    Vector3ub cColor = m_multiColor ? blue : color;
    cylinders->addCylinder(o, o + c, radius, cColor);
    cylinders->addCylinder(o + a, o + a + c, radius, color);
    cylinders->addCylinder(o + b, o + b + c, radius, color);
    cylinders->addCylinder(o + a + b, o + a + b + c, radius, color);
  }
}

void CrystalScene::setLineWidth(double width)
{
  m_lineWidth = width;
  emit drawablesChanged();

  QSettings settings;
  settings.setValue("crystal/lineWidth", width);
}

void CrystalScene::setColor(const QColor& color)
{
  m_color[0] = static_cast<unsigned char>(color.red());
  m_color[1] = static_cast<unsigned char>(color.green());
  m_color[2] = static_cast<unsigned char>(color.blue());

  emit drawablesChanged();

  QSettings settings;
  settings.setValue("crystal/color", color);
}

void CrystalScene::setMultiColor(bool multiColor)
{
  m_multiColor = multiColor;
  emit drawablesChanged();

  QSettings settings;
  settings.setValue("crystal/multiColor", multiColor);
}

QWidget* CrystalScene::setupWidget()
{
  if (!m_setupWidget) {
    m_setupWidget = new QWidget(qobject_cast<QWidget*>(parent()));
    auto* v = new QVBoxLayout;

    // line width
    auto* spin = new QDoubleSpinBox;
    spin->setRange(0.5, 5.0);
    spin->setSingleStep(0.25);
    spin->setDecimals(2);
    spin->setValue(m_lineWidth);
    connect(spin, SIGNAL(valueChanged(double)), SLOT(setLineWidth(double)));
    auto* form = new QFormLayout;
    form->addRow(tr("Line width:"), spin);

    auto* multiColor = new QCheckBox;
    multiColor->setChecked(m_multiColor);
    form->addRow(tr("Color axes:"), multiColor);
    connect(multiColor, SIGNAL(toggled(bool)), SLOT(setMultiColor(bool)));

    auto* color = new QtGui::ColorButton;
    connect(color, SIGNAL(colorChanged(const QColor&)),
            SLOT(setColor(const QColor&)));
    form->addRow(tr("Line color:"), color);

    v->addLayout(form);

    v->addStretch(1);
    m_setupWidget->setLayout(v);
  }
  return m_setupWidget;
}

} // namespace Avogadro::QtPlugins
