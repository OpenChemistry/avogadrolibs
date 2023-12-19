/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "crystalscene.h"

#include <avogadro/core/array.h>
#include <avogadro/core/unitcell.h>
#include <avogadro/qtgui/colorbutton.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/groupnode.h>
#include <avogadro/rendering/linestripgeometry.h>

#include <QtCore/QSettings>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QDoubleSpinBox>
#include <QtWidgets/QFormLayout>
#include <QtWidgets/QVBoxLayout>

#include <QDebug>

namespace Avogadro::QtPlugins {

using Core::Array;
using Core::UnitCell;
using Rendering::GeometryNode;
using Rendering::GroupNode;
using Rendering::LineStripGeometry;

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
    auto* lines = new LineStripGeometry;
    geometry->addDrawable(lines);
    lines->setColor(m_color);
    auto color = m_color;
    float width = m_lineWidth;

    Vector3f a = cell->aVector().cast<float>();
    Vector3f b = cell->bVector().cast<float>();
    Vector3f c = cell->cVector().cast<float>();

    Vector3f vertex(Vector3f::Zero());

    Array<Vector3f> strip;
    // draw the a axis
    strip.reserve(5);
    strip.push_back(vertex);
    strip.push_back(vertex + a);
    if (!m_multiColor)
      lines->addLineStrip(strip, color, width);
    else // a axis is R-G-B
      lines->addLineStrip(strip, red, width);

    // now the b-axis
    strip.clear();
    strip.push_back(vertex);
    strip.push_back(vertex + b);
    if (!m_multiColor)
      lines->addLineStrip(strip, color, width);
    else // b axis is R-G-B
      lines->addLineStrip(strip, green, width);

    // now the rest of the ab plane
    strip.clear();
    strip.push_back(vertex + a);
    strip.push_back(vertex + a + b);
    strip.push_back(vertex + b);
    lines->addLineStrip(strip, width);

    // now the ab plane "up" by axis c
    strip.clear();
    strip.push_back(vertex + c);
    strip.push_back(vertex + a + c);
    strip.push_back(vertex + a + b + c);
    strip.push_back(vertex + b + c);
    strip.push_back(vertex + c);
    lines->addLineStrip(strip, width);

    // now the c axis
    strip.resize(2);
    strip[0] = Vector3f::Zero();
    strip[1] = c;
    if (!m_multiColor)
      lines->addLineStrip(strip, color, width);
    else // c axis is R-G-B
      lines->addLineStrip(strip, blue, width);

    // now the remaining "struts" from ab plane along c axis
    strip[0] += a;
    strip[1] += a;
    lines->addLineStrip(strip, width);

    strip[0] += b;
    strip[1] += b;
    lines->addLineStrip(strip, width);

    strip[0] -= a;
    strip[1] -= a;
    lines->addLineStrip(strip, width);
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
