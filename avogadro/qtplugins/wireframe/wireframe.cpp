/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "wireframe.h"

#include <avogadro/core/elements.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/groupnode.h>
#include <avogadro/rendering/linestripgeometry.h>
#include <avogadro/rendering/spheregeometry.h>

#include <QtCore/QSettings>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QDoubleSpinBox>
#include <QtWidgets/QFormLayout>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>

namespace Avogadro {
namespace QtPlugins {

using Core::Array;
using Core::Elements;
using QtGui::PluginLayerManager;
using Rendering::GeometryNode;
using Rendering::GroupNode;
using Rendering::LineStripGeometry;
using Rendering::SphereGeometry;

struct LayerWireframe : Core::LayerData
{
  QWidget* widget;
  bool multiBonds;
  bool showHydrogens;
  float lineWidth;

  LayerWireframe()
  {
    widget = nullptr;
    QSettings settings;
    multiBonds = settings.value("wireframe/multiBonds", true).toBool();
    showHydrogens = settings.value("wireframe/showHydrogens", true).toBool();
    lineWidth = settings.value("wireframe/lineWidth", 1.0).toDouble();
  }

  ~LayerWireframe()
  {
    if (widget)
      widget->deleteLater();
  }

  std::string serialize() override final
  {
    return boolToString(multiBonds) + " " + boolToString(showHydrogens) + " " +
           std::to_string(lineWidth);
  }
  void deserialize(std::string text) override final
  {
    std::stringstream ss(text);
    std::string aux;
    ss >> aux;
    multiBonds = stringToBool(aux);
    ss >> aux;
    showHydrogens = stringToBool(aux);
    ss >> aux;
    lineWidth = std::stof(aux);
  }

  void setupWidget(Wireframe* slot)
  {
    if (!widget) {
      widget = new QWidget(qobject_cast<QWidget*>(slot->parent()));
      QVBoxLayout* v = new QVBoxLayout;

      // line width
      QDoubleSpinBox* spin = new QDoubleSpinBox;
      spin->setRange(0.5, 5.0);
      spin->setSingleStep(0.25);
      spin->setDecimals(2);
      spin->setValue(lineWidth);
      QObject::connect(spin, SIGNAL(valueChanged(double)), slot,
                       SLOT(setWidth(double)));
      QFormLayout* form = new QFormLayout;
      form->addRow(QObject::tr("Line width:"), spin);
      v->addLayout(form);

      // options
      QCheckBox* check = new QCheckBox(QObject::tr("Show multiple bonds"));
      check->setChecked(multiBonds);
      QObject::connect(check, &QCheckBox::clicked, slot,
                       &Wireframe::multiBonds);
      v->addWidget(check);

      check = new QCheckBox(QObject::tr("Show hydrogens"));
      check->setChecked(showHydrogens);
      QObject::connect(check, &QCheckBox::clicked, slot,
                       &Wireframe::showHydrogens);
      v->addWidget(check);

      v->addStretch(1);
      widget->setLayout(v);
    }
  }
};

Wireframe::Wireframe(QObject* p) : ScenePlugin(p), m_group(nullptr)
{
  m_layerManager = PluginLayerManager(m_name);
}

Wireframe::~Wireframe() {}

void Wireframe::process(const QtGui::Molecule& molecule,
                        Rendering::GroupNode& node)
{
  m_layerManager.load<LayerWireframe>();
  // Add a node to contain all of the lines.
  m_group = &node;
  GeometryNode* geometry = new GeometryNode;
  node.addChild(geometry);

  LineStripGeometry* lines = new LineStripGeometry;
  lines->identifier().molecule = &molecule;
  lines->identifier().type = Rendering::BondType;
  auto selectedAtoms = new SphereGeometry;
  selectedAtoms->setOpacity(0.42);
  Vector3ub selectedColor(0, 0, 255);

  geometry->addDrawable(lines);
  geometry->addDrawable(selectedAtoms);
  for (Index i = 0; i < molecule.bondCount(); ++i) {
    Core::Bond bond = molecule.bond(i);
    if (!m_layerManager.bondEnabled(bond.atom1().index(),
                                    bond.atom2().index())) {
      continue;
    }
    LayerWireframe& interface1 = m_layerManager.getSetting<LayerWireframe>(
      m_layerManager.getLayerID(bond.atom1().index()));
    LayerWireframe& interface2 = m_layerManager.getSetting<LayerWireframe>(
      m_layerManager.getLayerID(bond.atom2().index()));
    if (!interface1.showHydrogens && !interface2.showHydrogens &&
        (bond.atom1().atomicNumber() == 1 ||
         bond.atom2().atomicNumber() == 1)) {
      continue;
    }
    Vector3f pos1 = bond.atom1().position3d().cast<float>();
    Vector3f pos2 = bond.atom2().position3d().cast<float>();
    Vector3ub color1(Elements::color(bond.atom1().atomicNumber()));
    Vector3ub color2(Elements::color(bond.atom2().atomicNumber()));
    Array<Vector3f> points;
    Array<Vector3ub> colors;
    points.push_back(pos1);
    points.push_back(pos2);
    colors.push_back(color1);
    colors.push_back(color2);
    float lineWidth = interface1.lineWidth;

    if (interface1.multiBonds || interface2.multiBonds)
      lineWidth *= bond.order();
    lines->addLineStrip(points, colors, lineWidth);
    if (bond.atom1().selected())
      selectedAtoms->addSphere(pos1, selectedColor, 0.3f, i);
    if (bond.atom2().selected())
      selectedAtoms->addSphere(pos2, selectedColor, 0.3f, i);
  }
}

QWidget* Wireframe::setupWidget()
{
  LayerWireframe& interface = m_layerManager.getSetting<LayerWireframe>();
  interface.setupWidget(this);
  return interface.widget;
}

void Wireframe::multiBonds(bool show)
{
  LayerWireframe& interface = m_layerManager.getSetting<LayerWireframe>();
  if (show != interface.multiBonds) {
    interface.multiBonds = show;
    emit drawablesChanged();
  }
  QSettings settings;
  settings.setValue("wireframe/multiBonds", show);
}

void Wireframe::showHydrogens(bool show)
{
  LayerWireframe& interface = m_layerManager.getSetting<LayerWireframe>();
  if (show != interface.showHydrogens) {
    interface.showHydrogens = show;
    emit drawablesChanged();
  }
  QSettings settings;
  settings.setValue("wireframe/showHydrogens", show);
}

void Wireframe::setWidth(double width)
{
  LayerWireframe& interface = m_layerManager.getSetting<LayerWireframe>();
  interface.lineWidth = float(width);
  emit drawablesChanged();

  QSettings settings;
  settings.setValue("wireframe/lineWidth", interface.lineWidth);
}

} // namespace QtPlugins
} // namespace Avogadro
