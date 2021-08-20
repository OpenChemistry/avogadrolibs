/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "ballandstick.h"

#include <avogadro/core/elements.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/rendering/cylindergeometry.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/groupnode.h>
#include <avogadro/rendering/spheregeometry.h>

#include <QtCore/QSettings>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QFormLayout>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QSlider>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>

namespace Avogadro {
namespace QtPlugins {

using Core::Elements;
using QtGui::PluginLayerManager;
using Rendering::CylinderGeometry;
using Rendering::GeometryNode;
using Rendering::GroupNode;
using Rendering::SphereGeometry;

struct LayerBallAndStick : Core::LayerData
{
  QWidget* widget;
  bool multiBonds;
  bool showHydrogens;
  float atomScale;
  float bondRadius;

  LayerBallAndStick()
  {
    widget = nullptr;
    QSettings settings;
    atomScale = settings.value("ballandstick/atomScale", 0.3).toDouble();
    bondRadius = settings.value("ballandstick/bondRadius", 0.1).toDouble();
    multiBonds = settings.value("ballandstick/multiBonds", true).toBool();
    showHydrogens = settings.value("ballandstick/showHydrogens", true).toBool();
  }

  ~LayerBallAndStick()
  {
    if (widget)
      widget->deleteLater();
  }

  std::string serialize() override final
  {
    return boolToString(multiBonds) + " " + boolToString(showHydrogens) + " " +
           std::to_string(atomScale) + " " + std::to_string(bondRadius);
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
    atomScale = std::stof(aux);
    ss >> aux;
    bondRadius = std::stof(aux);
  }

  void setupWidget(BallAndStick* slot)
  {
    if (!widget) {
      widget = new QWidget(qobject_cast<QWidget*>(slot->parent()));
      QVBoxLayout* v = new QVBoxLayout;

      QFormLayout* f = new QFormLayout;
      QSlider* atomRadiusSlider = new QSlider(Qt::Horizontal);
      atomRadiusSlider->setMinimum(1);
      atomRadiusSlider->setMaximum(9);
      atomRadiusSlider->setTickInterval(1);
      atomRadiusSlider->setValue(atomScale * 10);
      QObject::connect(atomRadiusSlider, &QSlider::valueChanged, slot,
                       &BallAndStick::atomRadiusChanged);
      f->addRow(QObject::tr("Atom scale"), atomRadiusSlider);

      QSlider* bondRadiusSlider = new QSlider(Qt::Horizontal);
      bondRadiusSlider->setMinimum(1);
      bondRadiusSlider->setMaximum(8);
      bondRadiusSlider->setTickInterval(1);
      bondRadiusSlider->setValue(bondRadius * 10);
      QObject::connect(bondRadiusSlider, &QSlider::valueChanged, slot,
                       &BallAndStick::bondRadiusChanged);
      f->addRow(QObject::tr("Bond scale"), bondRadiusSlider);
      v->addLayout(f);

      QCheckBox* check = new QCheckBox(QObject::tr("Show multiple bonds"));
      check->setChecked(multiBonds);
      QObject::connect(check, &QCheckBox::clicked, slot,
                       &BallAndStick::multiBonds);
      v->addWidget(check);

      check = new QCheckBox(QObject::tr("Show hydrogens"));
      check->setChecked(showHydrogens);
      QObject::connect(check, &QCheckBox::clicked, slot,
                       &BallAndStick::showHydrogens);
      v->addWidget(check);

      v->addStretch(1);
      widget->setLayout(v);
    }
  }
};

BallAndStick::BallAndStick(QObject* p) : ScenePlugin(p), m_group(nullptr)
{
  m_layerManager = PluginLayerManager(m_name);
}

BallAndStick::~BallAndStick() {}

void BallAndStick::process(const QtGui::Molecule& molecule,
                           Rendering::GroupNode& node)
{
  m_layerManager.load<LayerBallAndStick>();
  // Add a sphere node to contain all of the spheres.
  m_group = &node;
  GeometryNode* geometry = new GeometryNode;
  node.addChild(geometry);
  SphereGeometry* spheres = new SphereGeometry;
  auto selectedSpheres = new SphereGeometry;
  selectedSpheres->setOpacity(0.42);
  spheres->identifier().molecule = reinterpret_cast<const void*>(&molecule);
  spheres->identifier().type = Rendering::AtomType;
  geometry->addDrawable(spheres);
  geometry->addDrawable(selectedSpheres);

  for (Index i = 0; i < molecule.atomCount(); ++i) {
    Core::Atom atom = molecule.atom(i);
    if (!m_layerManager.atomEnabled(i)) {
      continue;
    }
    unsigned char atomicNumber = atom.atomicNumber();
    LayerBallAndStick& interface = m_layerManager.getSetting<LayerBallAndStick>(
      m_layerManager.getLayerID(i));
    if (atomicNumber == 1 && !interface.showHydrogens)
      continue;

    Vector3ub color = atom.color();
    float radius = static_cast<float>(Elements::radiusVDW(atomicNumber));
    float scale = interface.atomScale;
    spheres->addSphere(atom.position3d().cast<float>(), color, radius * scale,
                       i);
    if (atom.selected()) {
      color = Vector3ub(0, 0, 255);
      radius *= 1.2;
      selectedSpheres->addSphere(atom.position3d().cast<float>(), color,
                                 radius * scale, i);
    }
  }

  CylinderGeometry* cylinders = new CylinderGeometry;
  cylinders->identifier().molecule = &molecule;
  cylinders->identifier().type = Rendering::BondType;
  geometry->addDrawable(cylinders);
  for (Index i = 0; i < molecule.bondCount(); ++i) {
    Core::Bond bond = molecule.bond(i);
    if (!m_layerManager.bondEnabled(bond.atom1().index(),
                                    bond.atom2().index())) {
      continue;
    }

    LayerBallAndStick& interface1 =
      m_layerManager.getSetting<LayerBallAndStick>(
        m_layerManager.getLayerID(bond.atom1().index()));
    LayerBallAndStick& interface2 =
      m_layerManager.getSetting<LayerBallAndStick>(
        m_layerManager.getLayerID(bond.atom2().index()));

    if (!interface1.showHydrogens && !interface2.showHydrogens &&
        (bond.atom1().atomicNumber() == 1 ||
         bond.atom2().atomicNumber() == 1)) {
      continue;
    }

    float bondRadius = (interface1.bondRadius + interface2.bondRadius) * 0.5f;

    Vector3f pos1 = bond.atom1().position3d().cast<float>();
    Vector3f pos2 = bond.atom2().position3d().cast<float>();
    Vector3ub color1 = bond.atom1().color();
    Vector3ub color2 = bond.atom2().color();
    Vector3f bondVector = pos2 - pos1;
    float bondLength = bondVector.norm();
    bondVector /= bondLength;
    switch (interface1.multiBonds || interface2.multiBonds ? bond.order() : 1) {
      case 3: {
        Vector3f delta = bondVector.unitOrthogonal() * (2.0f * bondRadius);
        cylinders->addCylinder(pos1 + delta, pos2 + delta, bondRadius, color1,
                               color2, i);
        cylinders->addCylinder(pos1 - delta, pos2 - delta, bondRadius, color1,
                               color2, i);
      }
      default:
      case 1:
        cylinders->addCylinder(pos1, pos2, m_bondRadius, color1, color2, i);
        break;
      case 2: {
        Vector3f delta = bondVector.unitOrthogonal() * bondRadius;
        cylinders->addCylinder(pos1 + delta, pos2 + delta, bondRadius, color1,
                               color2, i);
        cylinders->addCylinder(pos1 - delta, pos2 - delta, bondRadius, color1,
                               color2, i);
      }
    }
  }
}

QWidget* BallAndStick::setupWidget()
{
  LayerBallAndStick& interface = m_layerManager.getSetting<LayerBallAndStick>();
  interface.setupWidget(this);
  return interface.widget;
}

void BallAndStick::atomRadiusChanged(int value)
{
  m_atomScale = static_cast<float>(value) / 10.0f;

  LayerBallAndStick& interface = m_layerManager.getSetting<LayerBallAndStick>();
  if (m_atomScale != interface.atomScale) {
    interface.atomScale = m_atomScale;
    emit drawablesChanged();
  }

  QSettings settings;
  settings.setValue("ballandstick/atomScale", m_atomScale);
}

void BallAndStick::bondRadiusChanged(int value)
{
  m_bondRadius = static_cast<float>(value) / 10.0f;

  LayerBallAndStick& interface = m_layerManager.getSetting<LayerBallAndStick>();
  if (m_bondRadius != interface.bondRadius) {
    interface.bondRadius = m_bondRadius;
    emit drawablesChanged();
  }

  QSettings settings;
  settings.setValue("ballandstick/bondRadius", m_bondRadius);
}

void BallAndStick::multiBonds(bool show)
{
  LayerBallAndStick& interface = m_layerManager.getSetting<LayerBallAndStick>();
  if (show != interface.multiBonds) {
    interface.multiBonds = show;
    emit drawablesChanged();
  }
  QSettings settings;
  settings.setValue("ballandstick/multiBonds", show);
}

void BallAndStick::showHydrogens(bool show)
{
  LayerBallAndStick& interface = m_layerManager.getSetting<LayerBallAndStick>();
  if (show != interface.showHydrogens) {
    interface.showHydrogens = show;
    emit drawablesChanged();
  }
  QSettings settings;
  settings.setValue("ballandstick/showHydrogens", show);
}

} // namespace QtPlugins
} // namespace Avogadro
