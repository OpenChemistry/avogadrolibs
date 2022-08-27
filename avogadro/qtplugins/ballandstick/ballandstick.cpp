/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "ballandstick.h"

#include <avogadro/core/elements.h>
#include <avogadro/qtgui/molecule.h>

#include <QtCore/QSettings>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QFormLayout>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QSlider>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>

#include <QDebug>

namespace Avogadro::QtPlugins {

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

  ~LayerBallAndStick() override
  {
    if (widget)
      widget->deleteLater();
  }

  std::string serialize() final
  {
    return boolToString(multiBonds) + " " + boolToString(showHydrogens) + " " +
           std::to_string(atomScale) + " " + std::to_string(bondRadius);
  }

  void deserialize(std::string text) final
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
      auto* v = new QVBoxLayout;

      auto* f = new QFormLayout;
      auto* atomRadiusSlider = new QSlider(Qt::Horizontal);
      atomRadiusSlider->setMinimum(1);
      atomRadiusSlider->setMaximum(9);
      atomRadiusSlider->setTickInterval(1);
      atomRadiusSlider->setValue(atomScale * 10);
      QObject::connect(atomRadiusSlider, &QSlider::valueChanged, slot,
                       &BallAndStick::atomRadiusChanged);
      f->addRow(QObject::tr("Atom scale"), atomRadiusSlider);

      auto* bondRadiusSlider = new QSlider(Qt::Horizontal);
      bondRadiusSlider->setMinimum(1);
      bondRadiusSlider->setMaximum(8);
      bondRadiusSlider->setTickInterval(1);
      bondRadiusSlider->setValue(bondRadius * 10);
      QObject::connect(bondRadiusSlider, &QSlider::valueChanged, slot,
                       &BallAndStick::bondRadiusChanged);
      f->addRow(QObject::tr("Bond scale"), bondRadiusSlider);
      v->addLayout(f);

      auto* check = new QCheckBox(QObject::tr("Show multiple bonds"));
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

BallAndStick::BallAndStick(QObject* p)
  : ScenePlugin(p), m_group(nullptr), m_geometry(nullptr), m_spheres(nullptr),
    m_selectedSpheres(nullptr), m_cylinders(nullptr)
{
  m_layerManager = PluginLayerManager(m_name);
}

BallAndStick::~BallAndStick() {}

void BallAndStick::initialize()
{
  qDebug() << " initialized ball-and-stick";

  m_geometry = new GeometryNode;
  m_spheres = new SphereGeometry;
  m_selectedSpheres = new SphereGeometry;
  m_selectedSpheres->setOpacity(0.42);

  m_spheres->identifier().type = Rendering::AtomType;
  // don't identify the selected spheres - we should ignore them when selecting
  m_geometry->addDrawable(m_spheres);
  m_geometry->addDrawable(m_selectedSpheres);

  m_cylinders = new CylinderGeometry;
  m_cylinders->identifier().type = Rendering::BondType;
  m_geometry->addDrawable(m_cylinders);
}

void BallAndStick::process(const QtGui::Molecule& molecule,
                           Rendering::GroupNode& node)
{
  m_layerManager.load<LayerBallAndStick>();
  // Add a sphere node to contain all of the spheres.
  m_group = &node;

  if (m_geometry == nullptr)
    initialize();

  if (!node.hasChild(m_geometry))
    node.addChild(m_geometry);

  qDebug() << " process " << m_spheres->size();

  if (m_spheres->size())
    m_spheres->clear();
  if (m_selectedSpheres->size())
    m_selectedSpheres->clear();
  m_spheres->identifier().molecule = reinterpret_cast<const void*>(&molecule);

  for (Index i = 0; i < molecule.atomCount(); ++i) {
    Core::Atom atom = molecule.atom(i);
    if (!m_layerManager.atomEnabled(i)) {
      continue;
    }
    unsigned char atomicNumber = atom.atomicNumber();
    auto& interface = m_layerManager.getSetting<LayerBallAndStick>(
      m_layerManager.getLayerID(i));
    if (atomicNumber == 1 && !interface.showHydrogens)
      continue;

    Vector3ub color = atom.color();
    auto radius = static_cast<float>(Elements::radiusVDW(atomicNumber));
    float scale = interface.atomScale;
    m_spheres->addSphere(atom.position3d().cast<float>(), color, radius * scale,
                         i);
    if (atom.selected()) {
      color = Vector3ub(0, 0, 255);
      radius *= 1.2;
      m_selectedSpheres->addSphere(atom.position3d().cast<float>(), color,
                                   radius * scale, i);
    }
  }

  if (m_cylinders->size())
    m_cylinders->clear();
  m_cylinders->identifier().molecule = &molecule;

  for (Index i = 0; i < molecule.bondCount(); ++i) {
    Core::Bond bond = molecule.bond(i);
    if (!m_layerManager.bondEnabled(bond.atom1().index(),
                                    bond.atom2().index())) {
      continue;
    }

    auto& interface1 = m_layerManager.getSetting<LayerBallAndStick>(
      m_layerManager.getLayerID(bond.atom1().index()));
    auto& interface2 = m_layerManager.getSetting<LayerBallAndStick>(
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
        m_cylinders->addCylinder(pos1 + delta, pos2 + delta, bondRadius, color1,
                                 color2, i);
        m_cylinders->addCylinder(pos1 - delta, pos2 - delta, bondRadius, color1,
                                 color2, i);
      }
      default:
      case 1:
        m_cylinders->addCylinder(pos1, pos2, m_bondRadius, color1, color2, i);
        break;
      case 2: {
        Vector3f delta = bondVector.unitOrthogonal() * bondRadius;
        m_cylinders->addCylinder(pos1 + delta, pos2 + delta, bondRadius, color1,
                                 color2, i);
        m_cylinders->addCylinder(pos1 - delta, pos2 - delta, bondRadius, color1,
                                 color2, i);
      }
    }
  }
}

QWidget* BallAndStick::setupWidget()
{
  auto& interface = m_layerManager.getSetting<LayerBallAndStick>();
  interface.setupWidget(this);
  return interface.widget;
}

void BallAndStick::atomRadiusChanged(int value)
{
  m_atomScale = static_cast<float>(value) / 10.0f;

  auto& interface = m_layerManager.getSetting<LayerBallAndStick>();
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

  auto& interface = m_layerManager.getSetting<LayerBallAndStick>();
  if (m_bondRadius != interface.bondRadius) {
    interface.bondRadius = m_bondRadius;
    emit drawablesChanged();
  }

  QSettings settings;
  settings.setValue("ballandstick/bondRadius", m_bondRadius);
}

void BallAndStick::multiBonds(bool show)
{
  auto& interface = m_layerManager.getSetting<LayerBallAndStick>();
  if (show != interface.multiBonds) {
    interface.multiBonds = show;
    emit drawablesChanged();
  }
  QSettings settings;
  settings.setValue("ballandstick/multiBonds", show);
}

void BallAndStick::showHydrogens(bool show)
{
  auto& interface = m_layerManager.getSetting<LayerBallAndStick>();
  if (show != interface.showHydrogens) {
    interface.showHydrogens = show;
    emit drawablesChanged();
  }
  QSettings settings;
  settings.setValue("ballandstick/showHydrogens", show);
}

} // namespace Avogadro::QtPlugins
