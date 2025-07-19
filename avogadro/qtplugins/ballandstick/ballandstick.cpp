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

#include <iostream>

namespace Avogadro::QtPlugins {

using Core::Elements;
using QtGui::PluginLayerManager;
using Rendering::CylinderGeometry;
using Rendering::GeometryNode;
using Rendering::SphereGeometry;

struct LayerBallAndStick : Core::LayerData
{
  QWidget* widget;
  bool multiBonds;
  bool showHydrogens;
  float atomScale;
  float bondRadius;
  float opacity;

  LayerBallAndStick()
  {
    widget = nullptr;
    QSettings settings;

    atomScale = settings.value("ballandstick/atomScale", 0.3).toDouble();
    bondRadius = settings.value("ballandstick/bondRadius", 0.1).toDouble();
    multiBonds = settings.value("ballandstick/multiBonds", true).toBool();
    showHydrogens = settings.value("ballandstick/showHydrogens", true).toBool();
    opacity = settings.value("ballandstick/opacity", 1.0).toDouble();
  }

  LayerBallAndStick(std::string settings)
  {
    widget = nullptr;
    deserialize(settings);
  }

  ~LayerBallAndStick() override
  {
    if (widget)
      widget->deleteLater();
  }

  std::string serialize() final
  {
    return boolToString(multiBonds) + " " + boolToString(showHydrogens) + " " +
           std::to_string(atomScale) + " " + std::to_string(bondRadius) + " " +
           std::to_string(opacity);
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
    ss >> aux;
    if (!aux.empty())
      opacity = std::stof(aux); // backwards compatibility
  }

  LayerData* clone() final { return new LayerBallAndStick(serialize()); }

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

      auto* opacitySlider = new QSlider(Qt::Horizontal);
      opacitySlider->setMinimum(0);
      opacitySlider->setMaximum(100);
      opacitySlider->setTickInterval(1);
      opacitySlider->setValue(static_cast<int>(opacity * 100));
      QObject::connect(opacitySlider, &QSlider::valueChanged, slot,
                       &BallAndStick::opacityChanged);
      f->addRow(QObject::tr("Opacity"), opacitySlider);

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
  auto* geometry = new GeometryNode;
  node.addChild(geometry);
  auto* spheres = new SphereGeometry;
  spheres->identifier().molecule = reinterpret_cast<const void*>(&molecule);
  spheres->identifier().type = Rendering::AtomType;
  geometry->addDrawable(spheres);

  // if we have to draw any translucent spheres, we need to add a separate
  // geometry node for them
  auto translucentSpheres = new SphereGeometry;
  translucentSpheres->setRenderPass(Rendering::TranslucentPass);
  translucentSpheres->identifier().molecule =
    reinterpret_cast<const void*>(&molecule);
  translucentSpheres->identifier().type = Rendering::AtomType;
  geometry->addDrawable(translucentSpheres);

  // for the selected atoms
  auto selectedSpheres = new SphereGeometry;
  selectedSpheres->setOpacity(0.42);
  geometry->addDrawable(selectedSpheres);

  for (Index i = 0; i < molecule.atomCount(); ++i) {
    Core::Atom atom = molecule.atom(i);
    if (!m_layerManager.atomEnabled(i)) {
      continue;
    }
    unsigned char atomicNumber = atom.atomicNumber();

    auto* interface = m_layerManager.getSetting<LayerBallAndStick>(
      m_layerManager.getLayerID(i));
    if (atomicNumber == 1 && !interface->showHydrogens)
      continue;

    Vector3ub color = atom.color();
    auto radius = static_cast<float>(Elements::radiusVDW(atomicNumber));
    float scale = interface->atomScale;

    if (interface->opacity < 1.0f) {
      translucentSpheres->addSphere(atom.position3d().cast<float>(), color,
                                    radius * scale, i);
      translucentSpheres->setOpacity(interface->opacity);
    } else
      spheres->addSphere(atom.position3d().cast<float>(), color, radius * scale,
                         i);

    if (atom.selected()) {
      // add the selected indicator
      color = Vector3ub(0, 0, 255);
      radius *= 1.2;
      selectedSpheres->addSphere(atom.position3d().cast<float>(), color,
                                 radius * scale, i);
    }
  }

  auto* cylinders = new CylinderGeometry;
  cylinders->identifier().molecule = &molecule;
  cylinders->identifier().type = Rendering::BondType;
  geometry->addDrawable(cylinders);

  auto* translucentBonds = new CylinderGeometry;
  translucentBonds->setRenderPass(Rendering::TranslucentPass);
  translucentBonds->identifier().molecule = &molecule;
  translucentBonds->identifier().type = Rendering::BondType;
  float opacity = 1.0f; // for any translucent bonds
  geometry->addDrawable(translucentBonds);

  for (Index i = 0; i < molecule.bondCount(); ++i) {
    Core::Bond bond = molecule.bond(i);
    if (!m_layerManager.bondEnabled(bond.atom1().index(),
                                    bond.atom2().index())) {
      continue;
    }

    auto* interface1 = m_layerManager.getSetting<LayerBallAndStick>(
      m_layerManager.getLayerID(bond.atom1().index()));
    auto* interface2 = m_layerManager.getSetting<LayerBallAndStick>(
      m_layerManager.getLayerID(bond.atom2().index()));

    if (!interface1->showHydrogens && !interface2->showHydrogens &&
        (bond.atom1().atomicNumber() == 1 ||
         bond.atom2().atomicNumber() == 1)) {
      continue;
    }

    bool doOpaque = true;
    if (interface1->opacity < 1.0f || interface2->opacity < 1.0f) {
      opacity = std::min(interface1->opacity, interface2->opacity);
      translucentBonds->setOpacity(opacity);
      doOpaque = false;
    }

    float bondRadius = (interface1->bondRadius + interface2->bondRadius) * 0.5f;

    Vector3f pos1 = bond.atom1().position3d().cast<float>();
    Vector3f pos2 = bond.atom2().position3d().cast<float>();
    Vector3ub color1 = bond.atom1().color();
    Vector3ub color2 = bond.atom2().color();
    Vector3f bondVector = pos2 - pos1;
    float bondLength = bondVector.norm();
    bondVector /= bondLength;

    switch (interface1->multiBonds || interface2->multiBonds ? bond.order()
                                                             : 1) {
      case 3: {
        Vector3f delta = bondVector.unitOrthogonal();
        // Rotate 45 degrees around the bond vector.
        Eigen::Quaternionf q;
        q = Eigen::AngleAxisf(45.0f * DEG_TO_RAD_F, bondVector);
        delta = q * delta * 2.0f * bondRadius;
        if (doOpaque) {
          cylinders->addCylinder(pos1 + delta, pos2 + delta, bondRadius * 1.15,
                                 color1, color2, i);
          cylinders->addCylinder(pos1 - delta, pos2 - delta, bondRadius * 1.15,
                                 color1, color2, i);
        } else {
          translucentBonds->addCylinder(pos1 + delta, pos2 + delta,
                                        bondRadius * 1.15, color1, color2, i);
          translucentBonds->addCylinder(pos1 - delta, pos2 - delta,
                                        bondRadius * 1.15, color1, color2, i);
        }
        // This relies upon the single bond case below for the third cylinder.
        [[fallthrough]];
      }
      default:
      case 1:
        if (doOpaque) {
          cylinders->addCylinder(pos1, pos2, m_bondRadius, color1, color2, i);
        } else {
          translucentBonds->addCylinder(pos1, pos2, m_bondRadius, color1,
                                        color2, i);
        }
        break;
      case 2: {
        Vector3f delta = bondVector.unitOrthogonal();
        // Rotate 45 degrees around the bond vector.
        Eigen::Quaternionf q;
        q = Eigen::AngleAxisf(45.0f * DEG_TO_RAD_F, bondVector);
        delta = q * delta * bondRadius;
        if (doOpaque) {
          cylinders->addCylinder(pos1 + delta, pos2 + delta, bondRadius * 1.3,
                                 color1, color2, i);
          cylinders->addCylinder(pos1 - delta, pos2 - delta, bondRadius * 1.3,
                                 color1, color2, i);
        } else {
          translucentBonds->addCylinder(pos1 + delta, pos2 + delta,
                                        bondRadius * 1.3, color1, color2, i);
          translucentBonds->addCylinder(pos1 - delta, pos2 - delta,
                                        bondRadius * 1.3, color1, color2, i);
        }
      }
    }
  }
}

QWidget* BallAndStick::setupWidget()
{
  auto* interface = m_layerManager.getSetting<LayerBallAndStick>();
  interface->setupWidget(this);
  return interface->widget;
}

void BallAndStick::opacityChanged(int opacity)
{
  m_opacity = static_cast<float>(opacity) / 100.0f;
  auto* interface = m_layerManager.getSetting<LayerBallAndStick>();
  if (m_opacity != interface->opacity) {
    interface->opacity = m_opacity;
    emit drawablesChanged();
  }

  QSettings settings;
  settings.setValue("ballandstick/opacity", m_opacity);
}

void BallAndStick::atomRadiusChanged(int value)
{
  m_atomScale = static_cast<float>(value) / 10.0f;

  auto* interface = m_layerManager.getSetting<LayerBallAndStick>();
  if (m_atomScale != interface->atomScale) {
    interface->atomScale = m_atomScale;
    emit drawablesChanged();
  }

  QSettings settings;
  settings.setValue("ballandstick/atomScale", m_atomScale);
}

void BallAndStick::bondRadiusChanged(int value)
{
  m_bondRadius = static_cast<float>(value) / 10.0f;

  auto* interface = m_layerManager.getSetting<LayerBallAndStick>();
  if (m_bondRadius != interface->bondRadius) {
    interface->bondRadius = m_bondRadius;
    emit drawablesChanged();
  }

  QSettings settings;
  settings.setValue("ballandstick/bondRadius", m_bondRadius);
}

void BallAndStick::multiBonds(bool show)
{
  auto* interface = m_layerManager.getSetting<LayerBallAndStick>();
  if (show != interface->multiBonds) {
    interface->multiBonds = show;
    emit drawablesChanged();
  }
  QSettings settings;
  settings.setValue("ballandstick/multiBonds", show);
}

void BallAndStick::showHydrogens(bool show)
{
  auto* interface = m_layerManager.getSetting<LayerBallAndStick>();
  if (show != interface->showHydrogens) {
    interface->showHydrogens = show;
    emit drawablesChanged();
  }
  QSettings settings;
  settings.setValue("ballandstick/showHydrogens", show);
}

} // namespace Avogadro::QtPlugins
