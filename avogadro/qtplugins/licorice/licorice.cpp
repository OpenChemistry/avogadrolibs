/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "licorice.h"

#include <avogadro/core/elements.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/rendering/cylindergeometry.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/groupnode.h>
#include <avogadro/rendering/spheregeometry.h>

#include <QtCore/QSettings>
#include <QtWidgets/QFormLayout>
#include <QtWidgets/QSlider>

namespace Avogadro::QtPlugins {

using QtGui::Molecule;
using QtGui::PluginLayerManager;
using Rendering::CylinderGeometry;
using Rendering::GeometryNode;
using Rendering::GroupNode;
using Rendering::SphereGeometry;

struct LayerLicorice : Core::LayerData
{
  QWidget* widget;
  float opacity;

  LayerLicorice()
  {
    widget = nullptr;
    QSettings settings;
    opacity = settings.value("licorice/opacity", 1.0).toFloat();
  }

  LayerLicorice(std::string settings)
  {
    widget = nullptr;
    deserialize(settings);
  }

  LayerData* clone() final { return new LayerLicorice(*this); }

  ~LayerLicorice() override
  {
    if (widget)
      widget->deleteLater();
  }

  std::string serialize() final { return std::to_string(opacity); }

  void deserialize(std::string text) final
  {
    std::stringstream ss(text);
    std::string aux;
    ss >> aux;
    opacity = std::stof(aux);
  }

  void setupWidget(Licorice* slot)
  {
    if (!widget) {
      widget = new QWidget(qobject_cast<QWidget*>(slot->parent()));
      auto* form = new QFormLayout;

      // Opacity
      auto* slider = new QSlider(Qt::Horizontal);
      slider->setRange(0, 100);
      slider->setTickInterval(1);
      slider->setValue(round(opacity * 100));
      QObject::connect(slider, &QSlider::valueChanged, slot,
                       &Licorice::setOpacity);

      form->addRow(QObject::tr("Opacity:"), slider);
      widget->setLayout(form);
    }
  }
};

Licorice::Licorice(QObject* p) : ScenePlugin(p)
{
  m_layerManager = PluginLayerManager(m_name);
}

Licorice::~Licorice() {}

void Licorice::process(const Molecule& molecule, Rendering::GroupNode& node)
{
  m_layerManager.load<LayerLicorice>();

  // Use a common radius for all spheres and cylinders.
  float radius(0.2f);
  float selectedRadius(radius * 2.0f);

  // Add a sphere node to contain all of the spheres.
  auto* geometry = new GeometryNode;
  node.addChild(geometry);
  auto* spheres = new SphereGeometry;
  spheres->identifier().molecule = &molecule;
  spheres->identifier().type = Rendering::AtomType;

  auto selectedSpheres = new SphereGeometry;
  selectedSpheres->setOpacity(0.42);

  auto translucentSpheres = new SphereGeometry;
  translucentSpheres->setRenderPass(Rendering::TranslucentPass);
  translucentSpheres->identifier().molecule = &molecule;
  translucentSpheres->identifier().type = Rendering::AtomType;

  geometry->addDrawable(spheres);
  geometry->addDrawable(selectedSpheres);
  geometry->addDrawable(translucentSpheres);

  float opacity = 1.0;

  for (Index i = 0; i < molecule.atomCount(); ++i) {
    Core::Atom atom = molecule.atom(i);
    if (!m_layerManager.atomEnabled(i)) {
      continue;
    }
    Vector3ub color = atom.color();

    auto* interface =
      m_layerManager.getSetting<LayerLicorice>(m_layerManager.getLayerID(i));
    opacity = interface->opacity;
    if (opacity < 1.0f) {
      translucentSpheres->addSphere(atom.position3d().cast<float>(), color,
                                    radius, i);
      translucentSpheres->setOpacity(opacity);
    } else
      spheres->addSphere(atom.position3d().cast<float>(), color, radius, i);

    if (atom.selected()) {
      color = Vector3ub(0, 0, 255);
      selectedSpheres->addSphere(atom.position3d().cast<float>(), color,
                                 selectedRadius, i);
    }
  }

  auto* cylinders = new CylinderGeometry;
  cylinders->identifier().molecule = &molecule;
  cylinders->identifier().type = Rendering::BondType;

  auto* translucentCylinders = new CylinderGeometry;
  translucentCylinders->setRenderPass(Rendering::TranslucentPass);
  translucentCylinders->identifier().molecule = &molecule;
  translucentCylinders->identifier().type = Rendering::BondType;

  geometry->addDrawable(cylinders);
  geometry->addDrawable(translucentCylinders);

  for (Index i = 0; i < molecule.bondCount(); ++i) {
    Core::Bond bond = molecule.bond(i);
    if (!m_layerManager.bondEnabled(bond.atom1().index(),
                                    bond.atom2().index())) {
      continue;
    }

    auto* interface1 = m_layerManager.getSetting<LayerLicorice>(
      m_layerManager.getLayerID(bond.atom1().index()));
    auto* interface2 = m_layerManager.getSetting<LayerLicorice>(
      m_layerManager.getLayerID(bond.atom2().index()));

    bool doOpaque = true;
    if (interface1->opacity < 1.0f || interface2->opacity < 1.0f) {
      opacity = std::min(interface1->opacity, interface2->opacity);
      translucentCylinders->setOpacity(opacity);
      doOpaque = false;
    }

    Vector3f pos1 = bond.atom1().position3d().cast<float>();
    Vector3f pos2 = bond.atom2().position3d().cast<float>();
    Vector3ub color1 = bond.atom1().color();
    Vector3ub color2 = bond.atom2().color();
    Vector3f bondVector = pos2 - pos1;
    float bondLength = bondVector.norm();
    bondVector /= bondLength;

    if (doOpaque)
      cylinders->addCylinder(pos1, pos2, radius, color1, color2, i);
    else
      translucentCylinders->addCylinder(pos1, pos2, radius, color1, color2, i);
  }
}

void Licorice::setOpacity(int opacity)
{
  m_opacity = static_cast<float>(opacity) / 100.0f;
  auto* interface = m_layerManager.getSetting<LayerLicorice>();
  if (m_opacity != interface->opacity) {
    interface->opacity = m_opacity;
    emit drawablesChanged();
  }

  QSettings settings;
  settings.setValue("licorice/opacity", m_opacity);
}

QWidget* Licorice::setupWidget()
{
  auto* interface = m_layerManager.getSetting<LayerLicorice>();
  interface->setupWidget(this);
  return interface->widget;
}

} // namespace Avogadro::QtPlugins
