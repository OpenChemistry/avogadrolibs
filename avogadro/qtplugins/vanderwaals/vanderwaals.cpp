/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "vanderwaals.h"

#include <avogadro/core/elements.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/groupnode.h>
#include <avogadro/rendering/spheregeometry.h>

#include <QtCore/QSettings>
#include <QtWidgets/QFormLayout>
#include <QtWidgets/QSlider>

namespace Avogadro::QtPlugins {

using Core::Elements;
using QtGui::PluginLayerManager;
using Rendering::GeometryNode;
using Rendering::GroupNode;
using Rendering::SphereGeometry;

struct LayerVdW : Core::LayerData
{
  QWidget* widget;
  float opacity;

  LayerVdW()
  {
    widget = nullptr;
    QSettings settings;
    opacity = settings.value("vdw/opacity", 1.0).toFloat();
  }

  LayerVdW(std::string settings)
  {
    widget = nullptr;
    deserialize(settings);
  }

  LayerData* clone() final { return new LayerVdW(*this); }

  ~LayerVdW() override
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

  void setupWidget(VanDerWaals* slot)
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
                       &VanDerWaals::setOpacity);

      form->addRow(QObject::tr("Opacity:"), slider);
      widget->setLayout(form);
    }
  }
};

VanDerWaals::VanDerWaals(QObject* p) : ScenePlugin(p)
{
  m_layerManager = PluginLayerManager(m_name);

  QSettings settings;
}

VanDerWaals::~VanDerWaals() {}

void VanDerWaals::process(const QtGui::Molecule& molecule,
                          Rendering::GroupNode& node)
{
  m_layerManager.load<LayerVdW>();

  // Add a sphere node to contain all of the VdW spheres.
  auto* geometry = new GeometryNode;
  node.addChild(geometry);
  auto* spheres = new SphereGeometry;
  spheres->identifier().molecule = &molecule;
  spheres->identifier().type = Rendering::AtomType;

  auto* translucentSpheres = new SphereGeometry;
  translucentSpheres->setRenderPass(Rendering::TranslucentPass);
  translucentSpheres->identifier().molecule = &molecule;
  translucentSpheres->identifier().type = Rendering::AtomType;

  auto selectedSpheres = new SphereGeometry;
  selectedSpheres->setOpacity(0.42);
  selectedSpheres->setRenderPass(Rendering::TranslucentPass);

  geometry->addDrawable(spheres);
  geometry->addDrawable(selectedSpheres);
  geometry->addDrawable(translucentSpheres);

  for (Index i = 0; i < molecule.atomCount(); ++i) {
    Core::Atom atom = molecule.atom(i);
    if (!m_layerManager.atomEnabled(i)) {
      continue;
    }
    unsigned char atomicNumber = atom.atomicNumber();

    Vector3ub color = atom.color();
    auto radius = static_cast<float>(Elements::radiusVDW(atomicNumber));
    auto* interface =
      m_layerManager.getSetting<LayerVdW>(m_layerManager.getLayerID(i));
    float opacity = interface->opacity;
    if (opacity < 1.0f) {
      translucentSpheres->addSphere(atom.position3d().cast<float>(), color,
                                    radius, i);
      translucentSpheres->setOpacity(opacity);
    } else {
      spheres->addSphere(atom.position3d().cast<float>(), color, radius, i);
    }

    if (atom.selected()) {
      color = Vector3ub(0, 0, 255);
      radius += 0.3f;
      selectedSpheres->addSphere(atom.position3d().cast<float>(), color, radius,
                                 i);
    }
  }
}

void VanDerWaals::setOpacity(int opacity)
{
  m_opacity = static_cast<float>(opacity) / 100.0f;
  auto* interface = m_layerManager.getSetting<LayerVdW>();
  if (m_opacity != interface->opacity) {
    interface->opacity = m_opacity;
    emit drawablesChanged();
  }

  QSettings settings;
  settings.setValue("vdw/opacity", m_opacity);
}

QWidget* VanDerWaals::setupWidget()
{
  auto* interface = m_layerManager.getSetting<LayerVdW>();
  interface->setupWidget(this);
  return interface->widget;
}

} // namespace Avogadro::QtPlugins
