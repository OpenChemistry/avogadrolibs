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

VanDerWaals::VanDerWaals(QObject* p) : ScenePlugin(p)
{
  m_layerManager = PluginLayerManager(m_name);

  QSettings settings;
  // out of 255
  m_opacity = settings.value("vdw/opacity", 1.0).toFloat();
}

VanDerWaals::~VanDerWaals() {}

void VanDerWaals::process(const QtGui::Molecule& molecule,
                          Rendering::GroupNode& node)
{
  // Add a sphere node to contain all of the VdW spheres.
  auto* geometry = new GeometryNode;
  node.addChild(geometry);
  auto* spheres = new SphereGeometry;
  spheres->identifier().molecule = &molecule;
  spheres->identifier().type = Rendering::AtomType;
  spheres->setOpacity(m_opacity);
  if (m_opacity < 1.0f)
    spheres->setRenderPass(Rendering::TranslucentPass);

  auto selectedSpheres = new SphereGeometry;
  selectedSpheres->setOpacity(0.42);
  selectedSpheres->setRenderPass(Rendering::TranslucentPass);

  geometry->addDrawable(spheres);
  geometry->addDrawable(selectedSpheres);

  for (Index i = 0; i < molecule.atomCount(); ++i) {
    Core::Atom atom = molecule.atom(i);
    if (!m_layerManager.atomEnabled(i)) {
      continue;
    }
    unsigned char atomicNumber = atom.atomicNumber();

    Vector3ub color = atom.color();
    auto radius = static_cast<float>(Elements::radiusVDW(atomicNumber));
    spheres->addSphere(atom.position3d().cast<float>(), color, radius, i);
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
  m_opacity = opacity / 100.0f;
  emit drawablesChanged();

  QSettings settings;
  settings.setValue("vdw/opacity", m_opacity);
}

QWidget* VanDerWaals::setupWidget()
{
  if (!m_setupWidget) {
    m_setupWidget = new QWidget(qobject_cast<QWidget*>(parent()));
    auto* form = new QFormLayout;

    // Opacity
    auto* slide = new QSlider(Qt::Horizontal);
    slide->setRange(0, 100);
    slide->setTickInterval(1);
    slide->setValue(round(m_opacity * 100));
    connect(slide, SIGNAL(valueChanged(int)), SLOT(setOpacity(int)));

    form->addRow(tr("Opacity:"), slide);
    m_setupWidget->setLayout(form);
  }
  return m_setupWidget;
}

} // namespace Avogadro::QtPlugins
