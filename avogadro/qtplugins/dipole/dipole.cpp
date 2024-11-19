/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "dipole.h"

#include <avogadro/calc/chargemanager.h>
#include <avogadro/core/elements.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/rendering/arrowgeometry.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/groupnode.h>

#include <QTimer>
#include <QtWidgets/QWidget>

namespace Avogadro::QtPlugins {

using QtGui::Molecule;
using Rendering::ArrowGeometry;
using Rendering::GeometryNode;
using Rendering::GroupNode;

Dipole::Dipole(QObject* p) : ScenePlugin(p)
{
  m_layerManager = QtGui::PluginLayerManager(m_name);
}

Dipole::~Dipole() {}

void Dipole::process(const QtGui::Molecule& molecule,
                     Rendering::GroupNode& node)
{
  auto* geometry = new GeometryNode;
  node.addChild(geometry);

  auto* arrow = new ArrowGeometry;
  arrow->identifier().molecule = &molecule;

  arrow->setColor(Vector3ub(255, 0, 0));
  geometry->addDrawable(arrow);

  Vector3f origin = Vector3f::Zero();
  // check if the molecule has the dipole set
  if (!m_customDipole) {
    if (molecule.hasData("dipoleMoment"))
      m_dipoleVector = molecule.data("dipoleMoment").toVector3();

    // make sure the molecule tells us when to update
    connect(&molecule, &Molecule::changed, this, &Dipole::updateDipole);
  }

  arrow->addSingleArrow(m_dipoleVector.cast<float>(), origin);
}

QWidget* Dipole::setupWidget()
{
  return nullptr;
}

void Dipole::updateFinished()
{
  m_updateRequested = false;
}

void Dipole::updateDipole()
{
  // get the molecule as the sender
  auto* molecule = qobject_cast<Molecule*>(sender());
  if (!molecule || molecule->atomCount() == 0)
    return; // nothing to do

  if (!m_updateRequested) {
    // calculate the dipole moment
    m_dipoleVector =
      Calc::ChargeManager::instance().dipoleMoment(m_type, *molecule);
    // don't ask for another 500 ms
    QTimer::singleShot(500, this, &Dipole::updateFinished);
  }

  m_updateRequested = true;
}

} // namespace Avogadro::QtPlugins
