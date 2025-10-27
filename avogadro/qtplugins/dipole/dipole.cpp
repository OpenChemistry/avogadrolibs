/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "dipole.h"

#include <avogadro/calc/chargemanager.h>
#include <avogadro/core/elements.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/rwmolecule.h>
#include <avogadro/rendering/arrowgeometry.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/groupnode.h>

#include <QDebug>
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
  // check if the molecule is empty
  // (single atoms don't have a dipole moment)
  if (molecule.atomCount() < 2) {
    return;
  }

  // check if the molecule has the dipole set
  if (!m_customDipole) {
    if (molecule.hasData("dipoleMoment")) {
      m_dipoleVector = molecule.data("dipoleMoment").toVector3();
    } else {
      // connect to molecule changes
      connect(&molecule, &QtGui::Molecule::update, this, &Dipole::updateDipole);
      connect(&molecule, SIGNAL(changed(unsigned int)), SLOT(updateDipole()));
    }
  } else {
    // custom dipole moment set
    m_dipoleVector = m_customDipoleVector;
  }

  // okay if we have all that, set up the arrow
  auto* geometry = new GeometryNode;
  node.addChild(geometry);

  auto* arrow = new ArrowGeometry;
  arrow->identifier().molecule = &molecule;

  arrow->setColor(Vector3ub(255, 0, 0));
  geometry->addDrawable(arrow);

  Vector3f origin = Vector3f::Zero();
  arrow->addSingleArrow(m_dipoleVector.cast<float>(), origin);
}

void Dipole::updateFinished()
{
  m_updateNeeded = true;
  emit drawablesChanged();
}

void Dipole::updateDipole()
{
  QtGui::Molecule* molecule = qobject_cast<QtGui::Molecule*>(sender());
  if (molecule == nullptr || molecule->isInteractive())
    return;

  // if the molecule has a dipole moment set, use it
  if (molecule->hasData("dipoleMoment"))
    return;

  // otherwise, calculate it
  if (m_updateNeeded) {
    m_updateNeeded = false;
    m_dipoleVector =
      Calc::ChargeManager::instance().dipoleMoment(m_type, *molecule);
    // single-shot
    QTimer::singleShot(0, this, SLOT(updateFinished()));
  }
}

QWidget* Dipole::setupWidget()
{
  return nullptr;
}

} // namespace Avogadro::QtPlugins
