/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "applycolors.h"

#include <avogadro/qtgui/molecule.h>

#include <QtWidgets/QAction>

#include <QtCore/QStringList>

namespace Avogadro {
namespace QtPlugins {

ApplyColors::ApplyColors(QObject* parent_)
  : Avogadro::QtGui::ExtensionPlugin(parent_), m_molecule(nullptr)
{
  QAction* action;
  
  /*
  action = new QAction(tr("Custom Color..."), this);
  connect(action, SIGNAL(triggered()), SLOT(adjustApplyColors()));
  m_actions.append(action);
  */

  action = new QAction(tr("By Atomic Index"), this);
  connect(action, SIGNAL(triggered()), SLOT(applyIndexColors()));
  m_actions.append(action);

  action = new QAction(tr("Reset Colors"), this);
  connect(action, SIGNAL(triggered()), SLOT(resetColors()));
  m_actions.append(action);
}

ApplyColors::~ApplyColors()
{
}

QString ApplyColors::description() const
{
  return tr("Apply color schemes to atoms and residues.");
}

QList<QAction*> ApplyColors::actions() const
{
  return m_actions;
}

QStringList ApplyColors::menuPath(QAction*) const
{
  return QStringList() << tr("&View") << tr("&Apply Colors");
}

void ApplyColors::setMolecule(QtGui::Molecule* mol)
{
  m_molecule = mol;
}

void ApplyColors::applyIndexColors()
{
  if (m_molecule == nullptr)
    return;



  // probably better to get color scales, but for now do it manually
  float r, g, b;
  auto numAtoms = m_molecule->atomCount();
  for (Index i = 0; i < numAtoms; ++i) {
    float indexFraction = float(i) / float(numAtoms);

    if (indexFraction < 0.4f) {
      // red to orange (i.e., R = 1.0  and G goes from 0 -> 0.5
      // also orange to yellow R = 1.0 and G goes from 0.5 -> 1.0
      r = 1.0f; // red
      g = indexFraction * 2.5f; // green
      b = 0.0f; // blue
    } else if (indexFraction > 0.4f && indexFraction < 0.6f) {
      // yellow to green: R 1.0 -> 0.0 and G stays 1.0
      r = 1.0f - 5.0f * (indexFraction - 0.4f); // red
      g = 1.0f; // green
      b = 0.0f; // blue
    } else if (indexFraction > 0.6f && indexFraction < 0.8f) {
      // green to blue: G -> 0.0 and B -> 1.0
      r = 0.0f; // red
      g = 1.0f - 5.0f * (indexFraction - 0.6f); // green
      b = 5.0f * (indexFraction - 0.6f); // blue
    } else if (indexFraction > 0.8f) {
    // blue to purple: B -> 0.5 and R -> 0.5
      r = 2.5f * (indexFraction - 0.8f);
      g = 0.0;
      b = 1.0f - 2.5f * (indexFraction - 0.8f);
    } 
    Vector3ub color(r*255, g*255, b*255);

    m_molecule->atom(i).setColor(color);
  }

  m_molecule->emitChanged(QtGui::Molecule::Atoms);
}

void ApplyColors::resetColors()
{
  if (m_molecule == nullptr)
    return;

  for (Index i = 0; i < m_molecule->atomCount(); ++i) {
    Vector3ub color(Core::Elements::color(m_molecule->atomicNumber(i)));
    m_molecule->atom(i).setColor(color);
  }

  m_molecule->emitChanged(QtGui::Molecule::Atoms);
}


} // namespace QtPlugins
} // namespace Avogadro
