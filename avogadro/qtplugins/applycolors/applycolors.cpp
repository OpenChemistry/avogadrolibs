/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "applycolors.h"

#include <avogadro/qtgui/molecule.h>

#include <QtCore/QStringList>
#include <QtWidgets/QAction>
#include <QtWidgets/QColorDialog>

namespace Avogadro {
namespace QtPlugins {

ApplyColors::ApplyColors(QObject* parent_)
  : Avogadro::QtGui::ExtensionPlugin(parent_), m_molecule(nullptr),
    m_dialog(nullptr)
{
  QAction* action;

  action = new QAction(tr("By Custom Color..."), this);
  connect(action, SIGNAL(triggered()), SLOT(openColorDialog()));
  m_actions.append(action);

  action = new QAction(tr("By Atomic Index"), this);
  connect(action, SIGNAL(triggered()), SLOT(applyIndexColors()));
  m_actions.append(action);

  action = new QAction(tr("By Element"), this);
  connect(action, SIGNAL(triggered()), SLOT(resetColors()));
  m_actions.append(action);

  // add a separator if we're going to have residue actions
  // (by chain id, etc.)
}

ApplyColors::~ApplyColors()
{
  if (m_dialog)
    m_dialog->deleteLater();
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
  return QStringList() << tr("&View") << tr("Color Atoms");
}

void ApplyColors::setMolecule(QtGui::Molecule* mol)
{
  m_molecule = mol;
}

void ApplyColors::openColorDialog()
{
  if (m_dialog == nullptr) {
    m_dialog = new QColorDialog(qobject_cast<QWidget*>(parent()));
    connect(m_dialog, SIGNAL(currentColorChanged(const QColor&)),
            SLOT(applyCustomColor(const QColor&)));
  }

  m_dialog->exec();
}

// TODO - read colormap gradients
Vector3ub rainbowGradient(float value)
{
  Vector3 color;

  if (value < 0.4f) {
    // red to orange (i.e., R = 1.0  and G goes from 0 -> 0.5
    // also orange to yellow R = 1.0 and G goes from 0.5 -> 1.0
    color[0] = 1.0f;         // red
    color[1] = value * 2.5f; // green
    color[2] = 0.0f;         // blue
  } else if (value > 0.4f && value < 0.6f) {
    // yellow to green: R 1.0 -> 0.0 and G stays 1.0
    color[0] = 1.0f - 5.0f * (value - 0.4f); // red
    color[1] = 1.0f;                         // green
    color[2] = 0.0f;                         // blue
  } else if (value > 0.6f && value < 0.8f) {
    // green to blue: G -> 0.0 and B -> 1.0
    color[0] = 0.0f;                         // red
    color[1] = 1.0f - 5.0f * (value - 0.6f); // green
    color[2] = 5.0f * (value - 0.6f);        // blue
  } else if (value > 0.8f) {
    // blue to purple: B -> 0.5 and R -> 0.5
    color[0] = 2.5f * (value - 0.8f);
    color[1] = 0.0;
    color[2] = 1.0f - 2.5f * (value - 0.8f);
  }
  color *= 255;

  return color.cast<unsigned char>();
}

void ApplyColors::applyIndexColors()
{
  if (m_molecule == nullptr)
    return;

  bool isSelection = !m_molecule->isSelectionEmpty();

  // probably better to get color scales, but for now do it manually
  auto numAtoms = m_molecule->atomCount();
  for (Index i = 0; i < numAtoms; ++i) {
    // if there's a selection and this atom isn't selected, skip  it
    if (isSelection && !m_molecule->atomSelected(i))
      continue;

    float indexFraction = float(i) / float(numAtoms);

    m_molecule->atom(i).setColor(rainbowGradient(indexFraction));
  }

  m_molecule->emitChanged(QtGui::Molecule::Atoms);
}

void ApplyColors::resetColors()
{
  if (m_molecule == nullptr)
    return;

  bool isSelection = !m_molecule->isSelectionEmpty();

  for (Index i = 0; i < m_molecule->atomCount(); ++i) {
    // if there's a selection and this atom isn't selected, skip  it
    if (isSelection && !m_molecule->atomSelected(i))
      continue;

    Vector3ub color(Core::Elements::color(m_molecule->atomicNumber(i)));
    m_molecule->atom(i).setColor(color);
  }

  m_molecule->emitChanged(QtGui::Molecule::Atoms);
}

void ApplyColors::applyCustomColor(const QColor& new_color)
{
  if (m_molecule == nullptr)
    return;

  bool isSelection = !m_molecule->isSelectionEmpty();

  Vector3ub color; // map to our types
  color[0] = static_cast<unsigned char>(new_color.red());
  color[1] = static_cast<unsigned char>(new_color.green());
  color[2] = static_cast<unsigned char>(new_color.blue());

  for (Index i = 0; i < m_molecule->atomCount(); ++i) {
    // if there's a selection and this atom isn't selected, skip  it
    if (isSelection && !m_molecule->atomSelected(i))
      continue;

    m_molecule->atom(i).setColor(color);
  }

  m_molecule->emitChanged(QtGui::Molecule::Atoms);
}

} // namespace QtPlugins
} // namespace Avogadro
