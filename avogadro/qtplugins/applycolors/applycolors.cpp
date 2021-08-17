/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "applycolors.h"

#include <avogadro/core/residue.h>
#include <avogadro/core/residuecolors.h>
#include <avogadro/qtgui/molecule.h>

#include <QtCore/QStringList>
#include <QtWidgets/QAction>
#include <QtWidgets/QColorDialog>

namespace Avogadro {
namespace QtPlugins {

const int atomColors = 0;
const int bondColors = 1;
const int residueColors = 2;

ApplyColors::ApplyColors(QObject* parent_)
  : Avogadro::QtGui::ExtensionPlugin(parent_), m_molecule(nullptr),
    m_dialog(nullptr)
{
  QAction* action;

  action = new QAction(tr("By Custom Color..."), this);
  action->setData(atomColors);
  connect(action, SIGNAL(triggered()), SLOT(openColorDialog()));
  m_actions.append(action);

  action = new QAction(tr("By Atomic Index"), this);
  action->setData(atomColors);
  connect(action, SIGNAL(triggered()), SLOT(applyIndexColors()));
  m_actions.append(action);

  action = new QAction(tr("By Distance"), this);
  action->setData(atomColors);
  connect(action, SIGNAL(triggered()), SLOT(applyDistanceColors()));
  m_actions.append(action);

  action = new QAction(tr("By Element"), this);
  action->setData(atomColors);
  connect(action, SIGNAL(triggered()), SLOT(resetColors()));
  m_actions.append(action);

  // not sure if we want to color atoms by residue or not...
  action = new QAction(tr("By Custom Color..."), this);
  action->setData(residueColors);
  connect(action, SIGNAL(triggered()), SLOT(openColorDialogResidue()));
  m_actions.append(action);

  action = new QAction(tr("By Chain"), this);
  action->setData(residueColors);
  connect(action, SIGNAL(triggered()), SLOT(resetColorsResidue()));
  m_actions.append(action);

  action = new QAction(tr("By Secondary Structure"), this);
  action->setData(residueColors);
  connect(action, SIGNAL(triggered()), SLOT(applySecondaryStructureColors()));
  m_actions.append(action);

  action = new QAction(tr("By Amino Acid"), this);
  action->setData(residueColors);
  connect(action, SIGNAL(triggered()), SLOT(applyAminoColors()));
  m_actions.append(action);

  action = new QAction(tr("By Shapely Scheme"), this);
  action->setData(residueColors);
  connect(action, SIGNAL(triggered()), SLOT(applyShapelyColors()));
  m_actions.append(action);
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

QStringList ApplyColors::menuPath(QAction* action) const
{
  if (action->data() == atomColors)
    return QStringList() << tr("&View") << tr("Color Atoms");
  else if (action->data() == residueColors)
    return QStringList() << tr("&View") << tr("Color Residues");
  else
    return QStringList();
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

void ApplyColors::applyDistanceColors()
{
  if (m_molecule == nullptr && m_molecule->atomCount() == 0)
    return;

  bool isSelection = !m_molecule->isSelectionEmpty();
  Vector3 firstPos = m_molecule->atomPosition3d(0);
  Real size = 2.0 * m_molecule->radius();

  // probably better to get color scales, but for now do it manually
  auto numAtoms = m_molecule->atomCount();
  for (Index i = 0; i < numAtoms; ++i) {
    // if there's a selection and this atom isn't selected, skip  it
    if (isSelection && !m_molecule->atomSelected(i))
      continue;

    Vector3 currPos = m_molecule->atomPosition3d(i);
    Vector3 diff = currPos - firstPos;
    Real distance = diff.norm();
    Real distanceFraction = distance / size;

    m_molecule->atom(i).setColor(rainbowGradient(distanceFraction));
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

void ApplyColors::openColorDialogResidue()
{
  if (m_dialog == nullptr) {
    m_dialog = new QColorDialog(qobject_cast<QWidget*>(parent()));
  }
  m_dialog->disconnect();
  connect(m_dialog, SIGNAL(currentColorChanged(const QColor&)),
          SLOT(applyCustomColorResidue(const QColor&)));

  m_dialog->exec();
}

void ApplyColors::applyCustomColorResidue(const QColor& new_color)
{
  if (m_molecule == nullptr)
    return;

  bool isSelection = !m_molecule->isSelectionEmpty();

  Vector3ub color; // map to our types
  color[0] = static_cast<unsigned char>(new_color.red());
  color[1] = static_cast<unsigned char>(new_color.green());
  color[2] = static_cast<unsigned char>(new_color.blue());

  for (Index i = 0; i < m_molecule->residueCount(); ++i) {
    // if there's a selection and this residue isn't selected, skip it
    auto& residue = m_molecule->residue(i);
    if (isSelection &&
        !m_molecule->atomSelected(residue.getAtomByName("CA").index()))
      continue;

    residue.setColor(color);
  }

  m_molecule->emitChanged(QtGui::Molecule::Atoms);
}

void ApplyColors::resetColorsResidue()
{
  if (m_molecule == nullptr)
    return;

  bool isSelection = !m_molecule->isSelectionEmpty();

  for (Index i = 0; i < m_molecule->residueCount(); ++i) {
    // if there's a selection and this residue isn't selected, skip it
    auto& residue = m_molecule->residue(i);
    if (isSelection &&
        !m_molecule->atomSelected(residue.getAtomByName("CA").index()))
      continue;

    int offset = 0;
    char chainId = residue.chainId();
    if (chainId >= 'A' && chainId <= 'Z')
      offset = chainId - 'A';
    else if (chainId >= 'a' && chainId <= 'z')
      offset = chainId - 'a';
    else if (chainId >= '0' && chainId <= '9')
      offset = chainId - '0' + 15; // starts at 'P'

    Vector3ub color(Core::chain_color[offset]);
    residue.setColor(color);
  }

  m_molecule->emitChanged(QtGui::Molecule::Atoms);
}

void ApplyColors::applySecondaryStructureColors()
{
  if (m_molecule == nullptr)
    return;

  bool isSelection = !m_molecule->isSelectionEmpty();

  for (Index i = 0; i < m_molecule->residueCount(); ++i) {
    // if there's a selection and this residue isn't selected, skip it
    auto& residue = m_molecule->residue(i);
    if (isSelection &&
        !m_molecule->atomSelected(residue.getAtomByName("CA").index()))
      continue;

    Core::Residue::SecondaryStructure type = residue.secondaryStructure();
    if (type < 0 || type > 7) {
      type = Core::Residue::SecondaryStructure::coil;
    }
    Vector3ub color(Core::secondary_color[type]);
    residue.setColor(color);
  } // end loop

  m_molecule->emitChanged(QtGui::Molecule::Atoms);
}

int residueNameToOffset(const std::string& name)
{
  std::string residueName(name);
  // ensure it's always in uppercase
  for (auto& c : residueName)
    c = (unsigned char)toupper(c);

  // used for "amino" and "shapely" color schemes
  int offset = 22; // other
  if (residueName == "ALA")
    offset = 0;
  else if (residueName == "ARG")
    offset = 1;
  else if (residueName == "ASN")
    offset = 2;
  else if (residueName == "ASP")
    offset = 3;
  else if (residueName == "CYS")
    offset = 4;
  else if (residueName == "GLN")
    offset = 5;
  else if (residueName == "GLU")
    offset = 6;
  else if (residueName == "GLY")
    offset = 7;
  else if (residueName == "HIS")
    offset = 8;
  else if (residueName == "ILE")
    offset = 9;
  else if (residueName == "LEU")
    offset = 10;
  else if (residueName == "LYS")
    offset = 11;
  else if (residueName == "MET")
    offset = 12;
  else if (residueName == "PHE")
    offset = 13;
  else if (residueName == "PRO")
    offset = 14;
  else if (residueName == "SER")
    offset = 15;
  else if (residueName == "THR")
    offset = 16;
  else if (residueName == "TRP")
    offset = 17;
  else if (residueName == "TYR")
    offset = 18;
  else if (residueName == "VAL")
    offset = 19;
  else if (residueName == "ASX")
    offset = 20;
  else if (residueName == "GLX")
    offset = 21;
  else
    offset = 22; // default

  return offset;
}

void ApplyColors::applyAminoColors()
{
  if (m_molecule == nullptr)
    return;

  bool isSelection = !m_molecule->isSelectionEmpty();

  for (Index i = 0; i < m_molecule->residueCount(); ++i) {
    // if there's a selection and this residue isn't selected, skip it
    auto& residue = m_molecule->residue(i);
    if (isSelection &&
        !m_molecule->atomSelected(residue.getAtomByName("CA").index()))
      continue;

    int offset = residueNameToOffset(residue.residueName());

    Vector3ub color(Core::amino_color[offset]);
    residue.setColor(color);
  }

  m_molecule->emitChanged(QtGui::Molecule::Atoms);
}

void ApplyColors::applyShapelyColors()
{
  if (m_molecule == nullptr)
    return;

  bool isSelection = !m_molecule->isSelectionEmpty();

  for (Index i = 0; i < m_molecule->residueCount(); ++i) {
    // if there's a selection and this residue isn't selected, skip it
    auto& residue = m_molecule->residue(i);
    if (isSelection &&
        !m_molecule->atomSelected(residue.getAtomByName("CA").index()))
      continue;

    int offset = residueNameToOffset(residue.residueName());

    Vector3ub color(Core::shapely_color[offset]);
    residue.setColor(color);
  }

  m_molecule->emitChanged(QtGui::Molecule::Atoms);
}

} // namespace QtPlugins
} // namespace Avogadro
