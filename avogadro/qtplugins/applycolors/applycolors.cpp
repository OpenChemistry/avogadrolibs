/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "applycolors.h"
#include "ui_chargedialog.h"

#include "tinycolormap.hpp"

#include <avogadro/calc/chargemanager.h>
#include <avogadro/core/residue.h>
#include <avogadro/core/residuecolors.h>
#include <avogadro/qtgui/molecule.h>

#include <QtCore/QDebug>
#include <QtCore/QStringList>
#include <QtWidgets/QAction>
#include <QtWidgets/QColorDialog>
#include <QtWidgets/QInputDialog>

using namespace tinycolormap;

namespace Avogadro::QtPlugins {

const int atomColors = 0;
const int bondColors = 1;
const int residueColors = 2;

class ChargeColorDialog : public QDialog, public Ui::ChargeDialog
{
public:
  ChargeColorDialog(QWidget* parent = nullptr) : QDialog(parent)
  {
    setWindowFlags(Qt::Dialog | Qt::Tool);
    setupUi(this);
  }
};

ApplyColors::ApplyColors(QObject* parent_)
  : Avogadro::QtGui::ExtensionPlugin(parent_), m_molecule(nullptr),
    m_dialog(nullptr)
{
  QAction* action;

  action = new QAction(tr("By Custom Color…"), this);
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
  action = new QAction(tr("By Custom Color…"), this);
  action->setData(residueColors);
  connect(action, SIGNAL(triggered()), SLOT(openColorDialogResidue()));
  m_actions.append(action);

  action = new QAction(tr("By Chain"), this);
  action->setData(residueColors);
  connect(action, SIGNAL(triggered()), SLOT(resetColorsResidue()));
  m_actions.append(action);

  action = new QAction(tr("By Partial Charge…"), this);
  action->setData(atomColors);
  connect(action, SIGNAL(triggered()), SLOT(applyChargeColors()));
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

ColormapType ApplyColors::getColormapFromString(const QString& name) const
{
  // Just do all of them, even though we won't use them all
  if (name == tr("Parula", "colormap"))
    return ColormapType::Parula;
  else if (name == tr("Heat", "colormap"))
    return ColormapType::Heat;
  else if (name == tr("Hot", "colormap"))
    return ColormapType::Hot;
  else if (name == tr("Gray", "colormap"))
    return ColormapType::Gray;
  else if (name == tr("Magma", "colormap"))
    return ColormapType::Magma;
  else if (name == tr("Inferno", "colormap"))
    return ColormapType::Inferno;
  else if (name == tr("Plasma", "colormap"))
    return ColormapType::Plasma;
  else if (name == tr("Viridis", "colormap"))
    return ColormapType::Viridis;
  else if (name == tr("Cividis", "colormap"))
    return ColormapType::Cividis;
  else if (name == tr("Spectral", "colormap"))
    return ColormapType::Spectral;
  else if (name == tr("Coolwarm", "colormap"))
    return ColormapType::Coolwarm;
  else if (name == tr("Balance", "colormap"))
    return ColormapType::Balance;
  else if (name == tr("Blue-DarkRed", "colormap"))
    return ColormapType::BlueDkRed;
  else if (name == tr("Turbo", "colormap"))
    return ColormapType::Turbo;

  return ColormapType::Turbo;
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

// TODO - read colormap gradients (e.g., turbo)
Vector3ub rainbowGradient(const float value,
                          const ColormapType type = ColormapType::Turbo)
{
  auto color = tinycolormap::GetColor(value, type);
  Vector3ub ci(color.ri(), color.gi(), color.bi());

  return ci;
}

Vector3ub chargeGradient(const float value, const float clamp,
                         const ColormapType type = ColormapType::Coolwarm)
{
  // okay, typically color scales have blue at the bottom, red at the top.
  // so we need to invert, so blue is positive charge, red is negative charge.
  // we also need to scale the color to the range of the charge.
  float scaledValue = value / clamp; // from -1 to 1.0
  float scaledValue2 =
    1.0 - ((scaledValue + 1.0) / 2.0); // from 0 to 1.0 red to blue

  auto color = tinycolormap::GetColor(scaledValue2, type);
  Vector3ub ci(color.ri(), color.gi(), color.bi());

  return ci;
}

void ApplyColors::applyIndexColors()
{
  if (m_molecule == nullptr)
    return;

  // check on colormap
  ColormapType type = ColormapType::Turbo;
  QStringList colormaps;
  bool ok;
  colormaps << tr("Parula", "colormap") << tr("Magma", "colormap")
            << tr("Inferno", "colormap") << tr("Plasma", "colormap")
            << tr("Viridis", "colormap") << tr("Cividis", "colormap")
            << tr("Spectral", "colormap") << tr("Turbo", "colormap");

  QString item = QInputDialog::getItem(
    nullptr, tr("Select Colormap"), tr("Colormap:"), colormaps, 7, false, &ok);
  if (ok) {
    type = getColormapFromString(item);
  }

  bool isSelection = !m_molecule->isSelectionEmpty();

  // probably better to get color scales, but for now do it manually
  auto numAtoms = m_molecule->atomCount();
  for (Index i = 0; i < numAtoms; ++i) {
    // if there's a selection and this atom isn't selected, skip  it
    if (isSelection && !m_molecule->atomSelected(i))
      continue;

    float indexFraction = float(i) / float(numAtoms);

    m_molecule->atom(i).setColor(rainbowGradient(indexFraction, type));
  }

  m_molecule->emitChanged(QtGui::Molecule::Atoms);
}

void ApplyColors::applyChargeColors()
{
  if (m_molecule == nullptr)
    return;

  bool isSelection = !m_molecule->isSelectionEmpty();

  // get the list of possible models
  const auto identifiers =
    Calc::ChargeManager::instance().identifiersForMolecule(*m_molecule);
  if (identifiers.empty())
    return;

  // populate the dialog to choose the model and colormap
  ChargeColorDialog dialog;
  for (const auto &model : identifiers) {
    auto name = Calc::ChargeManager::instance().nameForModel(model);
    dialog.modelCombo->addItem(name.c_str(), model.c_str());
  }
  dialog.exec();
  if (dialog.result() != QDialog::Accepted)
    return;
  
  // get the model and colormap
  const auto model = dialog.modelCombo->currentData().toString().toStdString();
  const auto colormapName = dialog.colorMapCombo->currentText();
  const auto type = getColormapFromString(colormapName);

  // first off, get the range of partial charges
  auto numAtoms = m_molecule->atomCount();
  float minCharge = 0.0f;
  float maxCharge = 0.0f;
  auto charges =
    Calc::ChargeManager::instance().partialCharges(model, *m_molecule);
  for (Index i = 0; i < numAtoms; ++i) {
    float charge = charges(i, 0);
    minCharge = std::min(minCharge, charge);
    maxCharge = std::max(maxCharge, charge);
  }

  // now apply the colors
  float clamp = std::max(std::abs(minCharge), std::abs(maxCharge));
  for (Index i = 0; i < numAtoms; ++i) {
    // if there's a selection and this atom isn't selected, skip  it
    if (isSelection && !m_molecule->atomSelected(i))
      continue;

    m_molecule->atom(i).setColor(chargeGradient(charges(i, 0), clamp, type));
  }

  m_molecule->emitChanged(QtGui::Molecule::Atoms);
}

void ApplyColors::applyDistanceColors()
{
  if (m_molecule == nullptr && m_molecule->atomCount() == 0)
    return;

  bool isSelection = !m_molecule->isSelectionEmpty();

  // check on colormap
  ColormapType type = ColormapType::Turbo;
  QStringList colormaps;
  bool ok;
  colormaps << tr("Parula", "colormap") << tr("Magma", "colormap")
            << tr("Inferno", "colormap") << tr("Plasma", "colormap")
            << tr("Viridis", "colormap") << tr("Cividis", "colormap")
            << tr("Spectral", "colormap") << tr("Turbo", "colormap");

  QString item = QInputDialog::getItem(
    nullptr, tr("Select Colormap"), tr("Colormap:"), colormaps, 7, false, &ok);
  if (ok) {
    type = getColormapFromString(item);
  }

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

    m_molecule->atom(i).setColor(rainbowGradient(distanceFraction, type));
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

} // namespace Avogadro
