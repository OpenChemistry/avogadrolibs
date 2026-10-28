/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "applycolors.h"
#include "ui_chargedialog.h"

#include <avogadro/calc/chargemanager.h>
#include <avogadro/core/residue.h>
#include <avogadro/core/residuecolors.h>
#include <avogadro/core/vector.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/rwmolecule.h>

#include <QAction>
#include <QColorDialog>
#include <QInputDialog>
#include <QStringList>

#include <QDebug>

#include <array>

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

  action = new QAction(tr("By Atomic Index…"), this);
  action->setData(atomColors);
  connect(action, SIGNAL(triggered()), SLOT(applyIndexColors()));
  m_actions.append(action);

  action = new QAction(tr("By Distance…"), this);
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

namespace {

// Lookup table mapping normalized lowercase keys and display names to
// ColormapType.
struct ColormapEntry
{
  const char* key;
  const char* displayName;
  ColormapType type;
};

// All 21 colormaps supported by tinycolormap with aliases.
constexpr std::array<ColormapEntry, 21> s_colormaps = {
  { { "parula", "Parula", ColormapType::Parula },
    { "heat", "Heat", ColormapType::Heat },
    { "jet", "Jet", ColormapType::Jet },
    { "turbo", "Turbo", ColormapType::Turbo },
    { "hot", "Hot", ColormapType::Hot },
    { "gray", "Gray", ColormapType::Gray },
    { "grey", "Gray", ColormapType::Gray },
    { "magma", "Magma", ColormapType::Magma },
    { "inferno", "Inferno", ColormapType::Inferno },
    { "plasma", "Plasma", ColormapType::Plasma },
    { "viridis", "Viridis", ColormapType::Viridis },
    { "cividis", "Cividis", ColormapType::Cividis },
    { "github", "Github", ColormapType::Github },
    { "cubehelix", "Cubehelix", ColormapType::Cubehelix },
    { "spectral", "Spectral", ColormapType::Spectral },
    { "coolwarm", "Coolwarm", ColormapType::Coolwarm },
    { "vlag", "Vlag", ColormapType::Vlag },
    { "vik", "Vik", ColormapType::Vik },
    { "balance", "Balance", ColormapType::Balance },
    { "bluedarkred", "Blue-DarkRed", ColormapType::BlueDkRed },
    { "bluedkred", "Blue-DarkRed", ColormapType::BlueDkRed } }
};

// Normalize key by stripping non-alphanumeric characters and converting to
// lowercase.
QString normalizeKey(const QString& str)
{
  QString result;
  result.reserve(str.size());
  for (QChar ch : str) {
    if (ch.isLetterOrNumber())
      result.append(ch.toLower());
  }
  return result;
}

// Compute Levenshtein distance between two strings with early exit for large
// differences.
int levenshteinDistance(const QString& s1, const QString& s2)
{
  const auto m = s1.size();
  const auto n = s2.size();
  if (std::abs(m - n) >= 3)
    return 3;

  std::vector<int> prev(n + 1);
  std::vector<int> curr(n + 1);

  for (qsizetype j = 0; j <= n; ++j)
    prev[j] = static_cast<int>(j);

  for (qsizetype i = 1; i <= m; ++i) {
    curr[0] = static_cast<int>(i);
    for (qsizetype k = 1; k <= n; ++k) {
      int cost = (s1[i - 1] == s2[k - 1]) ? 0 : 1;
      curr[k] = std::min({ curr[k - 1] + 1, prev[k] + 1, prev[k - 1] + cost });
    }
    prev = curr;
  }

  return prev[n];
}

} // namespace

// Match a colormap name against known entries, with fuzzy matching for typo
// suggestions.
bool ApplyColors::colormapFromString(const QString& name, ColormapType& type,
                                     QString* suggestion)
{
  const QString key = normalizeKey(name);

  // Check normalized keys.
  for (const auto& entry : s_colormaps) {
    if (key == entry.key) {
      type = entry.type;
      return true;
    }
  }

  // Check translated display names.
  for (const auto& entry : s_colormaps) {
    if (name == tr(entry.displayName, "colormap")) {
      type = entry.type;
      return true;
    }
  }

  // Find nearest match for typo suggestion.
  if (suggestion != nullptr) {
    int bestDistance = 3;
    for (const auto& entry : s_colormaps) {
      int d = levenshteinDistance(key, QString::fromLatin1(entry.key));
      if (d < bestDistance) {
        bestDistance = d;
        *suggestion = entry.displayName;
      }
    }
  }

  return false;
}

ColormapType ApplyColors::getColormapFromString(const QString& name) const
{
  ColormapType type = ColormapType::Turbo;
  if (colormapFromString(name, type))
    return type;
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

// GUI slot: prompts user to select a colormap, then delegates to headless
// implementation.
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

  applyIndexColors(type);
}

// Headless implementation: applies index colormap gradient to atoms.
void ApplyColors::applyIndexColors(ColormapType type)
{
  if (m_molecule == nullptr)
    return;

  bool isSelection = !m_molecule->isSelectionEmpty();

  auto* rwmol = m_molecule->undoMolecule();
  rwmol->beginMergeMode(tr("Apply Index Colors"));
  auto numAtoms = rwmol->atomCount();
  for (Index i = 0; i < numAtoms; ++i) {
    // if there's a selection and this atom isn't selected, skip it
    if (isSelection && !m_molecule->atomSelected(i))
      continue;

    float indexFraction =
      (numAtoms > 1) ? float(i) / (float(numAtoms) - 1) : 0.0f;

    rwmol->setColor(i, rainbowGradient(indexFraction, type));
  }
  rwmol->endMergeMode();
  // colors are not structural; emitting Atoms would discard orbitals,
  // vibrations, etc.
  m_molecule->emitChanged(QtGui::Molecule::Properties);
}

// GUI slot: prompts user to select a charge model and colormap, then delegates.
void ApplyColors::applyChargeColors()
{
  if (m_molecule == nullptr)
    return;

  // get the list of possible models
  const auto identifiers =
    Calc::ChargeManager::instance().identifiersForMolecule(*m_molecule);
  if (identifiers.empty())
    return;

  // populate the dialog to choose the model and colormap
  ChargeColorDialog dialog;
  for (const auto& model : identifiers) {
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

  QString error;
  applyChargeColors(model, type, error);
}

// Headless implementation: computes partial charges and applies clamped
// colormap gradient.
bool ApplyColors::applyChargeColors(const std::string& model, ColormapType type,
                                    QString& error)
{
  if (m_molecule == nullptr) {
    error = tr("No molecule available.");
    return false;
  }

  auto numAtoms = m_molecule->atomCount();
  if (numAtoms == 0) {
    error = tr("Molecule has no atoms.");
    return false;
  }

  // first off, get the range of partial charges
  MatrixX charges =
    Calc::ChargeManager::instance().partialCharges(model, *m_molecule);
  // check if the model string is already a partial charge type
  if (m_molecule->partialChargeTypes().find(model) !=
      m_molecule->partialChargeTypes().end()) {
    charges = m_molecule->partialCharges(model);
  }

  if (charges.rows() < static_cast<Eigen::Index>(numAtoms)) {
    error = tr("Failed to compute partial charges for model \"%1\".")
              .arg(QString::fromStdString(model));
    return false;
  }

  float minCharge = 0.0f;
  float maxCharge = 0.0f;
  for (Index i = 0; i < numAtoms; ++i) {
    float charge = charges(i, 0);
    minCharge = std::min(minCharge, charge);
    maxCharge = std::max(maxCharge, charge);
  }

  // now apply the colors
  float clamp = std::max(std::abs(minCharge), std::abs(maxCharge));
  if (clamp == 0.0f)
    clamp = 1.0f;

  bool isSelection = !m_molecule->isSelectionEmpty();

  auto* rwmol = m_molecule->undoMolecule();
  rwmol->beginMergeMode(tr("Apply Charge Colors"));
  for (Index i = 0; i < numAtoms; ++i) {
    // if there's a selection and this atom isn't selected, skip it
    if (isSelection && !m_molecule->atomSelected(i))
      continue;

    rwmol->setColor(i, chargeGradient(charges(i, 0), clamp, type));
  }
  rwmol->endMergeMode();
  m_molecule->emitChanged(QtGui::Molecule::Properties);
  return true;
}

// GUI slot: prompts user to select a colormap, then delegates to headless
// implementation.
void ApplyColors::applyDistanceColors()
{
  if (m_molecule == nullptr || m_molecule->atomCount() == 0)
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

  applyDistanceColors(type);
}

// Headless implementation: applies distance colormap gradient relative to the
// first atom.
void ApplyColors::applyDistanceColors(ColormapType type)
{
  if (m_molecule == nullptr || m_molecule->atomCount() == 0)
    return;

  if (m_molecule->atomPositions3d().size() != m_molecule->atomCount())
    return;

  bool isSelection = !m_molecule->isSelectionEmpty();

  Vector3 firstPos = m_molecule->atomPosition3d(0);
  Real size = 2.0 * m_molecule->radius();

  auto* rwmol = m_molecule->undoMolecule();
  rwmol->beginMergeMode(tr("Apply Distance Colors"));
  auto numAtoms = rwmol->atomCount();
  for (Index i = 0; i < numAtoms; ++i) {
    // if there's a selection and this atom isn't selected, skip it
    if (isSelection && !m_molecule->atomSelected(i))
      continue;

    Vector3 currPos = m_molecule->atomPosition3d(i);
    Vector3 diff = currPos - firstPos;
    Real distance = diff.norm();
    Real distanceFraction = (size > 0.0) ? distance / size : 0.0;

    rwmol->setColor(i, rainbowGradient(distanceFraction, type));
  }
  rwmol->endMergeMode();
  m_molecule->emitChanged(QtGui::Molecule::Properties);
}

void ApplyColors::resetColors()
{
  if (m_molecule == nullptr)
    return;

  bool isSelection = !m_molecule->isSelectionEmpty();

  auto* rwmol = m_molecule->undoMolecule();
  rwmol->beginMergeMode(tr("Reset Atom Colors"));
  for (Index i = 0; i < rwmol->atomCount(); ++i) {
    // if there's a selection and this atom isn't selected, skip it
    if (isSelection && !m_molecule->atomSelected(i))
      continue;

    Vector3ub color(Core::Elements::color(m_molecule->atomicNumber(i)));
    rwmol->setColor(i, color);
  }
  rwmol->endMergeMode();
  m_molecule->emitChanged(QtGui::Molecule::Properties);
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

  auto* rwmol = m_molecule->undoMolecule();
  rwmol->beginMergeMode(tr("Apply Custom Color"));
  for (Index i = 0; i < rwmol->atomCount(); ++i) {
    // if there's a selection and this atom isn't selected, skip it
    if (isSelection && !m_molecule->atomSelected(i))
      continue;

    rwmol->setColor(i, color);
  }
  rwmol->endMergeMode();
  m_molecule->emitChanged(QtGui::Molecule::Properties);
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

  auto* rwmol = m_molecule->undoMolecule();
  rwmol->beginMergeMode(tr("Apply Custom Residue Color"));
  for (Index i = 0; i < m_molecule->residueCount(); ++i) {
    // if there's a selection and this residue isn't selected, skip it
    auto& residue = m_molecule->residue(i);
    if (isSelection) {
      auto caAtom = residue.atomByName("CA");
      if (!caAtom.isValid() || !m_molecule->atomSelected(caAtom.index()))
        continue;
    }

    rwmol->setResidueColor(i, color);
  }
  rwmol->endMergeMode();
  m_molecule->emitChanged(QtGui::Molecule::Properties);
}

void ApplyColors::resetColorsResidue()
{
  if (m_molecule == nullptr)
    return;

  bool isSelection = !m_molecule->isSelectionEmpty();

  auto* rwmol = m_molecule->undoMolecule();
  rwmol->beginMergeMode(tr("Reset Residue Colors"));
  for (Index i = 0; i < m_molecule->residueCount(); ++i) {
    // if there's a selection and this residue isn't selected, skip it
    auto& residue = m_molecule->residue(i);
    if (isSelection) {
      auto caAtom = residue.atomByName("CA");
      if (!caAtom.isValid() || !m_molecule->atomSelected(caAtom.index()))
        continue;
    }

    int offset = 0;
    char chainId = residue.chainId();
    if (chainId >= 'A' && chainId <= 'Z')
      offset = chainId - 'A';
    else if (chainId >= 'a' && chainId <= 'z')
      offset = chainId - 'a';
    else if (chainId >= '0' && chainId <= '9')
      offset = chainId - '0' + 15; // starts at 'P'

    Vector3ub color(Core::chain_color[offset]);
    rwmol->setResidueColor(i, color);
  }
  rwmol->endMergeMode();
  m_molecule->emitChanged(QtGui::Molecule::Properties);
}

void ApplyColors::applySecondaryStructureColors()
{
  if (m_molecule == nullptr)
    return;

  bool isSelection = !m_molecule->isSelectionEmpty();

  auto* rwmol = m_molecule->undoMolecule();
  rwmol->beginMergeMode(tr("Apply Secondary Structure Colors"));
  for (Index i = 0; i < m_molecule->residueCount(); ++i) {
    // if there's a selection and this residue isn't selected, skip it
    auto& residue = m_molecule->residue(i);
    if (isSelection) {
      auto caAtom = residue.atomByName("CA");
      if (!caAtom.isValid() || !m_molecule->atomSelected(caAtom.index()))
        continue;
    }

    Core::Residue::SecondaryStructure type = residue.secondaryStructure();
    if (type < 0 || type > 7) {
      type = Core::Residue::SecondaryStructure::coil;
    }
    Vector3ub color(Core::secondary_color[type]);
    rwmol->setResidueColor(i, color);
  } // end loop
  rwmol->endMergeMode();
  m_molecule->emitChanged(QtGui::Molecule::Properties);
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

  auto* rwmol = m_molecule->undoMolecule();
  rwmol->beginMergeMode(tr("Apply Amino Acid Colors"));
  for (Index i = 0; i < m_molecule->residueCount(); ++i) {
    // if there's a selection and this residue isn't selected, skip it
    auto& residue = m_molecule->residue(i);
    if (isSelection) {
      auto caAtom = residue.atomByName("CA");
      if (!caAtom.isValid() || !m_molecule->atomSelected(caAtom.index()))
        continue;
    }

    int offset = residueNameToOffset(residue.residueName());

    Vector3ub color(Core::amino_color[offset]);
    rwmol->setResidueColor(i, color);
  }
  rwmol->endMergeMode();
  m_molecule->emitChanged(QtGui::Molecule::Properties);
}

void ApplyColors::applyShapelyColors()
{
  if (m_molecule == nullptr)
    return;

  bool isSelection = !m_molecule->isSelectionEmpty();

  auto* rwmol = m_molecule->undoMolecule();
  rwmol->beginMergeMode(tr("Apply Shapely Colors"));
  for (Index i = 0; i < m_molecule->residueCount(); ++i) {
    // if there's a selection and this residue isn't selected, skip it
    auto& residue = m_molecule->residue(i);
    if (isSelection) {
      auto caAtom = residue.atomByName("CA");
      if (!caAtom.isValid() || !m_molecule->atomSelected(caAtom.index()))
        continue;
    }

    int offset = residueNameToOffset(residue.residueName());

    Vector3ub color(Core::shapely_color[offset]);
    rwmol->setResidueColor(i, color);
  }
  rwmol->endMergeMode();
  m_molecule->emitChanged(QtGui::Molecule::Properties);
}

void ApplyColors::registerCommands()
{
  emit registerCommand("colorAtomsCustom",
                       tr("Apply a custom color to atoms."));
  emit registerCommand(
    "resetAtomColors",
    tr("Reset atom colors to their default element colors."));
  emit registerCommand("colorResiduesCustom",
                       tr("Apply a custom color to residues."));
  emit registerCommand("colorResiduesByAminoAcid",
                       tr("Color residues by their amino acid type."));
  emit registerCommand("colorResiduesShapely",
                       tr("Color residues using the Shapely color scheme."));
  emit registerCommand("colorResiduesBySecondaryStructure",
                       tr("Color residues by secondary structure."));
  emit registerCommand("resetResidueColors",
                       tr("Reset residue colors to default chain colors."));

  emit registerCommand(
    "colorAtomsByIndex",
    tr("Color atoms along a colormap gradient by atomic index. Options: "
       "optional \"colormap\" (e.g. \"Turbo\", \"Viridis\", \"Magma\")."));
  emit registerCommand(
    "colorAtomsByDistance",
    tr("Color atoms along a colormap gradient by distance from the first atom. "
       "Options: optional \"colormap\" (e.g. \"Turbo\", \"Viridis\")."));
  emit registerCommand(
    "colorAtomsByCharge",
    tr("Color atoms along a colormap gradient by partial charge. Options: "
       "optional \"colormap\" (e.g. \"Coolwarm\"), optional \"model\" (e.g. "
       "\"MMFF94\", \"Gasteiger\")."));
}

bool ApplyColors::handleCommand(const QString& command,
                                [[maybe_unused]] const QVariantMap& options)
{
  static const QStringList knownCommands = {
    "colorAtomsCustom",     "resetAtomColors",
    "colorResiduesCustom",  "colorResiduesByAminoAcid",
    "colorResiduesShapely", "colorResiduesBySecondaryStructure",
    "resetResidueColors",   "colorAtomsByIndex",
    "colorAtomsByDistance", "colorAtomsByCharge"
  };

  if (!knownCommands.contains(command))
    return false; // not one of our commands

  if (m_molecule == nullptr) {
    emit commandFailed(tr("No molecule"));
    return true;
  }

  if (command == "colorAtomsCustom") {
    if (!options.contains("color")) {
      emit commandFailed(tr("colorAtomsCustom requires a \"color\" option "
                            "(a color name or \"#rrggbb\" value)."));
      return true;
    }
    const QColor color(options["color"].toString());
    if (!color.isValid()) {
      emit commandFailed(
        tr("Unknown color \"%1\".").arg(options["color"].toString()));
      return true;
    }
    applyCustomColor(color);
    emit commandFinished();
    return true;
  }

  if (command == "resetAtomColors") {
    resetColors();
    emit commandFinished();
    return true;
  }

  if (command == "colorResiduesCustom") {
    if (!options.contains("color")) {
      emit commandFailed(tr("colorResiduesCustom requires a \"color\" option "
                            "(a color name or \"#rrggbb\" value)."));
      return true;
    }
    const QColor color(options["color"].toString());
    if (!color.isValid()) {
      emit commandFailed(
        tr("Unknown color \"%1\".").arg(options["color"].toString()));
      return true;
    }
    applyCustomColorResidue(color);
    emit commandFinished();
    return true;
  }

  if (command == "colorResiduesByAminoAcid") {
    applyAminoColors();
    emit commandFinished();
    return true;
  }

  if (command == "colorResiduesShapely") {
    applyShapelyColors();
    emit commandFinished();
    return true;
  }

  if (command == "colorResiduesBySecondaryStructure") {
    applySecondaryStructureColors();
    emit commandFinished();
    return true;
  }

  if (command == "resetResidueColors") {
    resetColorsResidue();
    emit commandFinished();
    return true;
  }

  // Color atoms along a colormap gradient by index.
  if (command == "colorAtomsByIndex" || command == "applyIndexColors") {
    if (m_molecule->atomCount() == 0) {
      emit commandFailed(tr("Molecule has no atoms."));
      return true;
    }

    ColormapType type = ColormapType::Turbo;
    if (options.contains("colormap")) {
      const QString colormapName = options["colormap"].toString();
      QString suggestion;
      if (!colormapFromString(colormapName, type, &suggestion)) {
        if (!suggestion.isEmpty()) {
          emit commandFailed(tr(R"(Unknown colormap "%1". Did you mean "%2"?)")
                               .arg(colormapName, suggestion));
        } else {
          emit commandFailed(tr(R"(Unknown colormap "%1".)").arg(colormapName));
        }
        return true;
      }
    }

    applyIndexColors(type);
    emit commandFinished();
    return true;
  }

  // Color atoms along a colormap gradient by distance from the first atom.
  if (command == "colorAtomsByDistance" || command == "applyDistanceColors") {
    if (m_molecule->atomCount() == 0) {
      emit commandFailed(tr("Molecule has no atoms."));
      return true;
    }

    if (m_molecule->atomPositions3d().size() != m_molecule->atomCount()) {
      emit commandFailed(tr("Molecule does not have 3D coordinates."));
      return true;
    }

    ColormapType type = ColormapType::Turbo;
    if (options.contains("colormap")) {
      const QString colormapName = options["colormap"].toString();
      QString suggestion;
      if (!colormapFromString(colormapName, type, &suggestion)) {
        if (!suggestion.isEmpty()) {
          emit commandFailed(tr(R"(Unknown colormap "%1". Did you mean "%2"?)")
                               .arg(colormapName, suggestion));
        } else {
          emit commandFailed(tr(R"(Unknown colormap "%1".)").arg(colormapName));
        }
        return true;
      }
    }

    applyDistanceColors(type);
    emit commandFinished();
    return true;
  }

  // Color atoms along a colormap gradient by partial charge.
  if (command == "colorAtomsByCharge" || command == "applyChargeColors") {
    if (m_molecule->atomCount() == 0) {
      emit commandFailed(tr("Molecule has no atoms."));
      return true;
    }

    ColormapType type = ColormapType::Coolwarm;
    if (options.contains("colormap")) {
      const QString colormapName = options["colormap"].toString();
      QString suggestion;
      if (!colormapFromString(colormapName, type, &suggestion)) {
        if (!suggestion.isEmpty()) {
          emit commandFailed(tr(R"(Unknown colormap "%1". Did you mean "%2"?)")
                               .arg(colormapName, suggestion));
        } else {
          emit commandFailed(tr(R"(Unknown colormap "%1".)").arg(colormapName));
        }
        return true;
      }
    }

    std::string model;
    const auto identifiers =
      Calc::ChargeManager::instance().identifiersForMolecule(*m_molecule);
    const auto existingTypes = m_molecule->partialChargeTypes();

    if (options.contains("model")) {
      const QString requested = options["model"].toString();
      const std::string requestedStd = requested.toStdString();
      if (existingTypes.find(requestedStd) != existingTypes.end()) {
        model = requestedStd;
      } else {
        for (const auto& id : identifiers) {
          const auto name = Calc::ChargeManager::instance().nameForModel(id);
          if (id == requestedStd ||
              QString::fromStdString(name).compare(requested,
                                                   Qt::CaseInsensitive) == 0 ||
              QString::fromStdString(id).compare(requested,
                                                 Qt::CaseInsensitive) == 0) {
            model = id;
            break;
          }
        }
      }
      if (model.empty()) {
        emit commandFailed(
          tr("Unknown or unavailable charge model \"%1\".").arg(requested));
        return true;
      }
    } else {
      if (!existingTypes.empty()) {
        model = *existingTypes.begin();
      } else if (!identifiers.empty()) {
        model = *identifiers.begin();
      } else {
        emit commandFailed(tr("No charge models available for this molecule."));
        return true;
      }
    }

    QString error;
    if (!applyChargeColors(model, type, error)) {
      emit commandFailed(error);
      return true;
    }

    emit commandFinished();
    return true;
  }

  return false;
}

} // namespace Avogadro::QtPlugins
