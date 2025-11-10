/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "insertpeptide.h"
#include "ui_insertpeptidedialog.h"

#include <avogadro/core/array.h>
#include <avogadro/core/residue.h>

#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/rwmolecule.h>
#include <avogadro/qtgui/utilities.h>

#include <QtCore/QDebug>
#include <QtCore/QSettings>
#include <QtCore/QStandardPaths>
#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QRegularExpression>

#include <QAction>

using Avogadro::Core::Array;
using Avogadro::QtGui::Molecule;

namespace Avogadro::QtPlugins {

const std::map<char, std::string> threeLetterCodes = {
  // map single letter codes to three letter codes
  // e.g. https://en.wikipedia.org/wiki/Amino_acid
  { 'A', "ALA" }, { 'R', "ARG" }, { 'N', "ASN" }, { 'D', "ASP" },
  { 'C', "CYS" }, { 'Q', "GLN" }, { 'E', "GLU" }, { 'G', "GLY" },
  { 'H', "HIS" }, { 'I', "ILE" }, { 'L', "LEU" }, { 'K', "LYS" },
  { 'M', "MET" }, { 'F', "PHE" }, { 'P', "PRO" }, { 'S', "SER" },
  { 'T', "THR" }, { 'W', "TRP" }, { 'Y', "TYR" }, { 'V', "VAL" },
  { 'O', "PYL" }, { 'U', "SEC" }
};

class InsertPeptideDialog : public QDialog, public Ui::InsertPeptideDialog
{
public:
  InsertPeptideDialog(QWidget* parent = 0) : QDialog(parent)
  {
    setWindowFlags(Qt::Dialog | Qt::Tool);
    setupUi(this);
  }
};

InsertPeptide::InsertPeptide(QObject* parent_)
  : Avogadro::QtGui::ExtensionPlugin(parent_), m_dialog(nullptr)
{
  auto* action = new QAction(tr("Peptide…"), this);
  action->setProperty("menu priority", 880);
  connect(action, SIGNAL(triggered()), SLOT(showDialog()));
  m_actions.append(action);
}

InsertPeptide::~InsertPeptide() {}

QList<QAction*> InsertPeptide::actions() const
{
  return m_actions;
}

QStringList InsertPeptide::menuPath(QAction* action) const
{
  return QStringList() << tr("&Build") << tr("&Insert");
}

void InsertPeptide::setMolecule(QtGui::Molecule* mol)
{
  m_molecule = mol;
}

void InsertPeptide::showDialog()
{
  if (m_molecule == nullptr)
    return;

  if (m_dialog == nullptr) {
    m_dialog = new InsertPeptideDialog(qobject_cast<QWidget*>(parent()));
  }

  QSettings settings;

  m_dialog->phiSpin->setValue(settings.value("peptide/phi", 180.0).toDouble());
  m_dialog->psiSpin->setValue(settings.value("peptide/psi", 180.0).toDouble());
  m_dialog->structureCombo->setCurrentIndex(
    settings.value("peptide/structure", 0).toInt());

  connect(m_dialog->insertButton, SIGNAL(clicked()), this,
          SLOT(performInsert()));

  // Set the amino buttons to update the sequence
  foreach (const QToolButton* child, m_dialog->findChildren<QToolButton*>()) {
    connect(child, SIGNAL(clicked()), this, SLOT(updateText()));
  }

  // connect the structure menu to set the phi / psi
  connect(m_dialog->structureCombo, SIGNAL(currentIndexChanged(int)), this,
          SLOT(setStructureType(int)));

  m_dialog->show();

  // deduce the directory for the fragments
  QString directory = "fragments/amino";
  QStringList dirs;
  QStringList stdPaths =
    QStandardPaths::standardLocations(QStandardPaths::AppLocalDataLocation);
  foreach (const QString& dirStr, stdPaths) {
    QString path = dirStr + "/data";
    dirs << path; // we'll check if these exist below
  }

  // add in paths relative to the binary (e.g. for development)
  dirs << QCoreApplication::applicationDirPath() + "/../" +
            QtGui::Utilities::dataDirectory() + "/avogadro2";

#ifdef Q_WS_X11
  dirs << QString(INSTALL_PREFIX) + "/share/avogadro2/";
#else
  // Mac and Windows use relative path from application location
  dirs << QCoreApplication::applicationDirPath() + "/../share/avogadro2";
#endif

  QDir dir;

  foreach (const QString& dirStr, dirs) {
    qDebug() << "Checking for " << directory << " data in" << dirStr;
    QDir testdir(dirStr + '/' + directory);
    if (testdir.exists() && testdir.isReadable()) {
      m_directory = testdir.absolutePath();
      break;
    }
  }
}

void InsertPeptide::setStructureType(int index)
{
  if (m_dialog == nullptr)
    return;

  switch (index) {
    case 0: // straight chain
      m_dialog->phiSpin->setValue(180.0);
      m_dialog->psiSpin->setValue(180.0);
      break;
    case 1: // alpha helix
      m_dialog->phiSpin->setValue(-60.0);
      m_dialog->psiSpin->setValue(-40.0);
      break;
    case 2: // beta sheet
      m_dialog->phiSpin->setValue(-135.0);
      m_dialog->psiSpin->setValue(135.0);
      break;
    case 3: // 3-10 helix
      m_dialog->phiSpin->setValue(-74.0);
      m_dialog->psiSpin->setValue(-4.0);
      break;
    case 4: // pi helix
      m_dialog->phiSpin->setValue(-57.0);
      m_dialog->psiSpin->setValue(-70.0);
      break;
    case 5: // other
    default:
      break;
  }

  QSettings settings;
  settings.setValue("peptide/phi", m_dialog->phiSpin->value());
  settings.setValue("peptide/psi", m_dialog->psiSpin->value());
  settings.setValue("peptide/structure", index);
}

void InsertPeptide::updateText()
{
  QToolButton* button = qobject_cast<QToolButton*>(sender());
  if (button) {
    QString sequenceText = m_dialog->sequenceText->toPlainText();
    sequenceText += '-' + button->text();
    // remove any final or initial dash
    if (sequenceText.endsWith('-'))
      sequenceText.chop(1);
    if (sequenceText.startsWith('-'))
      sequenceText.remove(0, 1);

    m_dialog->sequenceText->setPlainText(sequenceText);
  }
}

AminoAcid InsertPeptide::readAminoAcid(const QString& threeLetterCode)
{
  AminoAcid aa;

  // Construct the filename (e.g., "ALA.zmat")
  QString filename =
    QString(m_directory + "/%1.zmat").arg(threeLetterCode.toUpper());

  // Try opening the file
  QFile file(filename);
  if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
    qDebug() << "Failed to open amino acid file:" << filename;
    return aa;
  }

  QTextStream in(&file);

  while (!in.atEnd()) {
    QString line = in.readLine().trimmed();

    // Skip empty lines
    if (line.isEmpty())
      continue;

    // Parse the line
    QStringList parts =
      line.split(QRegularExpression("\\s+"), Qt::SkipEmptyParts);

    // Need at least: Element AtomName Distance Angle Dihedral RefAtom1 RefAtom2
    // RefAtom3
    if (parts.size() < 8)
      continue;

    QString element = parts[0];
    QString atomName = parts[1];
    double distance = parts[2].toDouble();
    double angle = parts[3].toDouble();
    double dihedral = parts[4].toDouble();
    int refAtom1 = parts[5].toInt();
    int refAtom2 = parts[6].toInt();
    int refAtom3 = parts[7].toInt();

    // Get atomic number from element symbol
    unsigned char atomicNum =
      Avogadro::Core::Elements::atomicNumberFromSymbol(element.toStdString());
    aa.atomicNumbers.push_back(atomicNum);
    aa.atomNames.push_back(atomName.toStdString());

    // Create internal coordinate
    Avogadro::Core::InternalCoordinate coord;

    // Convert 1-based indices to 0-based (but keep special cases)
    // 0 means no reference, keep as is
    coord.a = (refAtom1 > 0) ? refAtom1 - 1 : MaxIndex;
    coord.b = (refAtom2 > 0) ? refAtom2 - 1 : MaxIndex;
    coord.c = (refAtom3 > 0) ? refAtom3 - 1 : MaxIndex;

    coord.length = distance;
    // Keep in degrees as used in InternalCoordinate
    coord.angle = angle;
    coord.dihedral = dihedral;

    aa.internalCoords.push_back(coord);
  }

  file.close();

#ifndef NDEBUG
  qDebug() << "Read" << aa.atomicNumbers.size() << "atoms for"
           << threeLetterCode;
#endif

  return aa;
}

void InsertPeptide::performInsert()
{
  if (m_molecule == nullptr || m_dialog == nullptr)
    return;

  // get the sequence
  QString sequenceText = m_dialog->sequenceText->toPlainText();
  if (sequenceText.isEmpty())
    return;

  // figure out if the sequence has three-letter codes
  // separated by dashes
  QStringList sequenceList;
  sequenceList = sequenceText.split('-');

  // Check if we have single letter codes (no dashes, short strings)
  if (sequenceList.size() == 1 && sequenceList[0].length() > 3) {
    // Might be single letter codes like "ACDEFG"
    QString singleLetters = sequenceList[0];
    sequenceList.clear();
    for (int i = 0; i < singleLetters.length(); i++) {
      char letter = singleLetters[i].toUpper().toLatin1();
      if (threeLetterCodes.find(letter) != threeLetterCodes.end()) {
        sequenceList.append(
          QString::fromStdString(threeLetterCodes.at(letter)));
      }
    }
  }

  QString chain = m_dialog->chainNumberCombo->currentText();
  if (chain.isEmpty())
    chain = 'A';

  double phi = m_dialog->phiSpin->value();
  double psi = m_dialog->psiSpin->value();

  // get the N and C terminus
  auto nTerm = m_dialog->nGroupCombo->currentIndex();
  auto cTerm = m_dialog->cGroupCombo->currentIndex();

  char stereo = m_dialog->lStereoButton->isChecked() ? 'L' : 'D';

  // read the file into the new fragment
  Avogadro::QtGui::Molecule newMol(m_molecule->parent());

  // keep a map of the amino acids (i.e., only read once)
  std::map<std::string, AminoAcid> aaMap;

  // iterate through sequenceList to read the amino acids
  Index currentResidueNumber = 0;
  Array<Core::InternalCoordinate> internalCoords;
  // Track atom indices across residues
  Index totalAtomCount = 0;
  Index previousN = MaxIndex;
  Index previousCA = MaxIndex;
  Index previousC = MaxIndex;
  Index previousO = MaxIndex;
  Index currentN = MaxIndex;
  Index currentCA = MaxIndex;
  Index currentC = MaxIndex;
  Index currentO = MaxIndex;

  for (int i = 0; i < sequenceList.size(); i++) {
    QString aaString = sequenceList[i];
    std::string aaStdString = aaString.toUpper().toStdString();

    // Read amino acid if not already cached
    if (aaMap.find(aaStdString) == aaMap.end()) {
      aaMap[aaStdString] = readAminoAcid(aaString);
    }

    AminoAcid amino = aaMap[aaStdString];

    if (amino.atomicNumbers.empty()) {
      qDebug() << "Failed to read amino acid:" << aaString;
      continue;
    }

    // Create residue
    auto residue = newMol.addResidue(aaStdString, ++currentResidueNumber,
                                     chain.toLatin1()[0]);

    // Add atoms from this amino acid
    for (size_t j = 0; j < amino.atomNames.size(); j++) {
      std::string atomName = amino.atomNames[j];

      // Skip terminal atoms for middle residues
      bool isLastResidue = (i == sequenceList.size() - 1);
      bool isFirstResidue = (i == 0);

      // Skip OXT/HXT for non-terminal residues
      if (!isLastResidue && (atomName == "OXT" || atomName == "HXT"))
        continue;

      // Add atom to molecule
      auto atom = newMol.addAtom(amino.atomicNumbers[j]);
      residue.addResidueAtom(atomName, atom);

      // Handle internal coordinates
      Core::InternalCoordinate coord = amino.internalCoords[j];

      // TODO : Handle stereochemistry for D- amino acids

      // For residues after the first, we need to adjust references
      if (i > 0) {
        // Atoms need to reference previous residue atoms for the peptide bond

        if (atomName == "N") {
          // N connects to previous C
          coord.a = previousC;
          coord.b = previousCA;
          coord.c = previousN;
          coord.length = 1.329; // typical peptide bond length
          coord.angle = 116.2;  // typical C-N-CA angle
          coord.dihedral = psi;
        } else if (atomName == "CA") {
          // CA connects to N (just added)
          coord.a = currentN; // N we just added
          coord.b = previousC;
          coord.c = previousCA;
          coord.angle = 121.7;    // typical N-CA-C angle
          coord.dihedral = 180.0; // omega
        } else if (atomName == "C") {
          coord.a = currentCA; // CA we just added
          coord.b = currentN;  // N we just added
          coord.c = previousC;
          coord.dihedral = phi;
        } else {
          // Other atoms: adjust their reference indices
          // Add offset for all atoms from previous residues
          if (coord.a != MaxIndex)
            coord.a += totalAtomCount;
          if (coord.b != MaxIndex)
            coord.b += totalAtomCount;
          if (coord.c != MaxIndex)
            coord.c += totalAtomCount;
        }
      }

      internalCoords.push_back(coord);

      /*
#ifndef NDEBUG
      qDebug() << " added " << atomName << " " << atom.index()
      << " " << coord.a << " " << coord.b << " " << coord.c
      << " " << coord.length << " " << coord.angle << " " << coord.dihedral;
#endif
      */

      // Track key atoms for next residue
      if (atomName == "N")
        currentN = newMol.atomCount() - 1;
      else if (atomName == "CA")
        currentCA = newMol.atomCount() - 1;
      else if (atomName == "C")
        currentC = newMol.atomCount() - 1;
      else if (atomName == "O")
        currentO = newMol.atomCount() - 1;
    }
    totalAtomCount = newMol.atomCount();

    residue.resolveResidueBonds(newMol);
    if (i > 0)
      // Add peptide bond
      newMol.addBond(previousC, currentN);

    // adjust the dihedral of the previous oxygen
    if (i > 0)
      internalCoords[previousO].dihedral = 180.0 + psi;

    previousN = currentN;
    previousCA = currentCA;
    previousC = currentC;
    previousO = currentO;
  }

  // Convert internal coordinates to Cartesian
  Array<Vector3> positions = internalToCartesian(newMol, internalCoords);

  // Set atom positions
  for (size_t i = 0; i < positions.size(); i++) {
    newMol.setAtomPosition3d(i, positions[i]);
  }

  m_molecule->undoMolecule()->appendMolecule(newMol, tr("Insert Peptide"));
  emit requestActiveTool("Manipulator");
}

} // namespace Avogadro::QtPlugins
