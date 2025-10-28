/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "insertpeptide.h"
#include "ui_insertpeptidedialog.h"

#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/rwmolecule.h>

#include <QtCore/QDebug>

#include <QAction>

using Avogadro::QtGui::Molecule;

namespace Avogadro::QtPlugins {

constexpr std::map<char, std::string> threeLetterCodes = {
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
  if (!sequence.contains('-')) {
    // go through letter by letter to get the three letter code
    foreach (const QChar& c, sequence) {
      sequenceList.append(threeLetterCodes[c.toLatin1()]);
    }
  } else
    sequenceList = sequence.split('-');

  QString chain = m_dialog->chainNumberCombo->currentText();
  if (chain.isEmpty())
    chain = 'A';

  double phi = m_dialog->phiSpin->value();
  double psi = m_dialog->psiSpin->value();

  // get the N and C terminus
  auto nTerm = m_dialog->nTermCombo->currentIndex();
  auto cTerm = m_dialog->cTermCombo->currentIndex();

  char stereo = m_dialog->lStereoButton->isChecked() ? 'L' : 'D';

  // read the file into the new fragment
  Avogadro::QtGui::Molecule newMol(m_molecule->parent());

  // m_molecule->undoMolecule()->appendMolecule(newMol, tr("Insert Peptide"));
  //  emit requestActiveTool("Manipulator");
}

} // namespace Avogadro::QtPlugins
