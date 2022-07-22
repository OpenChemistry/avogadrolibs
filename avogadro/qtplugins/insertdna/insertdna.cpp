/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "insertdna.h"
#include "ui_insertdnadialog.h"

#include <avogadro/qtgui/fileformatdialog.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/rwmolecule.h>

#include <avogadro/io/fileformat.h>
#include <avogadro/io/fileformatmanager.h>

#include <QtWidgets/QAction>
#include <QtWidgets/QButtonGroup>
#include <QtWidgets/QMessageBox>
#include <QtWidgets/QProgressDialog>

#include <nlohmann/json.hpp>

using json = nlohmann::json;
using Avogadro::Io::FileFormat;
using Avogadro::QtGui::FileFormatDialog;

namespace Avogadro::QtPlugins {

  class InsertDNADialog : public QDialog, public Ui::InsertDNADialog
    {
    public:
    InsertDNADialog(QWidget *parent=nullptr) : QDialog(parent) {
        setWindowFlags(Qt::Dialog | Qt::Tool);
        setupUi(this);
      }
    };


InsertDna::InsertDna(QObject* parent_)
  : Avogadro::QtGui::ExtensionPlugin(parent_), m_reader(nullptr),
    m_molecule(nullptr), m_dialog(nullptr)
{
  auto* action = new QAction(tr("DNA/RNA…"), this);
  connect(action, SIGNAL(triggered()), SLOT(showDialog()));

  m_actions.append(action);
}

InsertDna::~InsertDna()
{
  delete m_reader;
}

QList<QAction*> InsertDna::actions() const
{
  return m_actions;
}

QStringList InsertDna::menuPath(QAction*) const
{
  return QStringList() << tr("&Build") << tr("&Insert");
}

void InsertDna::setMolecule(QtGui::Molecule* mol)
{
  m_molecule = mol;
}

void InsertDna::showDialog()
{
  if (m_molecule == nullptr)
    return;

    // check to see if FASTA format is available from Open Babel
  QWidget* parentAsWidget = qobject_cast<QWidget*>(parent());
  const FileFormat::Operations ops = FileFormat::Read | FileFormat::String;
  const FileFormat* fmt = FileFormatDialog::findFileFormat(
    parentAsWidget, tr("Insert DNA/RNA…"), QString("file.fasta"), ops);

  if (fmt == nullptr) {
    return;
  } else {
    m_reader = fmt->newInstance();
  }

  // Prompt user for input:
  if (m_dialog == nullptr) {
    constructDialog();
  }
  m_dialog->show();
}


  void InsertDna::constructDialog()
  {
    if (m_dialog == nullptr) {
      m_dialog = new InsertDNADialog(qobject_cast<QWidget*>(parent()));

      auto* numStrands = new QButtonGroup(m_dialog);
      numStrands->addButton(m_dialog->singleStrandRadio, 0);
      numStrands->addButton(m_dialog->doubleStrandRadio, 1);
      numStrands->setExclusive(true);

      connect(m_dialog->insertButton, SIGNAL(clicked()),
              this, SLOT(performInsert()));

      connect(m_dialog->bpCombo, SIGNAL(currentIndexChanged(int)),
              this, SLOT(updateBPTurns(int)));

      connect(m_dialog->typeComboBox, SIGNAL(currentIndexChanged(int)),
              this, SLOT(changeNucleicType(int)));

      // Set the nucleic buttons to update the sequence
      foreach(const QToolButton *child, m_dialog->findChildren<QToolButton*>()) {
        connect(child, SIGNAL(clicked()), this, SLOT(updateText()));
      }
      connect(m_dialog, SIGNAL(destroyed()), this, SLOT(dialogDestroyed()));
    }
    m_dialog->sequenceText->setPlainText(QString());
  }

  void InsertDna::updateText()
  {
    auto *button = qobject_cast<QToolButton*>(sender());
    if (button) {
      QString sequenceText = m_dialog->sequenceText->toPlainText();
      sequenceText += button->text();

      m_dialog->sequenceText->setPlainText(sequenceText);
    }
  }

  void InsertDna::updateBPTurns(int type)
  {
    switch(type) {
    case 0: // A-DNA
      m_dialog->bpTurnsSpin->setValue(11.0);
      break;
    case 1: // B-DNA
      m_dialog->bpTurnsSpin->setValue(10.5);
      break;
    case 2: // Z-DNA
      m_dialog->bpTurnsSpin->setValue(12.0);
      break;
    default:
      // anything the user wants
      break;
    }
  }

  void InsertDna::changeNucleicType(int type)
  {
    if (type == 1) { // RNA
      m_dialog->bpCombo->setCurrentIndex(3); // other
      m_dialog->bpTurnsSpin->setValue(11.0); // standard RNA
      m_dialog->singleStrandRadio->setChecked(true);
      m_dialog->singleStrandRadio->setEnabled(false);
      m_dialog->doubleStrandRadio->setEnabled(false);
      m_dialog->toolButton_TU->setText(tr("U", "uracil"));
      m_dialog->toolButton_TU->setToolTip(tr("Uracil"));
      return;
    }
    // DNA
    m_dialog->singleStrandRadio->setEnabled(true);
    m_dialog->doubleStrandRadio->setEnabled(true);
    m_dialog->toolButton_TU->setText(tr("T", "thymine"));
    m_dialog->toolButton_TU->setToolTip(tr("Thymine"));
  }

  void InsertDna::performInsert()
  {
    if (m_dialog == nullptr || m_molecule == nullptr || m_reader == nullptr)
      return;

    QString sequence = m_dialog->sequenceText->toPlainText().toLower();
    bool dna = (m_dialog->typeComboBox->currentIndex() == 0);
    if (sequence.isEmpty())
      return; // also nothing to do
    // Add DNA/RNA tag for FASTA
    sequence = '>' + m_dialog->typeComboBox->currentText() + '\n'
      + sequence;

    // options
    // if DNA, check if the user wants single-strands
    json options;
    json arguments;

    // if it's DNA, allow single-stranded
    if (dna && m_dialog->singleStrandRadio->isChecked())
      arguments.push_back("-a1");

    // Add the number of turns
    QString turns = QString("-at %1").arg(m_dialog->bpTurnsSpin->value());
    arguments.push_back(turns.toStdString());

    options["arguments"] = arguments;

    QProgressDialog progDlg;
    progDlg.setModal(true);
    progDlg.setWindowTitle(tr("Insert Molecule…"));
    progDlg.setLabelText(tr("Generating 3D molecule…"));
    progDlg.setRange(0, 0);
    progDlg.setValue(0);
    progDlg.show();

    QtGui::Molecule newMol;
    m_reader->setOptions(options.dump());
    bool success = m_reader->readString(sequence.toStdString(), newMol);
    m_molecule->undoMolecule()->appendMolecule(newMol, "Insert Molecule");
    emit requestActiveTool("Manipulator");
  }

  void InsertDna::dialogDestroyed()
  {
    m_dialog = nullptr;
  }

} // namespace Avogadro
