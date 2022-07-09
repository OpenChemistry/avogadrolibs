/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "lammpsinput.h"

#include "lammpsinputdialog.h"

#include <avogadro/io/fileformat.h>
#include <avogadro/qtgui/fileformatdialog.h>
#include <avogadro/qtgui/molecule.h>

#include <QtCore/QDebug>

#include <QtWidgets/QAction>
#include <QtWidgets/QMessageBox>

namespace Avogadro {
namespace Core {
class Molecule;
}
namespace QtPlugins {

LammpsInput::LammpsInput(QObject* parent_)
  : ExtensionPlugin(parent_), m_action(new QAction(this)), m_molecule(nullptr),
    m_dialog(nullptr), m_outputFormat(nullptr)
{
  m_action->setEnabled(true);
  m_action->setText(tr("&LAMMPS…"));
  connect(m_action, SIGNAL(triggered()), SLOT(menuActivated()));
}

LammpsInput::~LammpsInput()
{
}

QList<QAction*> LammpsInput::actions() const
{
  QList<QAction*> actions_;
  actions_.append(m_action);
  return actions_;
}

QStringList LammpsInput::menuPath(QAction*) const
{
  QStringList path;
  path << tr("&Input");
  return path;
}

void LammpsInput::setMolecule(QtGui::Molecule* mol)
{
  if (m_dialog)
    m_dialog->setMolecule(mol);
  m_molecule = mol;
}

bool LammpsInput::readMolecule(QtGui::Molecule& mol)
{
  Io::FileFormat* reader = m_outputFormat->newInstance();
  bool success = reader->readFile(m_outputFileName.toStdString(), mol);
  if (!success) {
    QMessageBox::information(qobject_cast<QWidget*>(parent()), tr("Error"),
                             tr("Error reading output file '%1':\n%2")
                               .arg(m_outputFileName)
                               .arg(QString::fromStdString(reader->error())));
  }

  m_outputFormat = nullptr;
  m_outputFileName.clear();

  return success;
}

void LammpsInput::menuActivated()
{
  if (!m_dialog) {
    m_dialog = new LammpsInputDialog(qobject_cast<QWidget*>(parent()));
  }
  m_dialog->setMolecule(m_molecule);
  m_dialog->show();
}
}
}
