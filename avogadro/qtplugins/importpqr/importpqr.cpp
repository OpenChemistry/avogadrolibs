/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "importpqr.h"

#include "pqrwidget.h"

#include <avogadro/io/fileformat.h>
#include <avogadro/qtgui/fileformatdialog.h>
#include <avogadro/qtgui/molecule.h>

#include <QtCore/QDebug>

#include <QtWidgets/QAction>
#include <QtWidgets/QMessageBox>

namespace Avogadro::QtPlugins {

ImportPQR::ImportPQR(QObject* parent_)
  : ExtensionPlugin(parent_), m_action(new QAction(this)), m_molecule(nullptr),
    m_dialog(nullptr), m_outputFormat(nullptr)
{
  m_action->setEnabled(true);
  m_action->setText(tr("&Search PQR…"));
  connect(m_action, SIGNAL(triggered()), SLOT(menuActivated()));
}

ImportPQR::~ImportPQR()
{
  delete (m_outputFormat);
  delete (m_molecule);
  delete (m_action);
}

QList<QAction*> ImportPQR::actions() const
{
  QList<QAction*> actions_;
  actions_.append(m_action);
  return actions_;
}

QStringList ImportPQR::menuPath(QAction*) const
{
  QStringList path;
  path << tr("&File") << tr("&Import");
  return path;
}

void ImportPQR::setMolecule(QtGui::Molecule* mol)
{
  m_molecule = mol;
}

bool ImportPQR::readMolecule(QtGui::Molecule& mol)
{
  bool readOK = Io::FileFormatManager::instance().readString(
    mol, m_moleculeData.data(), "mol2");

  if (readOK) // worked, so set the filename
    mol.setData("name", m_moleculeName.toStdString());

  return readOK;
}

void ImportPQR::menuActivated()
{
  if (!m_dialog)
    m_dialog = new PQRWidget(qobject_cast<QWidget*>(this), this);

  m_dialog->show();
}

// called by widget
void ImportPQR::setMoleculeData(QByteArray& molData, QString name)
{
  m_moleculeName = name;
  m_moleculeData = molData;

  m_dialog->hide();
  emit moleculeReady(1);
}
} // namespace Avogadro
