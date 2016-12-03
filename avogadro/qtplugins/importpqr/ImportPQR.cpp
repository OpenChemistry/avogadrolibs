/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2012 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "ImportPQR.h"

#include "PQRWidget.h"

#include <avogadro/qtgui/fileformatdialog.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/io/fileformat.h>

#include <QtCore/QDebug>
#include <QtWidgets/QAction>

#include <QtWidgets/QMessageBox>

namespace Avogadro {
namespace QtPlugins {


ImportPQR::ImportPQR(QObject *parent_) :
  ExtensionPlugin(parent_),
  m_action(new QAction(this)),
  m_molecule(NULL),
  m_dialog(NULL),
  m_outputFormat(NULL)
{
  m_action->setEnabled(true);
  m_action->setText(tr("&Import From PQR"));
  connect(m_action, SIGNAL(triggered()), SLOT(menuActivated()));
}

ImportPQR::~ImportPQR()
{
}

QList<QAction *> ImportPQR::actions() const
{
  QList<QAction *> actions_;
  actions_.append(m_action);
  return actions_;
}

QStringList ImportPQR::menuPath(QAction *) const
{
  QStringList path;
  path << tr("&File");
  return path;
}

void ImportPQR::setMolecule(QtGui::Molecule *mol)
{

  m_molecule = mol;

}


bool ImportPQR::readMolecule(QtGui::Molecule &mol)
{


  bool readOK = Io::FileFormatManager::instance().readFile(
        mol, m_moleculePath.toStdString());


  if (readOK) // worked, so set the filename
    mol.setData("name", m_moleculeName.toStdString());
  QString err = QString::fromStdString(Io::FileFormatManager::instance().error());
//QMessageBox::warning(qobject_cast<QWidget*>(parent()),
  //                   tr("Network Download Failed"),
    //                 tr("Path: %1 Name: %2")
      //               .arg(err)
        //             .arg(m_moleculeName));

  return readOK;

}

void ImportPQR::menuActivated()
{
  if (!m_dialog) {
    m_dialog = new PQRWidget(qobject_cast<QWidget*>(this), this);

  }
  m_dialog->show();
}

void ImportPQR::setMoleculeData(QString path, QString name)
{
  m_moleculeName = name;
  m_moleculePath = path;

  m_dialog->hide();
  emit moleculeReady(1);
}

}
}
