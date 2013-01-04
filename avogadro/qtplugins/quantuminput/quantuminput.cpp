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

#include "quantuminput.h"

#include "quantuminputdialog.h"
#include "quantuminputconfig.h"

#include <QtGui/QAction>
#include <QtGui/QDialog>

#include <QtCore/QDebug>
#include <QtCore/QDir>
#include <QtCore/QtPlugin>
#include <QtCore/QStringList>

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)

namespace Avogadro {
namespace QtGui {
class Molecule;
}

namespace QtPlugins {

QuantumInput::QuantumInput(QObject *parent_) :
  ExtensionPlugin(parent_),
  m_molecule(NULL)
{
  refreshGenerators();
}

QuantumInput::~QuantumInput()
{
  qDeleteAll(m_dialogs.values());
  m_dialogs.clear();
}

QList<QAction *> QuantumInput::actions() const
{
  return m_actions;
}

QStringList QuantumInput::menuPath(QAction *) const
{
  QStringList path;
  path << tr("&Extensions") << tr("&Input Generators");
  return path;
}

void QuantumInput::setMolecule(QtGui::Molecule *mol)
{
  if (m_molecule == mol)
    return;

  m_molecule = mol;

  foreach (QuantumInputDialog *dlg, m_dialogs.values())
    dlg->setMolecule(mol);
}

void QuantumInput::refreshGenerators()
{
  updateInputGeneratorScripts();
  updateActions();
}

void QuantumInput::menuActivated()
{
  QAction *theSender = qobject_cast<QAction*>(sender());
  if (!theSender)
    return;

  QString scriptFileName = theSender->data().toString();
  QWidget *theParent = qobject_cast<QWidget*>(parent());
  QuantumInputDialog *dlg = m_dialogs.value(scriptFileName, NULL);

  if (!dlg) {
    dlg = new QuantumInputDialog(scriptFileName, theParent);
    m_dialogs.insert(scriptFileName, dlg);
  }
  dlg->setMolecule(m_molecule);
  dlg->show();
  dlg->raise();
}

void QuantumInput::updateInputGeneratorScripts()
{
  m_inputGeneratorScripts.clear();

  // List of directories to check. Currently hardcoded to the installation
  // directory and the source tree.
  QStringList dirs;
  dirs << QString(TOSTRING(QUANTUMINPUT_GENERATOR_DIR))
       << QString(TOSTRING(QUANTUMINPUT_GENERATOR_SOURCE_DIR));

  foreach (const QString &dirStr, dirs) {
    qDebug() << "Checking for generator scripts in" << dirStr;
    QDir dir(dirStr);
    if (dir.exists() && dir.isReadable()) {
      foreach (const QFileInfo &file, dir.entryInfoList(QDir::Files |
                                                        QDir::NoDotAndDotDot)) {
        QString filePath = file.absoluteFilePath();
        qDebug() << filePath;
        m_inputGeneratorScripts.insert(queryProgramName(filePath),
                                       filePath);
      }
    }
  }
}

void QuantumInput::updateActions()
{
  m_actions.clear();
  foreach (const QString &programName, m_inputGeneratorScripts.uniqueKeys()) {
    QStringList scripts = m_inputGeneratorScripts.values(programName);
    // Include the full path if there are multiple generators with the same name.
    if (scripts.size() == 1) {
      addAction(programName, scripts.first());
    }
    else {
      foreach (const QString &filePath, scripts) {
        addAction(QString("%1 (%2)").arg(programName, filePath), filePath);
      }
    }
  }
}

void QuantumInput::addAction(const QString &label,
                             const QString &scriptFilePath)
{
  qDebug() << "Adding action" << m_actions.size() + 1 << label << scriptFilePath;
  /// @todo Need a way to tell avogadro that the actions are no longer valid.
  QAction *action = new QAction(label, this);
  action->setData(scriptFilePath);
  action->setEnabled(true);
  connect(action, SIGNAL(triggered()), SLOT(menuActivated()));
  m_actions << action;
  /// @todo Need a way to tell avogadro that new actions are available.
}

QString QuantumInput::queryProgramName(const QString &scriptFilePath)
{
  /// @todo
  return "GAMESS";
}

}
}
