/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2016 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_WORKFLOW_H
#define AVOGADRO_QTPLUGINS_WORKFLOW_H

#include <avogadro/qtgui/extensionplugin.h>

#include <QtCore/QMultiMap>
#include <QtCore/QStringList>

class QAction;
class QDialog;

namespace Avogadro {
namespace Io {
  class FileFormat;
}

namespace QtGui {
  class InterfaceScript;
  class InterfaceWidget;
}

namespace QtPlugins {

/**
 * @brief The Workflow class implements the extension interface for
 * external (script) workflows
 * @author Geoffrey R. Hutchison
 */
class Workflow : public QtGui::ExtensionPlugin
{
  Q_OBJECT

public:
  explicit Workflow(QObject *parent = 0);
  ~Workflow();

  QString name() const { return tr("Workflow scripts"); }

  QString description() const { return tr("Run external workflow commands"); }

  QList<QAction *> actions() const;

  QStringList menuPath(QAction *) const;

  void setMolecule(QtGui::Molecule *mol);

public slots:
  /**
   * Scan for new scripts in the workflow directories.
   */
  void refreshScripts();

  void run();

  bool readMolecule(QtGui::Molecule &mol);

private slots:
  void menuActivated();
  void configurePython();

private:
  void updateScripts();
  void updateActions();
  void addAction(const QString &label, const QString &scriptFilePath);
  bool queryProgramName(const QString &scriptFilePath, QString &displayName);

  QList<QAction*> m_actions;
  QtGui::Molecule *m_molecule;
  // keyed on script file path
  QMultiMap<QString, QtGui::InterfaceWidget*> m_dialogs;
  QDialog *m_currentDialog;
  QtGui::InterfaceWidget *m_currentInterface;

  // maps program name --> script file path
  QMultiMap<QString, QString> m_workflowScripts;

  const Io::FileFormat *m_outputFormat;
  QString m_outputFileName;
};

}
}

#endif // AVOGADRO_QTPLUGINS_WORKFLOW_H
