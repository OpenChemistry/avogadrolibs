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

#include <QtCore/QMap>
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
  explicit Workflow(QObject* parent = 0);
  ~Workflow() override;

  QString name() const override { return tr("Workflow scripts"); }

  QString description() const override
  {
    return tr("Run external workflow commands");
  }

  QList<QAction*> actions() const override;

  QStringList menuPath(QAction*) const override;

  void setMolecule(QtGui::Molecule* mol) override;

public slots:
  /**
   * Scan for new scripts in the workflow directories.
   */
  void refreshScripts();

  void run();

  bool readMolecule(QtGui::Molecule& mol) override;

private slots:
  void menuActivated();
  void configurePython();

private:
  void updateScripts();
  void updateActions();
  void addAction(const QString& label, const QString& scriptFilePath);

  QList<QAction*> m_actions;
  QtGui::Molecule* m_molecule;
  // keyed on script file path
  QMap<QString, QtGui::InterfaceWidget*> m_dialogs;
  QDialog* m_currentDialog;
  QtGui::InterfaceWidget* m_currentInterface;

  // maps program name --> script file path
  QMap<QString, QString> m_workflowScripts;

  const Io::FileFormat* m_outputFormat;
  QString m_outputFileName;
};
}
}

#endif // AVOGADRO_QTPLUGINS_WORKFLOW_H
