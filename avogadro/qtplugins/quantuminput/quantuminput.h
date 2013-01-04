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

#ifndef AVOGADRO_QTPLUGINS_QUANTUMINPUT_H
#define AVOGADRO_QTPLUGINS_QUANTUMINPUT_H

#include <avogadro/qtgui/extensionplugin.h>

#include <QtCore/QMultiMap>
#include <QtCore/QStringList>

class QAction;
class QDialog;

namespace Avogadro {
namespace QtPlugins {

class QuantumInputDialog;

class QuantumInput : public QtGui::ExtensionPlugin
{
  Q_OBJECT

public:
  explicit QuantumInput(QObject *parent = 0);
  ~QuantumInput();

  QString name() const { return tr("Quantum input"); }

  QString description() const { return tr("Generate input for quantum codes."); }

  QList<QAction *> actions() const;

  QStringList menuPath(QAction *) const;

  void setMolecule(QtGui::Molecule *mol);

public slots:
  void refreshGenerators();

private slots:
  void menuActivated();

private:
  void updateInputGeneratorScripts();
  void updateActions();
  void addAction(const QString &label, const QString &scriptFilePath);
  QString queryProgramName(const QString &scriptFilePath);

  QList<QAction*> m_actions;
  QtGui::Molecule *m_molecule;
  // keyed on script file path
  QMultiMap<QString, QuantumInputDialog*> m_dialogs;
  // maps program name --> script file path
  QMultiMap<QString, QString> m_inputGeneratorScripts;
};

}
}

#endif // AVOGADRO_QTPLUGINS_QUANTUMINPUT_H
