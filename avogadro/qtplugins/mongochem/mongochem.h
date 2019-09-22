/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2019 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_MONGOCHEM_H
#define AVOGADRO_QTPLUGINS_MONGOCHEM_H

#include <memory>

#include <avogadro/qtgui/extensionplugin.h>

class QAction;
class QDialog;

namespace Avogadro {

namespace QtPlugins {

class MongoChem : public QtGui::ExtensionPlugin
{
  Q_OBJECT

public:
  explicit MongoChem(QObject* parent = 0);
  ~MongoChem() override;

  QString name() const override { return tr("Mongo Chem Server"); }

  QString description() const override
  {
    return tr("Interface with Mongo Chem Server.");
  }

  QList<QAction*> actions() const override { return m_actions; }

  QStringList menuPath(QAction*) const override;

public slots:
  void setMolecule(QtGui::Molecule* mol) override;
  bool readMolecule(QtGui::Molecule& mol) override;

private slots:
  void menuActivated();

private:
  // A non-owning list of the actions
  QList<QAction*> m_actions;
  QtGui::Molecule* m_molecule;

  std::unique_ptr<QAction> m_action;
  std::unique_ptr<QDialog> m_dialog;
};
} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_MONGOCHEM_H
