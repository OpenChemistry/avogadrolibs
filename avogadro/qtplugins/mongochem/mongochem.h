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

#include <avogadro/qtgui/extensionplugin.h>

#include <QByteArray>
#include <QScopedPointer>

class QAction;
class QDialog;

namespace Avogadro {

namespace QtPlugins {

class MongoChem : public QtGui::ExtensionPlugin
{
  Q_OBJECT

public:
  explicit MongoChem(QObject* parent = nullptr);
  ~MongoChem() override;

  QString name() const override { return tr("Mongo Chem Server"); }

  QString description() const override
  {
    return tr("Interface with Mongo Chem Server.");
  }

  QList<QAction*> actions() const override { return m_actions; }

  QStringList menuPath(QAction*) const override;

  // This will also emit moleculeReady(1)
  void setMoleculeData(const QByteArray& data);
  void setMoleculeName(const QString& name) { m_moleculeName = name; }

  // Returns the cjson of the current molecule as a QString
  QString currentMoleculeCjson() const;

public slots:
  void setMolecule(QtGui::Molecule* mol) override;

  // This will also clear m_moleculeData and m_moleculeName
  bool readMolecule(QtGui::Molecule& mol) override;

private slots:
  void menuActivated();

private:
  // A non-owning list of the actions
  QList<QAction*> m_actions;
  QtGui::Molecule* m_molecule;

  QScopedPointer<QAction> m_action;
  QScopedPointer<QDialog> m_dialog;

  // The data to be read by readMolecule()
  QByteArray m_moleculeData;
  QString m_moleculeName;
};
} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_MONGOCHEM_H
