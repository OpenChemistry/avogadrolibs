/******************************************************************************

  This source file is part of the MoleQueue project.

  Copyright 2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_HYDROGENS_H
#define AVOGADRO_QTPLUGINS_HYDROGENS_H

#include <avogadro/qtgui/extensionplugin.h>

namespace Avogadro {
namespace QtPlugins {

/**
 * @brief The Hydrogens class is an extension to modify hydrogens.
 */
class Hydrogens : public Avogadro::QtGui::ExtensionPlugin
{
  Q_OBJECT
public:
  explicit Hydrogens(QObject* parent_ = nullptr);
  ~Hydrogens() override;

  QString name() const override { return tr("Hydrogens"); }
  QString description() const override;
  QList<QAction*> actions() const override;
  QStringList menuPath(QAction*) const override;

public slots:
  void setMolecule(QtGui::Molecule* mol) override;

private slots:
  void adjustHydrogens();
  void addHydrogens();
  void removeHydrogens();
  void removeAllHydrogens();

private:
  QList<QAction*> m_actions;
  QtGui::Molecule* m_molecule;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_HYDROGENS_H
