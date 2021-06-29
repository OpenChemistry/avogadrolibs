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

#ifndef AVOGADRO_QTPLUGINS_MOLECULARPROPERTIES_H
#define AVOGADRO_QTPLUGINS_MOLECULARPROPERTIES_H

#include <avogadro/qtgui/extensionplugin.h>

namespace Avogadro {

namespace Core {
class Molecule;
}

namespace QtPlugins {
class MolecularPropertiesDialog;

/**
 * @brief The MolecularProperties class is an extension to launch
 * a MolecularPropertiesDialog.
 */
class MolecularProperties : public Avogadro::QtGui::ExtensionPlugin
{
  Q_OBJECT
public:
  explicit MolecularProperties(QObject* parent_ = nullptr);
  ~MolecularProperties() override;

  QString name() const override { return tr("Molecular Properties"); }
  QString description() const override;
  QList<QAction*> actions() const override;
  QStringList menuPath(QAction*) const override;

public slots:
  void setMolecule(QtGui::Molecule* mol) override;

private slots:
  void showDialog();

private:
  QAction* m_action;
  MolecularPropertiesDialog* m_dialog;
  QtGui::Molecule* m_molecule;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_MOLECULARPROPERTIESEXTENSION_H
