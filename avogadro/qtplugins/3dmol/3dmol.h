/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2016 Barry E Moore II

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_ThreeDMOL_H
#define AVOGADRO_QTPLUGINS_ThreeDMOL_H

#include <avogadro/qtgui/extensionplugin.h>

namespace Avogadro {

namespace Core {
class Molecule;
}

namespace QtPlugins {
class ThreeDMolDialog;

/**
 * @brief The ThreeDMol class is an extension to launch
 * a ThreeDMolDialog.
 */
class ThreeDMol : public Avogadro::QtGui::ExtensionPlugin
{
  Q_OBJECT
public:
  explicit ThreeDMol(QObject* parent_ = nullptr);
  ~ThreeDMol() override;

  QString name() const override { return tr("ThreeDMol"); }
  QString description() const override;
  QList<QAction*> actions() const override;
  QStringList menuPath(QAction*) const override;

public slots:
  void setMolecule(QtGui::Molecule* mol) override;

private slots:
  void showDialog();

private:
  QAction* m_action;
  ThreeDMolDialog* m_dialog;
  QtGui::Molecule* m_molecule;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_ThreeDMOLEXTENSION_H
