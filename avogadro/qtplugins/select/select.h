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

#ifndef AVOGADRO_QTPLUGINS_SELECT_H
#define AVOGADRO_QTPLUGINS_SELECT_H

#include <avogadro/qtgui/extensionplugin.h>

namespace Avogadro {
namespace QtPlugins {

/**
 * @brief The Select class is an extension to modify selections
 */
class Select : public Avogadro::QtGui::ExtensionPlugin
{
  Q_OBJECT
public:
  explicit Select(QObject* parent_ = nullptr);
  ~Select() override;

  QString name() const override { return tr("Select"); }
  QString description() const override;
  QList<QAction*> actions() const override;
  QStringList menuPath(QAction*) const override;

public slots:
  void setMolecule(QtGui::Molecule* mol) override;

private slots:
  void selectAll();
  void selectNone();
  void invertSelection();

private:
  QList<QAction*> m_actions;
  QtGui::Molecule* m_molecule;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_SELECT_H
