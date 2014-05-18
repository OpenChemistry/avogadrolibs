/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_BONDING_H
#define AVOGADRO_QTPLUGINS_BONDING_H

#include <avogadro/qtgui/extensionplugin.h>
#include <avogadro/core/avogadrocore.h>

namespace Avogadro {
namespace QtPlugins {

/**
 * @brief The Bonding class performs bonding operations on demand.
 */
class Bonding : public QtGui::ExtensionPlugin
{
  Q_OBJECT
public:
  explicit Bonding(QObject *parent_ = 0);
  ~Bonding() AVO_OVERRIDE;

  QString name() const AVO_OVERRIDE { return tr("Bonding"); }

  QString description() const AVO_OVERRIDE
  {
    return tr("Perform bonding operations.");
  }

  QList<QAction *> actions() const AVO_OVERRIDE;

  QStringList menuPath(QAction *action) const AVO_OVERRIDE;

public slots:
  void setMolecule(QtGui::Molecule *mol) AVO_OVERRIDE;

private slots:
  void bond();
  void bond2();
  void clearBonds();

private:
  QtGui::Molecule *m_molecule;

  QAction *m_action;
  QAction *m_clearAction;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_BONDING_H
