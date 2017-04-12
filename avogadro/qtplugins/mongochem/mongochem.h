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

#ifndef AVOGADRO_QTPLUGINS_MONGOCHEM_H
#define AVOGADRO_QTPLUGINS_MONGOCHEM_H

#include <avogadro/qtgui/extensionplugin.h>

namespace Avogadro {

namespace Core {
class Molecule;
}

namespace QtPlugins {

/**
 * @brief The MongoChem class is an extension to interact with MongoChem.
 */
class MongoChem : public Avogadro::QtGui::ExtensionPlugin
{
  Q_OBJECT
public:
  explicit MongoChem(QObject* parent_ = 0);
  ~MongoChem();

  QString name() const { return tr("Molecular Properties"); }
  QString description() const;
  QList<QAction*> actions() const;
  QStringList menuPath(QAction*) const;

public slots:
  void setMolecule(QtGui::Molecule* mol);

private slots:
  void showSimilarMolecules();

private:
  QAction* m_action;
  QtGui::Molecule* m_molecule;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_MONGOCHEMEXTENSION_H
