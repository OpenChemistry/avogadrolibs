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

#ifndef AVOGADRO_QTPLUGINS_CARTESIANEDITOR_H
#define AVOGADRO_QTPLUGINS_CARTESIANEDITOR_H

#include <avogadro/qtgui/extensionplugin.h>

#include <avogadro/core/avogadrocore.h>

namespace Avogadro {
namespace QtPlugins {
class CartesianEditorDialog;

/**
 * @brief CartesianEditor implements the plugin interface for the cartesian
 * editor extension.
 */
class CartesianEditor : public Avogadro::QtGui::ExtensionPlugin
{
  Q_OBJECT
public:
  explicit CartesianEditor(QObject *parent_ = 0);
  ~CartesianEditor() AVO_OVERRIDE;

  QString name() const AVO_OVERRIDE { return tr("Cartesian editor"); }

  QString description() const AVO_OVERRIDE
  {
    return tr("Text editing of cartesian atomic coordinates.");
  }

  QList<QAction *> actions() const AVO_OVERRIDE;

  QStringList menuPath(QAction *action) const AVO_OVERRIDE;

public slots:
  void setMolecule(QtGui::Molecule *mol) AVO_OVERRIDE;

private slots:
  void triggered();

private:
  CartesianEditorDialog *m_dialog;
  QtGui::Molecule *m_molecule;
  QAction *m_action;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_CARTESIANEDITOR_H
