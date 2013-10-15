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

#ifndef AVOGADRO_QTPLUGINS_COORDINATEEDITOR_H
#define AVOGADRO_QTPLUGINS_COORDINATEEDITOR_H

#include <avogadro/qtgui/extensionplugin.h>

#include <avogadro/core/avogadrocore.h>

namespace Avogadro {
namespace QtPlugins {
class CoordinateEditorDialog;

/**
 * @brief CoordinateEditor implements the plugin interface for the coordinate
 * editor extension.
 */
class CoordinateEditor : public Avogadro::QtGui::ExtensionPlugin
{
  Q_OBJECT
public:
  explicit CoordinateEditor(QObject *parent_ = 0);
  ~CoordinateEditor() AVO_OVERRIDE;

  QString name() const AVO_OVERRIDE { return tr("Coordinate editor"); }

  QString description() const AVO_OVERRIDE
  {
    return tr("Text editing of atomic coordinates.");
  }

  QList<QAction *> actions() const AVO_OVERRIDE;

  QStringList menuPath(QAction *action) const AVO_OVERRIDE;

public slots:
  void setMolecule(QtGui::Molecule *mol) AVO_OVERRIDE;

private slots:
  void triggered();

private:
  CoordinateEditorDialog *m_dialog;
  QtGui::Molecule *m_molecule;
  QAction *m_action;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_COORDINATEEDITOR_H
