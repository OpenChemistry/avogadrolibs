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

#ifndef AVOGADRO_QTPLUGINS_SCRIPTFILEFORMATS_H
#define AVOGADRO_QTPLUGINS_SCRIPTFILEFORMATS_H

#include <avogadro/qtgui/extensionplugin.h>

#include <avogadro/core/avogadrocore.h>

namespace Avogadro {
namespace QtPlugins {

/**
 * @brief This extension registers FileFormat reader/writers that are
 * implemented as external scripts.
 */
class ScriptFileFormats : public QtGui::ExtensionPlugin
{
  Q_OBJECT

public:
  explicit ScriptFileFormats(QObject* parent = nullptr);
  ~ScriptFileFormats() override;

  QString name() const override { return tr("Script File Formats"); }

  QString description() const override
  {
    return tr("Load file reader/writers from external scripts.");
  }

  QList<QAction*> actions() const override;

  QStringList menuPath(QAction*) const override;

  void setMolecule(QtGui::Molecule* mol) override;

private:
  QList<Io::FileFormat*> m_formats;

  void refreshFileFormats();
  void unregisterFileFormats();
  void registerFileFormats();
};
}
}

#endif // AVOGADRO_QTPLUGINS_QUANTUMOUTPUT_H
