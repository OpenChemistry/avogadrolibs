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

#ifndef AVOGADRO_QTPLUGINS_COPYPASTE_H
#define AVOGADRO_QTPLUGINS_COPYPASTE_H

#include <avogadro/qtgui/extensionplugin.h>
#include <avogadro/core/avogadrocore.h>

#include <QtGui/QIcon>

namespace Avogadro {
namespace Io {
class FileFormat;
}

namespace QtPlugins {

/**
 * @brief The CopyPaste class allows interaction with the system clipboard.
 */
class CopyPaste : public QtGui::ExtensionPlugin
{
  Q_OBJECT
public:
  explicit CopyPaste(QObject *parent_ = 0);
  ~CopyPaste() AVO_OVERRIDE;

  QString name() const AVO_OVERRIDE { return tr("Copy and paste"); }

  QString description() const AVO_OVERRIDE
  {
    return tr("Interact with the clipboard.");
  }

  QList<QAction *> actions() const AVO_OVERRIDE;

  QStringList menuPath(QAction *action) const AVO_OVERRIDE;

public slots:
  void setMolecule(QtGui::Molecule *mol) AVO_OVERRIDE;

  bool readMolecule(QtGui::Molecule &mol) AVO_OVERRIDE;

private slots:
  bool copy(); // returns bool so cut can reuse implementation.
  void cut();
  void paste();

private:
  // Cached between emitting moleculeReady() and calling readMolecule().
  QByteArray m_pastedData;
  Io::FileFormat *m_pastedFormat;

  QtGui::Molecule *m_molecule;

  QAction *m_copyAction;
  QAction *m_cutAction;
  QAction *m_pasteAction;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_COPYPASTE_H
