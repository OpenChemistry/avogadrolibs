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

#ifndef AVOGADRO_QTPLUGINS_OPENBABEL_H
#define AVOGADRO_QTPLUGINS_OPENBABEL_H

#include <avogadro/qtgui/extensionplugin.h>

#include <QtCore/QMap>

class QAction;
class QProgressDialog;

namespace Avogadro {
namespace QtPlugins {

class OBProcess;

/**
 * @brief The OpenBabel class implements the ExtensionPlugin interface to
 * expose some OpenBabel functionality.
 *
 * @todo The readMolecule method will need to be updated if we allow
 * multimolecule files to load with the Io::CmlReader.
 */
class OpenBabel : public QtGui::ExtensionPlugin
{
  Q_OBJECT

public:
  explicit OpenBabel(QObject *parent = 0);
  ~OpenBabel();

  QString name() const { return tr("OpenBabel"); }

  QString description() const
  {
    return tr("Interact with OpenBabel utilities.");
  }

  QList<QAction *> actions() const;

  QStringList menuPath(QAction *) const;

public slots:
  void setMolecule(QtGui::Molecule *);

  bool readMolecule(QtGui::Molecule &mol);

private slots:
  void onOpenFile();
  void onOpenFileReadFinished(const QByteArray &output);

  void refreshReadFormats();
  void handleReadFormatUpdate(QMap<QString, QString> fmts);

private:
  OBProcess *m_process;
  QList<QAction *> m_actions;
  QList<QByteArray> m_moleculeQueue;
  QMap<QString, QString> m_readFormats;
  QString m_readFormatsFilterString;
  QProgressDialog *m_progress;
};

}
}

#endif // AVOGADRO_QTPLUGINS_OPENBABEL_H
