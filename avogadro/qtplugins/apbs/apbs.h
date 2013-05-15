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

#ifndef AVOGADRO_QTPLUGINS_APBS_APBS_H
#define AVOGADRO_QTPLUGINS_APBS_APBS_H

#include <avogadro/qtgui/extensionplugin.h>

#include <QStringList>

class QProgressDialog;

namespace Avogadro {
namespace QtPlugins {

class Apbs : public QtGui::ExtensionPlugin
{
  Q_OBJECT

public:
  explicit Apbs(QObject *parent_ = 0);
  ~Apbs();

  QString name() const { return tr("APBS"); }
  QString description() const { return tr("Interact with APBS utilities."); }
  QList<QAction *> actions() const { return m_actions; }
  QStringList menuPath(QAction *) const
  {
    return QStringList() << tr("&Extensions") << tr("&APBS");
  }
  void setMolecule(QtGui::Molecule *);

private slots:
  void onOpenOutputFile();
  void onMeshGeneratorProgress(int value);
  void cubeGeneratorFinished();

private:
  QtGui::Molecule *m_molecule;
  QList<QAction *> m_actions;
  QProgressDialog *m_progressDialog;
};

}
}

#endif // AVOGADRO_QTPLUGINS_APBS_APBS_H
