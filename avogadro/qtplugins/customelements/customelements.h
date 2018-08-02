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

#ifndef AVOGADRO_QTPLUGINS_CUSTOMELEMENTS_H
#define AVOGADRO_QTPLUGINS_CUSTOMELEMENTS_H

#include <avogadro/qtgui/extensionplugin.h>

class QProgressDialog;
class QThread;

namespace Avogadro {

class BackgroundFileFormat;

namespace QtPlugins {

/**
 * @brief Manipulate custom element types in the current molecule.
 */
class CustomElements : public QtGui::ExtensionPlugin
{
  Q_OBJECT
public:
  explicit CustomElements(QObject* parent_ = 0);
  ~CustomElements() override;

  QString name() const override { return tr("Custom Elements"); }
  QString description() const override;
  QList<QAction*> actions() const override;
  QStringList menuPath(QAction*) const override;

public slots:
  void setMolecule(QtGui::Molecule* mol) override;

private slots:
  void moleculeChanged(unsigned int changes);
  void reassign();
  void importMapFile();
  void backgroundReaderFinished();

private:
  QtGui::Molecule* m_molecule;
  QAction* m_reassignUsingTool;
  QAction* m_reassignFromFile;
  QThread* m_fileReadThread;
  BackgroundFileFormat* m_threadedReader;
  QtGui::Molecule* m_fileReadMolecule;
  QProgressDialog* m_progressDialog;

  void updateReassignAction();
  bool openFile(const QString& fileName, Io::FileFormat* reader);
  void setMapFromMolecule(QtGui::Molecule* mol);
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_CUSTOMELEMENTS_H
