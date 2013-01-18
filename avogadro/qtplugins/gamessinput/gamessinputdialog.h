/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2012 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef GAMESSINPUTDIALOG_H
#define GAMESSINPUTDIALOG_H

#include <QDialog>
#include <QButtonGroup>
#include <QModelIndex>

#include "ui_gamessinputdialog.h"

#include <QtCore/QSettings>

class QJsonObject;

namespace MoleQueue {
class Client;
}

namespace Avogadro {
namespace QtGui {
class Molecule;
}

namespace QtPlugins {
class GamessHighlighter;

class GamessInputDialog : public QDialog
{
  Q_OBJECT

public:
  explicit GamessInputDialog(QWidget *parent_ = 0, Qt::WindowFlags f = 0 );
  ~GamessInputDialog();

  void setMolecule(QtGui::Molecule *mol);

private slots:
  void updatePreviewText();

  void refreshPrograms();
  void queueListReceived(const QJsonObject &queueList);

  void defaultsClicked();
  void resetClicked();
  void generateClicked();
  void computeClicked();

private:
  void connectBasic();
  void connectPreview();
  void connectButtons();
  void connectMoleQueue();

  void buildOptions();

  void buildCalculateOptions();
  void buildTheoryOptions();
  void buildBasisOptions();
  void buildStateOptions();
  void buildMultiplicityOptions();
  void buildChargeOptions();

  void setBasicDefaults();

  Ui::GamessInputDialog ui;
  QtGui::Molecule *m_molecule;
  GamessHighlighter *m_highlighter;

  MoleQueue::Client *m_client;
};

} // end namespace QtPlugins
} // end namespace Avogadro

#endif // GAMESSINPUTDIALOG_H
