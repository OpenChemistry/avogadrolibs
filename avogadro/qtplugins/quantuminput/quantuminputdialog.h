/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2012-2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef QUANTUMINPUTDIALOG_H
#define QUANTUMINPUTDIALOG_H

#include <QtGui/QDialog>

#include "ui_quantuminputdialog.h"

#include <qjsonobject.h>

#include <QtCore/QMap>

class QJsonValue;
class QWidget;

namespace MoleQueue {
class Client;
}

namespace Avogadro {
namespace QtGui {
class Molecule;
}

namespace QtPlugins {

/// @todo dox
/// @todo need some way to express dependencies across options, e.g. disable
/// basis selection if a semiempirical calc is request in GAMESS
class QuantumInputDialog : public QDialog
{
  Q_OBJECT

public:
  explicit QuantumInputDialog(const QString &script, QWidget *parent_ = 0,
                              Qt::WindowFlags f = 0 );
  ~QuantumInputDialog();

  void setMolecule(QtGui::Molecule *mol);

private slots:
  void updatePreviewText();
  void updatePreviewTextImmediately();

  void refreshPrograms();
  void queueListReceived(const QJsonObject &queueList);

  void defaultsClicked();
  void generateClicked();
  void computeClicked();

private:
  void connectButtons();
  void connectMoleQueue();

  void updateOptions();
  void buildOptionGui();
  void addOptionRow(const QString &label, const QJsonValue &option);
  QWidget* createOptionWidget(const QJsonValue &option);
  void updateInputMoleculeFormat();
  void setOptionDefaults();

  QByteArray collectOptions() const;
  QByteArray generateCJson() const;

  QString generateCoordinateBlock(const QString &spec) const;
  void replaceKeywords(QString &str) const;

  Ui::QuantumInputDialog m_ui;
  QtGui::Molecule *m_molecule;
  MoleQueue::Client *m_client;
  QJsonObject m_options;
  bool m_updatePending;
  QString m_scriptFilePath;

  QMap<QString, QWidget*> m_widgets;

  /// Molecular representation formats that generator scripts can request.
  /// @todo xyz, cml
  enum InputMoleculeFormat {
    NoInputFormat = 0,
    CJSON
  };
  InputMoleculeFormat m_inputMoleculeFormat;
};

} // end namespace QtPlugins
} // end namespace Avogadro

#endif // GAMESSINPUTDIALOG_H
