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

#include "inputgenerator.h"

#include <qjsonobject.h>

#include <QtCore/QMap>

class QJsonValue;
class QTextEdit;
class QWidget;

namespace MoleQueue {
class Client;
}

namespace Avogadro {
namespace QtGui {
class Molecule;
}

namespace QtPlugins {

/**
 * @brief the QuantumInputDialog class provides a dynamic user interface that
 * is generated from input generator scripts.
 * @author David C. Lonie
 * @todo Syntax highlighting
 * @todo Custom filenames
 * @todo need some way to express dependencies across options, e.g. disable
 * basis selection if a semiempirical calc is request in GAMESS
 */
class QuantumInputDialog : public QDialog
{
  Q_OBJECT

public:
  /**
   * Constructor
   * @param scriptFilePath Absolute path to generator script.
   */
  explicit QuantumInputDialog(const QString &scriptFilePath,
                              QWidget *parent_ = NULL,
                              Qt::WindowFlags f = NULL);
  ~QuantumInputDialog();

  /**
   * Set the molecule used in the simulation.
   */
  void setMolecule(QtGui::Molecule *mol);

private slots:
  /**
   * Update the input files. This method is throttled, and will only call the
   * generator script once every 250 milliseconds.
   */
  void updatePreviewText();

  /**
   * Immediately update the input files, bypassing (and resetting) the throttle
   * mechanism.
   */
  void updatePreviewTextImmediately();

  /**
   * Query the MoleQueue server (if available) for the list of available queues
   * and programs.
   */
  void refreshPrograms();

  /**
   * Triggered when MoleQueue replies to the request from refreshPrograms().
   * Parse the response from MoleQueue and update the GUI.
   */
  void queueListReceived(const QJsonObject &queueList);

  /**
   * Triggered when the user resets the default values.
   */
  void defaultsClicked();

  /**
   * Triggered when the user requests that the files are written to disk.
   */
  void generateClicked();

  /**
   * Triggered when the user requests that the simulation is submitted to
   * MoleQueue.
   */
  void computeClicked();

  /**
   * Show the user an error message.
   */
  void showError(const QString &err);

private:
  /**
   * Generate a QSettings key with the given identifier that is unique to this
   * input generator's display name.
   * @param identifier Setting key, e.g. "outputPath"
   * @return Script-specific key, e.g. "quantumInput/GAMESS/outputPath"
   * @todo Display names are not necessarily unique, but paths are too long.
   * Maybe add a namespace qualifier to the script display names?
   */
  QString settingsKey(const QString &identifier) const;

  /**
   * Make signal/slot connections.
   * @{
   */
  void connectButtons();
  void connectMoleQueue();
  /**@}*/

  /**
   * Used to construct the script-specific GUI.
   * @{
   */
  void updateOptions();
  void buildOptionGui();
  void addOptionRow(const QString &label, const QJsonValue &option);
  QWidget* createOptionWidget(const QJsonValue &option);
  /**@}*/

  /**
   * Set the simulation settings to their default values.
   */
  void setOptionDefaults();

  /**
   * Collect all of the user-specified options into a JSON object, to be sent
   * to the generator script.
   */
  QJsonObject collectOptions() const;

  /**
   * Used for keyword replacement.
   * @sa InputGenerator
   * @{
   */
  QString generateCoordinateBlock(const QString &spec) const;
  void replaceKeywords(QString &str) const;
  /**@}*/

  Ui::QuantumInputDialog m_ui;
  QtGui::Molecule *m_molecule;
  MoleQueue::Client *m_client;
  QJsonObject m_options;
  bool m_updatePending;
  InputGenerator m_inputGenerator;

  QMap<QString, QWidget*> m_widgets;
  QMap<QString, QTextEdit*> m_textEdits;
};

} // end namespace QtPlugins
} // end namespace Avogadro

#endif // GAMESSINPUTDIALOG_H
