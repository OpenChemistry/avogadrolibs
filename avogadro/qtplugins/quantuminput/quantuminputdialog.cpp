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

#include "quantuminputdialog.h"

#include "inputgenerator.h"

#include <avogadro/qtgui/molecule.h>

#include <molequeue/client/client.h>
#include <molequeue/client/job.h>

#include <qjsonarray.h>
#include <qjsondocument.h>
#include <qjsonobject.h>
#include <qjsonvalue.h>

#include <QtGui/QFileDialog>
#include <QtGui/QFormLayout>
#include <QtGui/QHBoxLayout>
#include <QtGui/QMessageBox>
#include <QtGui/QProgressDialog>
#include <QtGui/QTextBrowser>
#include <QtGui/QTextEdit>
#include <QtGui/QVBoxLayout>

#include <QtCore/QDebug>
#include <QtCore/QFile>
#include <QtCore/QFileInfo>
#include <QtCore/QPointer>
#include <QtCore/QRegExp>
#include <QtCore/QSettings>
#include <QtCore/QString>
#include <QtCore/QTextStream>
#include <QtCore/QTimer>

namespace Avogadro {
namespace QtPlugins {

QuantumInputDialog::QuantumInputDialog(const QString &scriptFilePath,
                                       QWidget *parent_, Qt::WindowFlags f)
  : QDialog( parent_, f ),
    m_molecule(NULL),
    m_client(new MoleQueue::Client(this)),
    m_updatePending(false),
    m_inputGenerator(scriptFilePath)
{
  m_ui.setupUi(this);

  m_ui.debugCheckBox->setChecked(m_inputGenerator.debug());

  setWindowTitle(tr("%1 Input Generator").arg(m_inputGenerator.displayName()));

  updateOptions();

  connectButtons();
  connectMoleQueue();

  m_client->connectToServer();
  if (m_client->isConnected())
    m_client->requestQueueList();
}

QuantumInputDialog::~QuantumInputDialog()
{
}

void QuantumInputDialog::setMolecule(QtGui::Molecule *mol)
{
  if (mol == m_molecule)
    return;

  if (m_molecule) {
    disconnect(mol, SIGNAL(changed(unsigned int)),
               this, SLOT(updatePreviewText()));
  }

  m_molecule = mol;

  connect(mol, SIGNAL(changed(unsigned int)), SLOT(updatePreviewText()));

  updatePreviewTextImmediately();
}

void QuantumInputDialog::showEvent(QShowEvent *e)
{
  QWidget::showEvent(e);

  // Update the preview text if an update was requested while hidden. Use a
  // single shot to allow the dialog to show before popping up any warnings.
  if (m_updatePending)
    QTimer::singleShot(0, this, SLOT(updatePreviewTextImmediately()));
}

void QuantumInputDialog::updatePreviewText()
{
  if (m_updatePending)
    return;

  m_updatePending = true;
  QTimer::singleShot(250, this, SLOT(updatePreviewTextImmediately()));
}

void QuantumInputDialog::updatePreviewTextImmediately()
{
  // If the dialog is not shown, delay the update in case we need to prompt the
  // user to overwrite changes. Set the m_updatePending flag to true so we'll
  // know to update in the show event.
  if (!isVisible()) {
    m_updatePending = true;
    return;
  }

  // Reset the update throttling
  m_updatePending = false;

  // Have any buffers been modified?
  if (!m_dirtyTextEdits.isEmpty()) {
    QStringList buffers;
    foreach (QTextEdit *edit, m_dirtyTextEdits)
      buffers << m_textEdits.key(edit, tr("Unknown"));
    QString message = tr("The following file(s) have been modified:\n\n%1\n\n"
                         "Would you like to overwrite your changes to reflect "
                         "the new geometry or job options?", "", buffers.size())
        .arg(buffers.join("\n"));
    int response =
        QMessageBox::question(this, tr("Overwrite modified input files?"),
                              message, QMessageBox::Yes | QMessageBox::No,
                              QMessageBox::No);
    if (static_cast<QMessageBox::StandardButton>(response) !=
        QMessageBox::Yes) {
      applyOptions(m_optionCache);
      return;
    }
  }

  if (!m_molecule)
    return;

  // Generate the input files
  QJsonObject inputOptions;
  inputOptions["options"] = collectOptions();
  inputOptions["settings"] = collectSettings();
  if (!m_inputGenerator.generateInput(inputOptions, *m_molecule)) {
    showError(m_inputGenerator.errorString());
    m_inputGenerator.clearErrors();
    return;
  }

  // Store the currently displayed tab
  QPointer<QWidget> currentWidget(m_ui.tabWidget->currentWidget());

  // Ensure that the correct tabs are shown:
  QStringList fileNames = m_inputGenerator.fileNames();
  // Remove unneeded tabs
  foreach (const QString &tabName, m_textEdits.keys()) {
    if (!fileNames.contains(tabName)) {
      QTextEdit *edit = m_textEdits.value(tabName);
      int index = m_ui.tabWidget->indexOf(edit);
      m_ui.tabWidget->removeTab(index);
      m_textEdits.remove(tabName);
      delete edit;
    }
  }

  // Add new tabs
  foreach (const QString &fileName, fileNames) {
    if (m_textEdits.contains(fileName))
      continue;
    QTextEdit *edit = new QTextEdit();
    connect(edit, SIGNAL(textChanged()), this, SLOT(textEditModified()));
    m_ui.tabWidget->addTab(edit, fileName);
    m_textEdits.insert(fileName, edit);
  }

  // Sort and update
  int index = 0;
  foreach (const QString &fileName, fileNames) {
    QTextEdit *edit = m_textEdits.value(fileName);
    int tabIndex = m_ui.tabWidget->indexOf(edit);
    if (tabIndex != index) {
      m_ui.tabWidget->removeTab(tabIndex);
      m_ui.tabWidget->insertTab(index, edit, fileName);
    }
    edit->setText(m_inputGenerator.fileContents(fileName));
    edit->document()->setModified(false);
    ++index;
  }

  // Reset dirty buffer list and cached option list
  m_dirtyTextEdits.clear();
  m_optionCache = collectOptions();

  // Restore current tab
  if (!currentWidget.isNull())
    m_ui.tabWidget->setCurrentWidget(currentWidget);
}

void QuantumInputDialog::refreshPrograms()
{
  if (!m_client->isConnected()) {
    m_client->connectToServer();
    if (!m_client->isConnected()) {
      QMessageBox::information(this, tr("Cannot connect to MoleQueue"),
                               tr("Cannot connect to MoleQueue server. Please "
                                  "ensure that it is running and try again."));
      return;
    }
  }
  m_client->requestQueueList();
}

void QuantumInputDialog::queueListReceived(const QJsonObject &queueList)
{
  m_ui.programCombo->clear();
  int firstMatch = -1;
  foreach (const QString &queue, queueList.keys())
    {
    foreach (const QJsonValue &program, queueList.value(queue).toArray())
    {
      if (program.isString()) {
        if (firstMatch < 0 &&
            program.toString().contains(m_inputGenerator.displayName(),
                                        Qt::CaseInsensitive)) {
          firstMatch = m_ui.programCombo->count();
        }
        m_ui.programCombo->addItem(QString("%1 (%2)").arg(program.toString(),
                                                          queue));
      }
    }
  }
  m_ui.programCombo->setCurrentIndex(firstMatch);
}


void QuantumInputDialog::defaultsClicked()
{
  setOptionDefaults();
  updatePreviewTextImmediately();
}

void QuantumInputDialog::generateClicked()
{
  if (m_textEdits.size() == 1)
    saveSingleFile(m_textEdits.keys().first());
  else if (m_textEdits.size() > 1)
    saveDirectory();
  else
    showError(tr("No input files to save!"));
}

void QuantumInputDialog::computeClicked()
{
  if (!m_client->isConnected()) {
    m_client->connectToServer();
    if (!m_client->isConnected()) {
      QMessageBox::information(this, tr("Cannot connect to MoleQueue"),
                               tr("Cannot connect to MoleQueue server. Please "
                                  "ensure that it is running and try again."));
      return;
    }
  }

  QString programText = m_ui.programCombo->currentText();
  if (programText.isEmpty()) {
    QMessageBox::information(this, tr("No program set."),
                             tr("Cannot determine which MoleQueue program "
                                "configuration to use. Has MoleQueue been "
                                "configured?"));
    return;
  }

  QRegExp parser("^(.+) \\((.+)\\)$");
  int parseResult = parser.indexIn(programText);

  // Should not happen...
  if (parseResult == -1)
    return;

  const QString program = parser.cap(1);
  const QString queue = parser.cap(2);
  const QString mainFileName = m_inputGenerator.mainFileName();

  MoleQueue::JobObject job;
  job.setQueue(queue);
  job.setProgram(program);
  job.setDescription(tr("Avogadro calculation"));
  job.setValue("numberOfCores", m_ui.coresSpinBox->value());
  for (QMap<QString, QTextEdit*>::const_iterator it = m_textEdits.constBegin(),
       itEnd = m_textEdits.constEnd(); it != itEnd; ++it) {
    QString filename = it.key();
    if (filename != mainFileName)
      job.appendAdditionalInputFile(filename, it.value()->toPlainText());
    else
      job.setInputFile(filename, it.value()->toPlainText());
  }

  m_client->submitJob(job);
}

void QuantumInputDialog::showError(const QString &err)
{
  qWarning() << err;

  QWidget *theParent = this->isVisible() ? this
                                         : qobject_cast<QWidget*>(parent());
  QDialog dlg(theParent);
  QVBoxLayout *vbox = new QVBoxLayout();
  QLabel *label = new QLabel(tr("An error has occurred:"));
  vbox->addWidget(label);
  QTextBrowser *textBrowser = new QTextBrowser();

  // adjust the size of the text browser to ~80 char wide, ~20 lines high
  QSize theSize = textBrowser->sizeHint();
  QFontMetrics metrics(textBrowser->currentFont());
  int charWidth = metrics.width("i7OPlmWn9/") / 10;
  int charHeight = metrics.lineSpacing();
  theSize.setWidth(80 * charWidth);
  theSize.setHeight(20 * charHeight);
  textBrowser->setMinimumSize(theSize);
  textBrowser->setText(err);
  vbox->addWidget(textBrowser);
  dlg.setLayout(vbox);

  dlg.exec();
}

void QuantumInputDialog::textEditModified()
{
  if (QTextEdit *edit = qobject_cast<QTextEdit*>(sender())) {
    if (edit->document()->isModified()) {
      if (!m_dirtyTextEdits.contains(edit))
        m_dirtyTextEdits << edit;
    }
    else {
      m_dirtyTextEdits.removeOne(edit);
    }
  }
}

QString QuantumInputDialog::settingsKey(const QString &identifier) const
{
  return QString("quantumInput/%1/%2").arg(m_inputGenerator.displayName(),
                                           identifier);
}

void QuantumInputDialog::saveSingleFile(const QString &fileName)
{
  QSettings settings;
  QString filePath = settings.value(settingsKey("outputDirectory")).toString();
  filePath = QFileDialog::getSaveFileName(
        this, tr("Select output filename"), filePath + "/" + fileName);

  // User cancel:
  if (filePath.isNull())
    return;

  settings.setValue(settingsKey("outputDirectory"),
                    QFileInfo(filePath).absoluteDir().absolutePath());

  QFileInfo info(filePath);

  // Don't check for overwrite: the file save dialog takes care of this.
  // Attempt to open the file for writing
  if (!QFile(fileName).open(QFile::WriteOnly)) {
    showError(tr("%1: File exists and is not writable.").arg(fileName));
    return;
  }

  QTextEdit *edit = m_textEdits.value(fileName, NULL);
  if (!edit) {
    showError(tr("Internal error: could not find text widget for filename '%1'")
              .arg(fileName));
    return;
  }

  QFile file(filePath);
  bool success = false;
  if (file.open(QFile::WriteOnly | QFile::Text)) {
    if (file.write(edit->toPlainText().toLatin1()) > 0) {
      success = true;
    }
    file.close();
  }

  if (!success) {
    QMessageBox::critical(
          this, tr("Output Error"),
          tr("Failed to write to file %1.").arg(file.fileName()));
  }
}

void QuantumInputDialog::saveDirectory()
{
  QSettings settings;
  QString directory = settings.value(settingsKey("outputDirectory")).toString();
  directory = QFileDialog::getExistingDirectory(
        this, tr("Select output directory"), directory);

  // User cancel:
  if (directory.isNull())
    return;

  settings.setValue(settingsKey("outputDirectory"), directory);
  QDir dir(directory);

  QStringList fileNames = m_textEdits.keys();

  // Check for problems:
  QStringList errors;
  bool fatalError = false;

  do { // Do/while to break on fatal errors
    if (!dir.exists()) {
      errors << tr("%1: Directory does not exist!").arg(dir.absolutePath());
      fatalError = true;
      break;
    }

    if (!dir.isReadable()) {
      errors << tr("%1: Directory cannot be read!").arg(dir.absolutePath());
      fatalError = true;
      break;
    }

    foreach (const QString &fileName, fileNames) {
      QFileInfo info(dir.absoluteFilePath(fileName));

      if (info.exists()) {
        errors << tr("%1: File will be overwritten.")
                  .arg(info.absoluteFilePath());
      }

      // Attempt to open the file for writing
      if (!QFile(info.absoluteFilePath()).open(QFile::WriteOnly)) {
        errors << tr("%1: File is not writable.").arg(info.absoluteFilePath());
        fatalError = true;
        break;
      }
    }
  } while (false); // only run once

  // Handle fatal errors:
  if (fatalError) {
    QString formattedError;
    switch (errors.size()) {
    case 0:
      formattedError =
          tr("The input files cannot be written due to an unknown error.");
      break;
    case 1:
      formattedError =
          tr("The input files cannot be written:\n\n%1").arg(errors.first());
      break;
    default: {
      // If a fatal error occured, it will be last one in the list. Pop it off
      // and tell the user that it was the reason we had to stop.
      QString fatal = errors.last();
      QStringList tmp(errors);
      tmp.pop_back();
      formattedError =
          tr("The input files cannot be written:\n\n%1\n\nWarnings:\n\n%2")
          .arg(fatal, tmp.join("\n"));
      break;
    }
    }
    showError(formattedError);
    return;
  }

  // Non-fatal errors:
  if (!errors.isEmpty()) {
    QString formattedError = tr("Warning:\n\n%1\n\nWould you like to continue?")
        .arg(errors.join("\n"));

    QMessageBox::StandardButton reply =
        QMessageBox::warning(this, tr("Write input files"), formattedError,
                             QMessageBox::Yes | QMessageBox::No,
                             QMessageBox::No);

    if (reply != QMessageBox::Yes)
      return;
  }

  foreach (const QString &fileName, fileNames) {
    QTextEdit *edit = m_textEdits.value(fileName);
    QFile file(dir.absoluteFilePath(fileName));
    bool success = false;
    if (file.open(QFile::WriteOnly | QFile::Text)) {
      if (file.write(edit->toPlainText().toLatin1()) > 0) {
        success = true;
      }
      file.close();
    }

    if (!success) {
      QMessageBox::critical(
            this, tr("Output Error"),
            tr("Failed to write to file %1.").arg(file.fileName()));
    }
  }
}

void QuantumInputDialog::connectButtons()
{
  connect(m_ui.debugCheckBox, SIGNAL(toggled(bool)),
          &m_inputGenerator, SLOT(setDebug(bool)));
  connect(m_ui.debugCheckBox, SIGNAL(toggled(bool)), SLOT(updatePreviewText()));
  connect(m_ui.defaultsButton, SIGNAL(clicked()), SLOT(defaultsClicked()));
  connect(m_ui.generateButton, SIGNAL(clicked()), SLOT(generateClicked()));
  connect(m_ui.computeButton, SIGNAL(clicked()), SLOT(computeClicked()));
  connect(m_ui.closeButton, SIGNAL(clicked()), SLOT(close()));
  connect(m_ui.refreshProgramsButton, SIGNAL(clicked()),
          SLOT(refreshPrograms()));
  connect(m_ui.coresSpinBox, SIGNAL(valueChanged(int)),
          SLOT(updatePreviewText()));
}

void QuantumInputDialog::connectMoleQueue()
{
  connect(m_client, SIGNAL(queueListReceived(QJsonObject)),
          this, SLOT(queueListReceived(QJsonObject)));
}

void QuantumInputDialog::updateOptions()
{
  m_options = m_inputGenerator.options();

  if (m_inputGenerator.hasErrors()) {
    showError(m_inputGenerator.errorString());
    m_inputGenerator.clearErrors();
  }

  // Create the widgets, etc for the gui
  buildOptionGui();
  setOptionDefaults();
}

void QuantumInputDialog::buildOptionGui()
{
  // Clear old widgets from the layout
  m_widgets.clear();
  delete m_ui.optionsWidget->layout();
  QFormLayout *form = new QFormLayout;
  m_ui.optionsWidget->setLayout(form);

  if (!m_options.contains("userOptions") ||
      !m_options["userOptions"].isObject()) {
    showError(tr("'userOptions' missing, or not an object:\n%1")
              .arg(QString(QJsonDocument(m_options).toJson())));
    return;
  }

  QJsonObject userOptions = m_options.value("userOptions").toObject();

  // Calculation Type at the top:
  if (userOptions.contains("Calculation Type"))
    addOptionRow(tr("Calculation Type"), userOptions.take("Calculation Type"));

  // Theory/basis next. Combine into one row if both present.
  bool hasTheory = userOptions.contains("Theory");
  bool hasBasis = userOptions.contains("Basis");
  if (hasTheory && hasBasis) {
    QWidget *theoryWidget = createOptionWidget(userOptions.take("Theory"));
    QWidget *basisWidget = createOptionWidget(userOptions.take("Basis"));
    QHBoxLayout *hbox = new QHBoxLayout;
    if (theoryWidget) {
      hbox->addWidget(theoryWidget);
      m_widgets.insert("Theory", theoryWidget);
    }
    if (basisWidget) {
      hbox->addWidget(basisWidget);
      m_widgets.insert("Basis", basisWidget);
    }
    hbox->addStretch();

    form->addRow(tr("Theory:"), hbox);
  }
  else {
    if (hasTheory)
      addOptionRow(tr("Theory"), userOptions["Theory"]);
    if (hasBasis)
      addOptionRow(tr("Basis"), userOptions["Basis"]);
  }

  // Other special cases:
  if (userOptions.contains("Charge"))
    addOptionRow(tr("Charge"), userOptions.take("Charge"));
  if (userOptions.contains("Multiplicity"))
    addOptionRow(tr("Multiplicity"), userOptions.take("Multiplicity"));

  // Add remaining keys at bottom.
  for (QJsonObject::const_iterator it = userOptions.constBegin(),
       itEnd = userOptions.constEnd(); it != itEnd; ++it) {
    addOptionRow(it.key(), it.value());
  }
}

void QuantumInputDialog::addOptionRow(const QString &label,
                                      const QJsonValue &option)
{
  QWidget *widget = createOptionWidget(option);
  if (!widget)
    return;

  QFormLayout *form = qobject_cast<QFormLayout*>(m_ui.optionsWidget->layout());
  if (!form) {
    qWarning() << "Cannot add option" << label
               << "to GUI -- layout is not a form.";
    widget->deleteLater();
    return;
  }
  form->addRow(label + ":", widget);
  m_widgets.insert(label, widget);
}

QWidget* QuantumInputDialog::createOptionWidget(const QJsonValue &option)
{
  /// @todo Expand this to cover clamped number ranges, strings, etc
  if (!option.isObject())
    return NULL;

  QJsonObject obj = option.toObject();

  if (!obj.contains("values") || !obj["values"].isArray())
    return NULL;

  QJsonArray valueArray = obj["values"].toArray();

  QComboBox *combo = new QComboBox;

  for (QJsonArray::const_iterator vit = valueArray.constBegin(),
       vitEnd = valueArray.constEnd(); vit != vitEnd; ++vit) {
    combo->addItem((*vit).toString());
  }
  connect(combo, SIGNAL(currentIndexChanged(int)), SLOT(updatePreviewText()));

  return combo;
}

void QuantumInputDialog::setOptionDefaults()
{
  if (!m_options.contains("userOptions") ||
      !m_options["userOptions"].isObject()) {
    showError(tr("'userOptions' missing, or not an object:\n%1")
              .arg(QString(QJsonDocument(m_options).toJson())));
    return;
  }

  QJsonObject userOptions = m_options["userOptions"].toObject();

  for (QJsonObject::ConstIterator it = userOptions.constBegin(),
       itEnd = userOptions.constEnd(); it != itEnd; ++it) {
    QString label = it.key();
    QJsonValue val = it.value();

    if (!val.isObject()) {
      qWarning() << tr("Error: value must be object for key '%1'.")
                    .arg(label);
      continue;
    }

    QJsonObject obj = val.toObject();

    int def = 0;
    if (obj["default"].isDouble())
      def = static_cast<int>(std::floor(obj["default"].toDouble() + 0.5));

    if (QComboBox *combo =
        qobject_cast<QComboBox*>(m_widgets.value(label, NULL))) {
      combo->setCurrentIndex(def);
    }
  }
}

QJsonObject QuantumInputDialog::collectOptions() const
{
  QJsonObject ret;

  foreach (QString label, m_widgets.keys()) {
    if (QComboBox *combo =
        qobject_cast<QComboBox*>(m_widgets.value(label, NULL))) {
      ret.insert(label, combo->currentText());
    }
  }

  return ret;
}

QJsonObject QuantumInputDialog::collectSettings() const
{
  QJsonObject ret;

  ret.insert("numberOfCores", m_ui.coresSpinBox->value());

  return ret;
}

void QuantumInputDialog::applyOptions(const QJsonObject &opts) const
{
  foreach (const QString &label, opts.keys()) {
    if (QComboBox *combo =
        qobject_cast<QComboBox*>(m_widgets.value(label, NULL))) {
      QString currentText = opts.value(label).toString();
      int ind = combo->findText(currentText);
      combo->blockSignals(true);
      combo->setCurrentIndex(ind);
      combo->blockSignals(false);
    }
  }
}

} // end namespace QtPlugins
} // end namespace Avogadro
