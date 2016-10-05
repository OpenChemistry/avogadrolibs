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

#include "inputgeneratorwidget.h"
#include "ui_inputgeneratorwidget.h"
#include "molequeuedialog.h"
#include "molequeuemanager.h"
#include "batchjob.h"

#include <avogadro/qtgui/filebrowsewidget.h>
#include <avogadro/qtgui/generichighlighter.h>
#include <avogadro/qtgui/molecule.h>

#include <molequeue/client/jobobject.h>

#include <QtWidgets/QComboBox>
#include <QtWidgets/QFileDialog>
#include <QtWidgets/QFormLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QMessageBox>
#include <QtWidgets/QSpinBox>
#include <QtWidgets/QDoubleSpinBox>
#include <QtWidgets/QTextEdit>

#include <QtCore/QJsonDocument>
#include <QtCore/QDebug>
#include <QtCore/QPointer>
#include <QtCore/QSettings>
#include <QtCore/QTimer>

namespace Avogadro {
namespace MoleQueue {

using ::MoleQueue::JobObject;

InputGeneratorWidget::InputGeneratorWidget(QWidget *parent_) :
  QWidget(parent_),
  m_ui(new Ui::InputGeneratorWidget),
  m_molecule(NULL),
  m_updatePending(false),
  m_batchMode(false),
  m_inputGenerator(QString())
{
  m_ui->setupUi(this);
  m_ui->warningTextButton->setIcon(QIcon::fromTheme("dialog-warning"));

  connectButtons();
}

InputGeneratorWidget::~InputGeneratorWidget()
{
  delete m_ui;
}

void InputGeneratorWidget::setInputGeneratorScript(const QString &scriptFile)
{
  m_inputGenerator.setScriptFilePath(scriptFile);
  m_ui->debugCheckBox->setChecked(m_inputGenerator.debug());
  updateOptions();
  resetWarningDisplay();
}

void InputGeneratorWidget::setMolecule(QtGui::Molecule *mol)
{
  if (mol == m_molecule)
    return;

  if (m_molecule)
    m_molecule->disconnect(this);

  m_molecule = mol;

  if (mol) {
    connect(mol, SIGNAL(changed(unsigned int)), SLOT(updatePreviewText()));
    connect(mol, SIGNAL(changed(unsigned int)), SLOT(updateTitlePlaceholder()));
  }

  updateTitlePlaceholder();
  updatePreviewTextImmediately();
}

bool InputGeneratorWidget::configureBatchJob(BatchJob &batch) const
{
  if (!m_batchMode)
    return false;

  QJsonObject mqOpts = promptForBatchJobOptions();
  if (mqOpts.empty())
    return false;

  MoleQueue::JobObject job;
  job.fromJson(mqOpts);

  QJsonObject calcOpts;
  calcOpts[QLatin1String("options")] = collectOptions();

  // Set job description from title:
  QString description;
  if (!optionString("Title", description) || description.isEmpty())
    description = generateJobTitle();
  job.setDescription(description);

  mqOpts = job.json();

  batch.setInputGeneratorOptions(calcOpts);
  batch.setMoleQueueOptions(mqOpts);

  return true;
}

void InputGeneratorWidget::setBatchMode(bool m)
{
  if (m_batchMode != m) {
    m_batchMode = m;
    foreach (QTextEdit *edit, m_textEdits)
      edit->setReadOnly(m_batchMode);
    m_ui->computeButton->setVisible(!m_batchMode);
    m_ui->generateButton->setVisible(!m_batchMode);
    m_ui->closeButton->setText(m_batchMode ? tr("Continue") : tr("Close"));
    updateTitlePlaceholder();
  }
}

void InputGeneratorWidget::showEvent(QShowEvent *e)
{
  QWidget::showEvent(e);

  // Update the preview text if an update was requested while hidden. Use a
  // single shot to allow the dialog to show before popping up any warnings.
  if (m_updatePending)
    QTimer::singleShot(0, this, SLOT(updatePreviewTextImmediately()));
}

void InputGeneratorWidget::updatePreviewText()
{
  if (m_updatePending)
    return;

  m_updatePending = true;
  QTimer::singleShot(250, this, SLOT(updatePreviewTextImmediately()));
}

void InputGeneratorWidget::updatePreviewTextImmediately()
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
      // Prevent updates while restoring the option cache:
      bool oldUpdatePending = m_updatePending;
      m_updatePending = true;
      // Restore cached options.
      applyOptions(m_optionCache);
      m_updatePending = oldUpdatePending;
      return;
    }
  }

  if (!m_molecule)
    return;

  // Generate the input files
  QJsonObject inputOptions;
  inputOptions["options"] = collectOptions();
  bool success = m_inputGenerator.generateInput(inputOptions, *m_molecule);

  if (!m_inputGenerator.warningList().isEmpty()) {
    QString warningHtml;
    warningHtml += "<style>li{color:red;}h3{font-weight:bold;}</style>";
    warningHtml += "<h3>" + tr("Problems occured during input generation:")
        + "</h3>";
    warningHtml += "<ul>";
    foreach (const QString &warning, m_inputGenerator.warningList())
      warningHtml += QString ("<li>%1</li>").arg(warning);
    warningHtml += "</ul>";

    setWarning(warningHtml);
  }
  else {
    resetWarningDisplay();
  }

  if (!success) {
    showError(m_inputGenerator.errorList().join("\n\n"));
    m_inputGenerator.clearErrors();
    return;
  }

  // Store the currently displayed tab
  QPointer<QWidget> currentWidget(m_ui->tabWidget->currentWidget());

  // Ensure that the correct tabs are shown:
  QStringList fileNames = m_inputGenerator.fileNames();
  // Remove unneeded tabs
  foreach (const QString &tabName, m_textEdits.keys()) {
    if (!fileNames.contains(tabName)) {
      QTextEdit *edit = m_textEdits.value(tabName);
      int index = m_ui->tabWidget->indexOf(edit);
      m_ui->tabWidget->removeTab(index);
      m_textEdits.remove(tabName);
      delete edit;
    }
  }

  // Add new tabs
  foreach (const QString &fileName, fileNames) {
    if (m_textEdits.contains(fileName))
      continue;
    QTextEdit *edit = new QTextEdit(this);
    edit->setObjectName(fileName);
    edit->setFontFamily("monospace");
    connect(edit, SIGNAL(textChanged()), this, SLOT(textEditModified()));
    m_ui->tabWidget->addTab(edit, fileName);
    m_textEdits.insert(fileName, edit);
  }

  // Sort and update
  int index = 0;
  foreach (const QString &fileName, fileNames) {
    QTextEdit *edit = m_textEdits.value(fileName);
    int tabIndex = m_ui->tabWidget->indexOf(edit);
    if (tabIndex != index) {
      m_ui->tabWidget->removeTab(tabIndex);
      m_ui->tabWidget->insertTab(index, edit, fileName);
    }

    QtGui::GenericHighlighter *highlighter =
            m_inputGenerator.createFileHighlighter(fileName);
    if (highlighter) {
      highlighter->setParent(this);
      highlighter->setDocument(edit->document());
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
    m_ui->tabWidget->setCurrentWidget(currentWidget);
}

void InputGeneratorWidget::defaultsClicked()
{
  setOptionDefaults();
  updatePreviewTextImmediately();
}

void InputGeneratorWidget::generateClicked()
{
  if (m_textEdits.size() == 1)
    saveSingleFile(m_textEdits.keys().first());
  else if (m_textEdits.size() > 1)
    saveDirectory();
  else
    showError(tr("No input files to save!"));
}

void InputGeneratorWidget::computeClicked()
{
  // Verify that molequeue is running:
  MoleQueueManager &mqManager = MoleQueueManager::instance();
  if (!mqManager.connectIfNeeded()) {
    QMessageBox::information(this, tr("Cannot connect to MoleQueue"),
                             tr("Cannot connect to MoleQueue server. Please "
                                "ensure that it is running and try again."));
    return;
  }

  // Collect info for the MoleQueueDialog:
  const QString mainFileName = m_inputGenerator.mainFileName();

  QString description;
  if (!optionString("Title", description) || description.isEmpty())
    description = generateJobTitle();

  QString coresString;
  int numCores = optionString("Processor Cores", coresString)
      ? coresString.toInt() : 1;

  JobObject job;
  job.setProgram(m_inputGenerator.displayName());
  job.setDescription(description);
  job.setValue("numberOfCores", numCores);
  for (QMap<QString, QTextEdit*>::const_iterator it = m_textEdits.constBegin(),
       itEnd = m_textEdits.constEnd(); it != itEnd; ++it) {
    QString fileName = it.key();
    if (fileName != mainFileName)
      job.appendAdditionalInputFile(fileName, it.value()->toPlainText());
    else
      job.setInputFile(fileName, it.value()->toPlainText());
  }

  MoleQueueDialog::SubmitStatus result =
      MoleQueueDialog::submitJob(this,
                                 tr("Submit %1 Calculation")
                                 .arg(m_inputGenerator.displayName()),
                                 job, MoleQueueDialog::WaitForSubmissionResponse
                                 | MoleQueueDialog::SelectProgramFromTemplate);

  switch (result) {
  default:
  case MoleQueueDialog::SubmissionSuccessful:
  case MoleQueueDialog::SubmissionFailed:
  case MoleQueueDialog::SubmissionAttempted:
  case MoleQueueDialog::SubmissionAborted:
    // The dialog handles these cases adequately, we don't need to do anything.
    break;

  case MoleQueueDialog::JobFailed:
    // Inform the user:
    QMessageBox::information(this, tr("Job Failed"),
                             tr("The job did not complete successfully."),
                             QMessageBox::Ok);
    break;

  case MoleQueueDialog::JobFinished:
    // Let the world know that the job is ready to open. job has been
    // overwritten with the final job details.
    emit openJobOutput(job);
    // Hide the parent if it's a dialog:
    if (QDialog *dlg = qobject_cast<QDialog*>(parent()))
      dlg->hide();
    break;
  }
}

void InputGeneratorWidget::setWarning(const QString &warn)
{
  qWarning() << tr("Script returns warnings:\n") << warn;

  m_ui->warningText->setText(warn);
  m_ui->warningBox->show();
}

void InputGeneratorWidget::toggleWarningText()
{
  if (m_ui->warningText->isVisible())
    hideWarningText();
  else
    showWarningText();
}

void InputGeneratorWidget::showWarningText()
{
  m_ui->warningText->show();
  m_ui->warningTextButton->setText(tr("Hide &Warnings"));
}

void InputGeneratorWidget::hideWarningText()
{
  m_ui->warningText->hide();
  m_ui->warningTextButton->setText(tr("Show &Warnings"));
}

void InputGeneratorWidget::resetWarningDisplay()
{
  m_ui->warningBox->hide();
  showWarningText();
}

void InputGeneratorWidget::showError(const QString &err)
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

void InputGeneratorWidget::textEditModified()
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

void InputGeneratorWidget::updateTitlePlaceholder()
{
  if (QLineEdit *titleEdit =
        qobject_cast<QLineEdit*>(m_widgets.value("Title", NULL))) {
    titleEdit->setPlaceholderText(generateJobTitle());
  }
}

QString InputGeneratorWidget::settingsKey(const QString &identifier) const
{
  return QString("quantumInput/%1/%2").arg(m_inputGenerator.displayName(),
                                           identifier);
}

void InputGeneratorWidget::saveSingleFile(const QString &fileName)
{
  QSettings settings;
  QString filePath = settings.value(settingsKey("outputDirectory")).toString();
  if (filePath.isEmpty())
    filePath = QDir::homePath();
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

void InputGeneratorWidget::saveDirectory()
{
  QSettings settings;
  QString directory = settings.value(settingsKey("outputDirectory")).toString();
  if (directory.isEmpty())
    directory = QDir::homePath();
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

QJsonObject InputGeneratorWidget::promptForBatchJobOptions() const
{
  // Verify that molequeue is running:
  MoleQueueManager &mqManager = MoleQueueManager::instance();
  if (!mqManager.connectIfNeeded()) {
    QMessageBox::information(this->parentWidget(),
                             tr("Cannot connect to MoleQueue"),
                             tr("Cannot connect to MoleQueue server. Please "
                                "ensure that it is running and try again."));
    return QJsonObject();
  }

  QString coresString;
  int numCores = optionString("Processor Cores", coresString)
      ? coresString.toInt() : 1;

  MoleQueue::JobObject job;
  job.setProgram(m_inputGenerator.displayName());
  job.setValue("numberOfCores", numCores);

  if (!MoleQueueDialog::promptForJobOptions(this->parentWidget(),
                                            tr("Configure Job"), job)) {
    return QJsonObject();
  }

  return job.json();
}

void InputGeneratorWidget::connectButtons()
{
  connect(m_ui->debugCheckBox, SIGNAL(toggled(bool)),
          &m_inputGenerator, SLOT(setDebug(bool)));
  connect(m_ui->debugCheckBox, SIGNAL(toggled(bool)),
          SLOT(updatePreviewText()));
  connect(m_ui->defaultsButton, SIGNAL(clicked()), SLOT(defaultsClicked()));
  connect(m_ui->generateButton, SIGNAL(clicked()), SLOT(generateClicked()));
  connect(m_ui->computeButton, SIGNAL(clicked()), SLOT(computeClicked()));
  connect(m_ui->closeButton, SIGNAL(clicked()), SIGNAL(closeClicked()));
  connect(m_ui->warningTextButton, SIGNAL(clicked()),
          SLOT(toggleWarningText()));
}

QString InputGeneratorWidget::lookupOptionType(const QString &name) const
{
  if (!m_options.contains("userOptions") ||
      !m_options["userOptions"].isObject()) {
    qWarning() << tr("'userOptions' missing, or not an object.");
    return QString();
  }

  QJsonObject userOptions = m_options["userOptions"].toObject();

  if (!userOptions.contains(name)) {
    qWarning() << tr("Option '%1' not found in userOptions.").arg(name);
    return QString();
  }

  if (!userOptions.value(name).isObject()) {
    qWarning() << tr("Option '%1' does not refer to an object.");
    return QString();
  }

  QJsonObject obj = userOptions[name].toObject();

  if (!obj.contains("type") ||
      !obj.value("type").isString()) {
    qWarning() << tr("'type' is not a string for option '%1'.").arg(name);
    return QString();
  }

  return obj["type"].toString();
}

void InputGeneratorWidget::updateOptions()
{
  m_options = m_inputGenerator.options();

  if (m_inputGenerator.hasErrors()) {
    showError(m_inputGenerator.errorList().join("\n\n"));
    m_inputGenerator.clearErrors();
  }

  // Create the widgets, etc for the gui
  buildOptionGui();
  setOptionDefaults();
}

void InputGeneratorWidget::buildOptionGui()
{
  // Clear old widgets from the layout
  m_widgets.clear();
  delete m_ui->optionsWidget->layout();
  QFormLayout *form = new QFormLayout;
  m_ui->optionsWidget->setLayout(form);

  if (!m_options.contains("userOptions") ||
      !m_options["userOptions"].isObject()) {
    showError(tr("'userOptions' missing, or not an object:\n%1")
              .arg(QString(QJsonDocument(m_options).toJson())));
    return;
  }

  QJsonObject userOptions = m_options.value("userOptions").toObject();

  // Title first
  if (userOptions.contains("Title"))
    addOptionRow(tr("Title"), userOptions.take("Title"));

  // File basename next:
  if (userOptions.contains("Filename Base"))
    addOptionRow(tr("Filename Base"), userOptions.take("Filename Base"));

  // Number of cores next:
  if (userOptions.contains("Processor Cores"))
    addOptionRow(tr("Processor Cores"), userOptions.take("Processor Cores"));

  // Calculation Type next:
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
      theoryWidget->setObjectName("Theory");
      hbox->addWidget(theoryWidget);
      m_widgets.insert("Theory", theoryWidget);
    }
    if (basisWidget) {
      basisWidget->setObjectName("Basis");
      hbox->addWidget(basisWidget);
      m_widgets.insert("Basis", basisWidget);
    }
    hbox->addStretch();

    form->addRow(tr("Theory:"), hbox);
  }
  else {
    if (hasTheory)
      addOptionRow(tr("Theory"), userOptions.take("Theory"));
    if (hasBasis)
      addOptionRow(tr("Basis"), userOptions.take("Basis"));
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

  // Make connections for standard options:
  if (QComboBox *combo = qobject_cast<QComboBox*>(
        m_widgets.value("Calculation Type", NULL))) {
    connect(combo, SIGNAL(currentIndexChanged(int)),
            SLOT(updateTitlePlaceholder()));
  }
  if (QComboBox *combo = qobject_cast<QComboBox*>(
        m_widgets.value("Theory", NULL))) {
    connect(combo, SIGNAL(currentIndexChanged(int)),
            SLOT(updateTitlePlaceholder()));
  }
  if (QComboBox *combo = qobject_cast<QComboBox*>(
        m_widgets.value("Basis", NULL))) {
    connect(combo, SIGNAL(currentIndexChanged(int)),
            SLOT(updateTitlePlaceholder()));
  }
}

void InputGeneratorWidget::addOptionRow(const QString &label,
                                        const QJsonValue &option)
{
  QWidget *widget = createOptionWidget(option);
  if (!widget)
    return;

  QFormLayout *form = qobject_cast<QFormLayout*>(m_ui->optionsWidget->layout());
  if (!form) {
    qWarning() << "Cannot add option" << label
               << "to GUI -- layout is not a form.";
    widget->deleteLater();
    return;
  }

  // For lookups during unit testing:
  widget->setObjectName(label);

  form->addRow(label + ":", widget);
  m_widgets.insert(label, widget);
}

QWidget *InputGeneratorWidget::createOptionWidget(const QJsonValue &option)
{
  if (!option.isObject())
    return NULL;

  QJsonObject obj = option.toObject();

  if (!obj.contains("type") ||
      !obj.value("type").isString())
    return NULL;

  QString type = obj["type"].toString();

  if (type == "stringList")
    return createStringListWidget(obj);
  else if (type == "string")
    return createStringWidget(obj);
  else if (type == "filePath")
    return createFilePathWidget(obj);
  else if (type == "integer")
    return createIntegerWidget(obj);
  else if (type == "float")
    return createFloatWidget(obj);
  else if (type == "boolean")
    return createBooleanWidget(obj);

  qDebug() << "Unrecognized option type:" << type;
  return NULL;
}

QWidget *InputGeneratorWidget::createStringListWidget(const QJsonObject &obj)
{
  if (!obj.contains("values") || !obj["values"].isArray()) {
    qDebug() << "QuantumInputDialog::createStringListWidget()"
                "values missing, or not array!";
    return NULL;
  }

  QJsonArray valueArray = obj["values"].toArray();

  QComboBox *combo = new QComboBox(this);

  for (QJsonArray::const_iterator vit = valueArray.constBegin(),
       vitEnd = valueArray.constEnd(); vit != vitEnd; ++vit) {
    if ((*vit).isString())
      combo->addItem((*vit).toString());
    else
      qDebug() << "Cannot convert value to string for stringList:" << *vit;
  }
  connect(combo, SIGNAL(currentIndexChanged(int)), SLOT(updatePreviewText()));

  return combo;
}

QWidget *InputGeneratorWidget::createStringWidget(const QJsonObject &obj)
{
  Q_UNUSED(obj);
  QLineEdit *edit = new QLineEdit(this);
  connect(edit, SIGNAL(textChanged(QString)), SLOT(updatePreviewText()));
  return edit;
}

QWidget *InputGeneratorWidget::createFilePathWidget(const QJsonObject &obj)
{
  Q_UNUSED(obj);
  QtGui::FileBrowseWidget *fileBrowse = new QtGui::FileBrowseWidget(this);
  connect(fileBrowse, SIGNAL(fileNameChanged(QString)),
          SLOT(updatePreviewText()));
  return fileBrowse;
}

QWidget *InputGeneratorWidget::createIntegerWidget(const QJsonObject &obj)
{
  QSpinBox *spin = new QSpinBox(this);
  if (obj.contains("minimum") &&
      obj.value("minimum").isDouble()) {
    spin->setMinimum(static_cast<int>(obj["minimum"].toDouble() + 0.5));
  }
  if (obj.contains("maximum") &&
      obj.value("maximum").isDouble()) {
    spin->setMaximum(static_cast<int>(obj["maximum"].toDouble() + 0.5));
  }
  if (obj.contains("prefix") &&
      obj.value("prefix").isString()) {
    spin->setPrefix(obj["prefix"].toString());
  }
  if (obj.contains("suffix") &&
      obj.value("suffix").isString()) {
    spin->setSuffix(obj["suffix"].toString());
  }
  connect(spin, SIGNAL(valueChanged(int)), SLOT(updatePreviewText()));
  return spin;
}

QWidget *InputGeneratorWidget::createFloatWidget(const QJsonObject &obj)
{
  QDoubleSpinBox *spin = new QDoubleSpinBox(this);
  if (obj.contains("minimum") &&
      obj.value("minimum").isDouble()) {
    spin->setMinimum(obj["minimum"].toDouble());
  }
  if (obj.contains("maximum") &&
      obj.value("maximum").isDouble()) {
    spin->setMaximum(obj["maximum"].toDouble());
  }
  if (obj.contains("precision") &&
      obj.value("precision").isDouble()) {
    spin->setDecimals(static_cast<int>(obj["precision"].toDouble()));
  }
  if (obj.contains("prefix") &&
      obj.value("prefix").isString()) {
    spin->setPrefix(obj["prefix"].toString());
  }
  if (obj.contains("suffix") &&
      obj.value("suffix").isString()) {
    spin->setSuffix(obj["suffix"].toString());
  }
  connect(spin, SIGNAL(valueChanged(double)), SLOT(updatePreviewText()));
  return spin;
}

QWidget *InputGeneratorWidget::createBooleanWidget(const QJsonObject &obj)
{
  Q_UNUSED(obj);
  QCheckBox *checkBox = new QCheckBox(this);
  connect(checkBox, SIGNAL(toggled(bool)), SLOT(updatePreviewText()));
  return checkBox;
}

void InputGeneratorWidget::setOptionDefaults()
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
    if (obj.contains("default"))
      setOption(label, obj["default"]);
    else if (m_inputGenerator.debug())
      qWarning() << tr("Default value missing for option '%1'.").arg(label);
  }
}

void InputGeneratorWidget::setOption(const QString &name,
                                     const QJsonValue &defaultValue)
{
  QString type = lookupOptionType(name);

  if (type == "stringList")
    return setStringListOption(name, defaultValue);
  else if (type == "string")
    return setStringOption(name, defaultValue);
  else if (type == "filePath")
    return setFilePathOption(name, defaultValue);
  else if (type == "integer")
    return setIntegerOption(name, defaultValue);
  else if (type == "boolean")
    return setBooleanOption(name, defaultValue);

  qWarning() << tr("Unrecognized option type '%1' for option '%2'.")
                .arg(type).arg(name);
  return;
}

void InputGeneratorWidget::setStringListOption(const QString &name,
                                               const QJsonValue &value)
{
  QComboBox *combo = qobject_cast<QComboBox*>(m_widgets.value(name, NULL));
  if (!combo) {
    qWarning() << tr("Error setting default for option '%1'. "
                     "Bad widget type.")
                  .arg(name);
    return;
  }

  if (!value.isDouble() && !value.isString()) {
    qWarning() << tr("Error setting default for option '%1'. "
                     "Bad default value:")
                  .arg(name)
               << value;
    return;
  }

  int index = -1;
  if (value.isDouble())
    index = static_cast<int>(value.toDouble() + 0.5);
  else if (value.isString())
    index = combo->findText(value.toString());

  if (index < 0) {
    qWarning() << tr("Error setting default for option '%1'. "
                     "Could not find valid combo entry index from value:")
                  .arg(name)
               << value;
    return;
  }

  combo->setCurrentIndex(index);
}

void InputGeneratorWidget::setStringOption(const QString &name,
                                           const QJsonValue &value)
{
  QLineEdit *lineEdit = qobject_cast<QLineEdit*>(m_widgets.value(name, NULL));
  if (!lineEdit) {
    qWarning() << tr("Error setting default for option '%1'. "
                     "Bad widget type.")
                  .arg(name);
    return;
  }

  if (!value.isString()) {
    qWarning() << tr("Error setting default for option '%1'. "
                     "Bad default value:")
                  .arg(name)
               << value;
    return;
  }

  lineEdit->setText(value.toString());
}

void InputGeneratorWidget::setFilePathOption(const QString &name,
                                             const QJsonValue &value)
{
  QtGui::FileBrowseWidget *fileBrowse =
      qobject_cast<QtGui::FileBrowseWidget*>(m_widgets.value(name, NULL));
  if (!fileBrowse) {
    qWarning() << tr("Error setting default for option '%1'. "
                     "Bad widget type.")
                  .arg(name);
    return;
  }

  if (!value.isString()) {
    qWarning() << tr("Error setting default for option '%1'. "
                     "Bad default value:")
                  .arg(name)
               << value;
    return;
  }

  fileBrowse->setFileName(value.toString());
}

void InputGeneratorWidget::setIntegerOption(const QString &name,
                                            const QJsonValue &value)
{
  QSpinBox *spin = qobject_cast<QSpinBox*>(m_widgets.value(name, NULL));
  if (!spin) {
    qWarning() << tr("Error setting default for option '%1'. "
                     "Bad widget type.")
                  .arg(name);
    return;
  }

  if (!value.isDouble()) {
    qWarning() << tr("Error setting default for option '%1'. "
                     "Bad default value:")
                  .arg(name)
               << value;
    return;
  }

  int intVal = static_cast<int>(value.toDouble() + 0.5);
  spin->setValue(intVal);
}

void InputGeneratorWidget::setBooleanOption(const QString &name,
                                            const QJsonValue &value)
{
  QCheckBox *checkBox = qobject_cast<QCheckBox*>(m_widgets.value(name, NULL));
  if (!checkBox) {
    qWarning() << tr("Error setting default for option '%1'. "
                     "Bad widget type.")
                  .arg(name);
    return;
  }

  if (!value.isBool()) {
    qWarning() << tr("Error setting default for option '%1'. "
                     "Bad default value:")
                  .arg(name)
               << value;
    return;
  }

  checkBox->setChecked(value.toBool());
}

bool InputGeneratorWidget::optionString(const QString &option,
                                        QString &value) const
{
  QWidget *widget = m_widgets.value(option, NULL);
  bool retval = false;
  value.clear();

  if (QLineEdit *edit = qobject_cast<QLineEdit*>(widget)) {
    retval = true;
    value = edit->text();
  }
  else if (QComboBox *combo = qobject_cast<QComboBox*>(widget)) {
    retval = true;
    value = combo->currentText();
  }
  else if (QSpinBox *spinbox = qobject_cast<QSpinBox*>(widget)) {
    retval = true;
    value = QString::number(spinbox->value());
  }
  else if (QDoubleSpinBox *dspinbox = qobject_cast<QDoubleSpinBox*>(widget)) {
    retval = true;
    value = QString::number(dspinbox->value());
  }
  else if (QtGui::FileBrowseWidget *fileBrowse
           = qobject_cast<QtGui::FileBrowseWidget*>(widget)) {
    retval = true;
    value = fileBrowse->fileName();
  }

  return retval;
}

QJsonObject InputGeneratorWidget::collectOptions() const
{
  QJsonObject ret;

  foreach (QString label, m_widgets.keys()) {
    QWidget *widget = m_widgets.value(label, NULL);
    if (QComboBox *combo = qobject_cast<QComboBox*>(widget)) {
      ret.insert(label, combo->currentText());
    }
    else if (QLineEdit *lineEdit = qobject_cast<QLineEdit*>(widget)) {
      QString value(lineEdit->text());
      if (value.isEmpty() && label == "Title")
        value = generateJobTitle();
      ret.insert(label, value);
    }
    else if (QSpinBox *spinBox = qobject_cast<QSpinBox*>(widget)) {
      ret.insert(label, spinBox->value());
    }
    else if (QCheckBox *checkBox = qobject_cast<QCheckBox*>(widget)) {
      ret.insert(label, checkBox->isChecked());
    }
    else if (QtGui::FileBrowseWidget *fileBrowse
             = qobject_cast<QtGui::FileBrowseWidget*>(widget)) {
      ret.insert(label, fileBrowse->fileName());
    }
    else {
      qWarning() << tr("Unhandled widget in collectOptions for option '%1'.")
                    .arg(label);
    }
  }

  return ret;
}

void InputGeneratorWidget::applyOptions(const QJsonObject &opts)
{
  foreach (const QString &label, opts.keys())
    setOption(label, opts[label]);
}

QString InputGeneratorWidget::generateJobTitle() const
{
  QString calculation;
  bool haveCalculation(optionString("Calculation Type", calculation));

  QString theory;
  bool haveTheory(optionString("Theory", theory));

  QString basis;
  bool haveBasis(optionString("Basis", basis));

  // Merge theory/basis into theory
  if (haveBasis) {
    if (haveTheory)
      theory += "/";
    theory += basis;
    theory.replace(QRegExp("\\s+"), "");
    haveTheory = true;
  }

  if (m_batchMode) {
    QString result;
    result = haveCalculation ? calculation : QString();
    result += haveTheory ? (result.size() != 0 ? " | " : QString()) + theory
                         : QString();
    return result;
  }

  QString formula(m_molecule ? QString::fromStdString(m_molecule->formula())
                             : tr("[no molecule]"));

  return QString("%1%2%3").arg(formula)
      .arg(haveCalculation ? " | " + calculation : QString())
      .arg(haveTheory      ? " | " + theory      : QString());
}

} // namespace MoleQueue
} // namespace Avogadro
