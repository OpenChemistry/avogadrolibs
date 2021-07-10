/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "inputgeneratorwidget.h"
#include "batchjob.h"
#include "molequeuedialog.h"
#include "molequeuemanager.h"
#include "ui_inputgeneratorwidget.h"

#include <avogadro/qtgui/filebrowsewidget.h>
#include <avogadro/qtgui/generichighlighter.h>
#include <avogadro/qtgui/molecule.h>

#include <QtWidgets/QComboBox>
#include <QtWidgets/QDoubleSpinBox>
#include <QtWidgets/QFileDialog>
#include <QtWidgets/QFormLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QMessageBox>
#include <QtWidgets/QSpinBox>
#include <QtWidgets/QTabWidget>
#include <QtWidgets/QTextEdit>

#include <QtCore/QDebug>
#include <QtCore/QJsonDocument>
#include <QtCore/QPointer>
#include <QtCore/QSettings>
#include <QtCore/QTimer>

namespace Avogadro {
namespace MoleQueue {

InputGeneratorWidget::InputGeneratorWidget(QWidget* parent_)
  : QtGui::JsonWidget(parent_), m_ui(new Ui::InputGeneratorWidget),
    m_updatePending(false), m_inputGenerator(QString())
{
  m_ui->setupUi(this);
  m_ui->warningTextButton->setIcon(QIcon::fromTheme("dialog-warning"));

  connectButtons();
}

InputGeneratorWidget::~InputGeneratorWidget()
{
  delete m_ui;
}

void InputGeneratorWidget::setInputGeneratorScript(const QString& scriptFile)
{
  m_inputGenerator.setScriptFilePath(scriptFile);
  m_ui->debugCheckBox->setChecked(m_inputGenerator.debug());
  updateOptions();
  resetWarningDisplay();
}

void InputGeneratorWidget::setMolecule(QtGui::Molecule* mol)
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

bool InputGeneratorWidget::configureBatchJob(BatchJob& batch) const
{
  if (!m_batchMode)
    return false;

  QJsonObject mqOpts = promptForBatchJobOptions();
  if (mqOpts.empty())
    return false;

  JobObject job;
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
    foreach (QTextEdit* edit, m_textEdits)
      edit->setReadOnly(m_batchMode);
    m_ui->computeButton->setVisible(!m_batchMode);
    m_ui->generateButton->setVisible(!m_batchMode);
    m_ui->closeButton->setText(m_batchMode ? tr("Continue") : tr("Close"));
    updateTitlePlaceholder();
  }
}

void InputGeneratorWidget::showEvent(QShowEvent* e)
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
    foreach (QTextEdit* edit, m_dirtyTextEdits)
      buffers << m_textEdits.key(edit, tr("Unknown"));
    QString message = tr("The following file(s) have been modified:\n\n%1\n\n"
                         "Would you like to overwrite your changes to reflect "
                         "the new geometry or job options?",
                         "", buffers.size())
                        .arg(buffers.join("\n"));
    int response = QMessageBox::question(
      this, tr("Overwrite modified input files?"), message,
      QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
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
    warningHtml +=
      "<h3>" + tr("Problems occurred during input generation:") + "</h3>";
    warningHtml += "<ul>";
    foreach (const QString& warning, m_inputGenerator.warningList())
      warningHtml += QString("<li>%1</li>").arg(warning);
    warningHtml += "</ul>";

    setWarning(warningHtml);
  } else {
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
  foreach (const QString& tabName, m_textEdits.keys()) {
    if (!fileNames.contains(tabName)) {
      QTextEdit* edit = m_textEdits.value(tabName);
      int index = m_ui->tabWidget->indexOf(edit);
      m_ui->tabWidget->removeTab(index);
      m_textEdits.remove(tabName);
      delete edit;
    }
  }

  // Add new tabs
  foreach (const QString& fileName, fileNames) {
    if (m_textEdits.contains(fileName))
      continue;
    QTextEdit* edit = new QTextEdit(this);
    edit->setObjectName(fileName);
    edit->setFontFamily("monospace");
    connect(edit, SIGNAL(textChanged()), this, SLOT(textEditModified()));
    m_ui->tabWidget->addTab(edit, fileName);
    m_textEdits.insert(fileName, edit);
  }

  // Sort and update
  int index = 0;
  foreach (const QString& fileName, fileNames) {
    QTextEdit* edit = m_textEdits.value(fileName);
    int tabIndex = m_ui->tabWidget->indexOf(edit);
    if (tabIndex != index) {
      m_ui->tabWidget->removeTab(tabIndex);
      m_ui->tabWidget->insertTab(index, edit, fileName);
    }

    QtGui::GenericHighlighter* highlighter =
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
  MoleQueueManager& mqManager = MoleQueueManager::instance();
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
  int numCores =
    optionString("Processor Cores", coresString) ? coresString.toInt() : 1;

  JobObject job;
  job.setProgram(m_inputGenerator.displayName());
  job.setDescription(description);
  job.setValue("numberOfCores", numCores);
  for (QMap<QString, QTextEdit*>::const_iterator it = m_textEdits.constBegin(),
                                                 itEnd = m_textEdits.constEnd();
       it != itEnd; ++it) {
    QString fileName = it.key();
    if (fileName != mainFileName)
      job.appendAdditionalInputFile(fileName, it.value()->toPlainText());
    else
      job.setInputFile(fileName, it.value()->toPlainText());
  }

  MoleQueueDialog::SubmitStatus result = MoleQueueDialog::submitJob(
    this, tr("Submit %1 Calculation").arg(m_inputGenerator.displayName()), job,
    MoleQueueDialog::WaitForSubmissionResponse |
      MoleQueueDialog::SelectProgramFromTemplate);

  switch (result) {
    default:
    case MoleQueueDialog::SubmissionSuccessful:
    case MoleQueueDialog::SubmissionFailed:
    case MoleQueueDialog::SubmissionAttempted:
    case MoleQueueDialog::SubmissionAborted:
      // The dialog handles these cases adequately, we don't need to do
      // anything.
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
      if (QDialog* dlg = qobject_cast<QDialog*>(parent()))
        dlg->hide();
      break;
  }
}

void InputGeneratorWidget::setWarning(const QString& warn)
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

void InputGeneratorWidget::showError(const QString& err)
{
  qWarning() << err;

  QWidget* theParent =
    this->isVisible() ? this : qobject_cast<QWidget*>(parent());
  QDialog dlg(theParent);
  QVBoxLayout* vbox = new QVBoxLayout();
  QLabel* label = new QLabel(tr("An error has occurred:"));
  vbox->addWidget(label);
  QTextBrowser* textBrowser = new QTextBrowser();

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
  if (QTextEdit* edit = qobject_cast<QTextEdit*>(sender())) {
    if (edit->document()->isModified()) {
      if (!m_dirtyTextEdits.contains(edit))
        m_dirtyTextEdits << edit;
    } else {
      m_dirtyTextEdits.removeOne(edit);
    }
  }
}

void InputGeneratorWidget::updateTitlePlaceholder()
{
  if (QLineEdit* titleEdit =
        qobject_cast<QLineEdit*>(m_widgets.value("Title", nullptr))) {
    titleEdit->setPlaceholderText(generateJobTitle());
  }
}

QString InputGeneratorWidget::settingsKey(const QString& identifier) const
{
  return QString("quantumInput/%1/%2")
    .arg(m_inputGenerator.displayName(), identifier);
}

void InputGeneratorWidget::saveSingleFile(const QString& fileName)
{
  QSettings settings;
  QString filePath = settings.value(settingsKey("outputDirectory")).toString();
  if (filePath.isEmpty())
    filePath = QDir::homePath();
  filePath = QFileDialog::getSaveFileName(this, tr("Select output filename"),
                                          filePath + "/" + fileName);

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

  QTextEdit* edit = m_textEdits.value(fileName, nullptr);
  if (!edit) {
    showError(tr("Internal error: could not find text widget for filename '%1'")
                .arg(fileName));
    return;
  }

  QFile file(filePath);
  bool success = false;
  if (file.open(QFile::WriteOnly | QFile::Text)) {
    if (file.write(edit->toPlainText().toLocal8Bit()) > 0) {
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

    foreach (const QString& fileName, fileNames) {
      QFileInfo info(dir.absoluteFilePath(fileName));

      if (info.exists()) {
        errors
          << tr("%1: File will be overwritten.").arg(info.absoluteFilePath());
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
        // If a fatal error occurred, it will be last one in the list. Pop it
        // off and tell the user that it was the reason we had to stop.
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
                           QMessageBox::Yes | QMessageBox::No, QMessageBox::No);

    if (reply != QMessageBox::Yes)
      return;
  }

  foreach (const QString& fileName, fileNames) {
    QTextEdit* edit = m_textEdits.value(fileName);
    QFile file(dir.absoluteFilePath(fileName));
    bool success = false;
    if (file.open(QFile::WriteOnly | QFile::Text)) {
      if (file.write(edit->toPlainText().toLocal8Bit()) > 0) {
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
  MoleQueueManager& mqManager = MoleQueueManager::instance();
  if (!mqManager.connectIfNeeded()) {
    QMessageBox::information(this->parentWidget(),
                             tr("Cannot connect to MoleQueue"),
                             tr("Cannot connect to MoleQueue server. Please "
                                "ensure that it is running and try again."));
    return QJsonObject();
  }

  QString coresString;
  int numCores =
    optionString("Processor Cores", coresString) ? coresString.toInt() : 1;

  JobObject job;
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
  connect(m_ui->debugCheckBox, SIGNAL(toggled(bool)), &m_inputGenerator,
          SLOT(setDebug(bool)));
  connect(m_ui->debugCheckBox, SIGNAL(toggled(bool)),
          SLOT(updatePreviewText()));
  connect(m_ui->defaultsButton, SIGNAL(clicked()), SLOT(defaultsClicked()));
  connect(m_ui->generateButton, SIGNAL(clicked()), SLOT(generateClicked()));
  connect(m_ui->computeButton, SIGNAL(clicked()), SLOT(computeClicked()));
  connect(m_ui->closeButton, SIGNAL(clicked()), SIGNAL(closeClicked()));
  connect(m_ui->warningTextButton, SIGNAL(clicked()),
          SLOT(toggleWarningText()));
}

void InputGeneratorWidget::updateOptions()
{
  m_options = m_inputGenerator.options();

  if (m_inputGenerator.hasErrors()) {
    showError(m_inputGenerator.errorList().join("\n\n"));
    m_inputGenerator.clearErrors();
  }

  m_centralWidget = m_ui->optionsWidget;

  // Create the widgets, etc for the gui
  buildOptionGui();
  setOptionDefaults();
}

} // namespace MoleQueue
} // namespace Avogadro
