/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "filebrowsewidget.h"

#include <QFileSystemModel>
#include <QtWidgets/QCompleter>
#include <QtWidgets/QFileDialog>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QPushButton>

#include <QFileInfo>
#include <QProcessEnvironment>

namespace Avogadro::QtGui {

FileBrowseWidget::FileBrowseWidget(QWidget* theParent)
  : QWidget(theParent), m_mode(), // use the setter to initialize filters.
    m_valid(false), m_fileSystemModel(new QFileSystemModel(this)),
    m_button(new QPushButton(tr("Browse"))), m_edit(new QLineEdit)
{
  auto* hbox = new QHBoxLayout;
  hbox->addWidget(m_edit);
  hbox->addWidget(m_button);
  setLayout(hbox);

  // Focus config
  setFocusPolicy(Qt::StrongFocus);
  setFocusProxy(m_edit);
  setTabOrder(m_edit, m_button);

  // Setup completion
  m_fileSystemModel->setRootPath(QDir::rootPath());
  auto* fsCompleter = new QCompleter(m_fileSystemModel, this);
  m_edit->setCompleter(fsCompleter);

  // Connections:
  connect(m_button, SIGNAL(clicked()), SLOT(browse()));
  connect(m_edit, SIGNAL(textChanged(QString)), SLOT(testFileName()));
  connect(m_edit, SIGNAL(textChanged(QString)),
          SIGNAL(fileNameChanged(QString)));

  setMode(ExistingFile);
}

FileBrowseWidget::~FileBrowseWidget() {}

QString FileBrowseWidget::fileName() const
{
  return m_edit->text();
}

QPushButton* FileBrowseWidget::browseButton() const
{
  return m_button;
}

QLineEdit* FileBrowseWidget::lineEdit() const
{
  return m_edit;
}

void FileBrowseWidget::setFileName(const QString& fname)
{
  m_edit->setText(fname);
}

void FileBrowseWidget::browse()
{
  QString fname(fileName());
  QFileInfo info(fname);
  QString initialFilePath;

  if (info.isAbsolute()) {
    initialFilePath = info.absolutePath();
  } else if (m_mode == ExecutableFile) {
    initialFilePath = searchSystemPathForFile(fname);
    if (!initialFilePath.isEmpty())
      initialFilePath = QFileInfo(initialFilePath).absolutePath();
  }

  if (initialFilePath.isEmpty())
    initialFilePath = QDir::homePath();

  initialFilePath += "/" + info.fileName();

  info = QFileInfo(initialFilePath);

  QFileDialog dlg(this);
  switch (m_mode) {
    default:
    case ExistingFile:
      dlg.setWindowTitle(tr("Select file:"));
      break;
    case ExecutableFile:
      dlg.setWindowTitle(tr("Select executable:"));
      dlg.setFilter(QDir::Executable);
      break;
  }
  dlg.setFileMode(QFileDialog::ExistingFile);
  dlg.setDirectory(info.absolutePath());
  dlg.selectFile(info.fileName());
  if (static_cast<QFileDialog::DialogCode>(dlg.exec()) ==
        QFileDialog::Accepted &&
      !dlg.selectedFiles().isEmpty())
    setFileName(dlg.selectedFiles().first());
}

void FileBrowseWidget::testFileName()
{
  QFileInfo info(fileName());
  if (info.isAbsolute()) {
    if (info.exists()) {
      if (m_mode != ExecutableFile || info.isExecutable()) {
        fileNameMatch();
        return;
      }
    }
  } else if (m_mode == ExecutableFile) {
    // for non-absolute executables, search PATH
    QString absoluteFilePath = searchSystemPathForFile(fileName());
    if (!absoluteFilePath.isNull()) {
      fileNameMatch();
      return;
    }
  }

  fileNameNoMatch();
}

void FileBrowseWidget::fileNameMatch()
{
  QPalette pal;
  pal.setColor(QPalette::Text, Qt::black);
  m_edit->setPalette(pal);
  m_valid = true;
}

void FileBrowseWidget::fileNameNoMatch()
{
  QPalette pal;
  pal.setColor(QPalette::Text, Qt::red);
  m_edit->setPalette(pal);
  m_valid = false;
}

QStringList FileBrowseWidget::searchSystemPathForFiles(const QStringList& execs)
{
  QStringList result;
  QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
  if (!env.contains(QStringLiteral("PATH")))
    return result;

  static QString pathSplitter =
#ifdef Q_OS_WIN32
    ";"
#else  // WIN32
    ":"
#endif // WIN32
    ;
  QStringList paths =
    env.value(QStringLiteral("PATH")).split(pathSplitter, Qt::SkipEmptyParts);

  foreach (const QString& exec, execs) {
    foreach (const QString& path, paths) {
      QFileInfo info(path + "/" + exec);
      if (!info.exists() || !info.isFile()) {
        continue;
      }
      result << info.absoluteFilePath();
      break;
    }
  }

  return result;
}

QString FileBrowseWidget::searchSystemPathForFile(const QString& exec)
{
  QString result;
  QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
  if (!env.contains(QStringLiteral("PATH")))
    return result;

  static QString pathSplitter =
#ifdef Q_OS_WIN32
    ";"
#else  // WIN32
    ":"
#endif // WIN32
    ;
  QStringList paths =
    env.value(QStringLiteral("PATH")).split(pathSplitter, Qt::SkipEmptyParts);

  foreach (const QString& path, paths) {
    QFileInfo info(path + "/" + exec);
    if (!info.exists() || !info.isFile()) {
      continue;
    }
    result = info.absoluteFilePath();
    break;
  }

  return result;
}

void FileBrowseWidget::setMode(FileBrowseWidget::Mode m)
{
  m_mode = m;
  QDir::Filters modelFilters =
    QDir::Files | QDir::AllDirs | QDir::NoDot | QDir::Drives;

  // This should go here, but unfortunately this also filters out a ton of
  // directories as well...
  //  if (m_mode == ExecutableFile)
  //    modelFilters |= QDir::Executable;

  m_fileSystemModel->setFilter(modelFilters);
  testFileName();
}

FileBrowseWidget::Mode FileBrowseWidget::mode() const
{
  return m_mode;
}

} // namespace Avogadro::QtGui
