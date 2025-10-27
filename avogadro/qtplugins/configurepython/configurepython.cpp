/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "configurepython.h"

#include "configurepythondialog.h"

#include <avogadro/qtgui/avogadropython.h>
#include <avogadro/qtgui/filebrowsewidget.h>
#include <avogadro/qtgui/utilities.h>

#include <QAction>
#include <QtCore/QDebug>
#include <QtCore/QDir>
#include <QtCore/QFileInfo>
#include <QtCore/QProcess>
#include <QtCore/QSettings>
#include <QtCore/QStandardPaths>
#include <QtCore/QSysInfo>
#include <QtCore/QUrl>
#include <QtGui/QDesktopServices>
#include <QtWidgets/QMessageBox>

namespace Avogadro::QtPlugins {

using QtGui::FileBrowseWidget;
using QtGui::Utilities::findExecutablePaths;

ConfigurePython::ConfigurePython(QObject* parent_)
  : Avogadro::QtGui::ExtensionPlugin(parent_), m_action(new QAction(this)),
    m_dialog(nullptr)
{
  m_action->setEnabled(true);
  m_action->setText(tr("Python Settings…"));
  m_action->setProperty("menu priority", 510);
  connect(m_action, SIGNAL(triggered()), SLOT(showDialog()));

  // check if the default pyproject.toml is installed for plugins
  QString pluginPath =
    QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation);
  if (!QDir(pluginPath).exists()) {
    QDir().mkpath(pluginPath);
  }
  QFileInfo info(pluginPath + "/pyproject.toml");
  QFile::copy(":/files/pyproject.toml", pluginPath + "/pyproject.toml");

  // check for Python on first launch
  QStringList paths = pythonPaths();
  QSettings settings;
  // check if we used pixi to install
  bool installedWithPixi = settings.value("installedWithPixi", false).toBool();

  if (paths.isEmpty() && !installedWithPixi) { // show a warning
    // suggest the user install Python
    auto option = QMessageBox::information(
      qobject_cast<QWidget*>(parent()), tr("Install Python"),
      tr("Python is used for many Avogadro "
         "features. Do you want to download Python?"),
      QMessageBox::Yes | QMessageBox::No, QMessageBox::Yes);
    if (option == QMessageBox::Yes) {
      // check if we have pixi
      // should be true for Mac and Windows because we bundle it
      QString pixiPath = QtGui::Utilities::findExecutablePath("pixi");
      if (!pixiPath.isEmpty()) {
        // use pixi
        QProcess pixi;
        pixi.setWorkingDirectory(pluginPath);
        pixi.start(pixiPath + "/pixi", { "install" });
        pixi.waitForFinished();
#ifndef NDEBUG
        qDebug() << "pixi output is " << pixi.readAllStandardOutput();
        qDebug() << "pixi error output is " << pixi.readAllStandardError();
#endif
        if (pixi.exitCode() != 0) {
          qWarning() << "Error installing dependencies with pixi";
        } else {
          installedWithPixi = true;
          settings.setValue("installedWithPixi", true);
          // don't need to do it again
        }

      } else {
        // no pixi, suggest installing miniforge
        QUrl miniforge;
#ifdef Q_OS_WIN
        // TODO: ARM or Intel? .. but conda-forge doesn't have ARM builds yet
        miniforge = QUrl("https://github.com/conda-forge/miniforge/releases/"
                         "latest/download/Miniforge3-Windows-x86_64.exe");
#elif defined(Q_OS_MACOS)
        // ARM or Intel?
        if (QSysInfo::currentCpuArchitecture().contains("arm"))
          miniforge = QUrl("https://github.com/conda-forge/miniforge/releases/"
                           "latest/download/Miniforge3-MacOSX-arm64.sh");
        else
          miniforge = QUrl("https://github.com/conda-forge/miniforge/releases/"
                           "latest/download/Miniforge3-MacOSX-x86_64.sh");
#else
        QString arch = QSysInfo::currentCpuArchitecture();
        if (arch.contains("arm"))
          miniforge = QUrl("https://github.com/conda-forge/miniforge/releases/"
                           "latest/download/Miniforge3-Linux-aarch64.sh");
        else if (arch.contains("ppc"))
          miniforge = QUrl("https://github.com/conda-forge/miniforge/releases/"
                           "latest/download/Miniforge3-Linux-ppc64le.sh");
        else
          miniforge = QUrl("https://github.com/conda-forge/miniforge/releases/"
                           "latest/download/Miniforge3-Linux-x86_64.sh");
#endif
        if (miniforge.isValid()) {
          QDesktopServices::openUrl(miniforge);
          // open install instructions
          QDesktopServices::openUrl(
            QUrl("https://github.com/conda-forge/"
                 "miniforge?tab=readme-ov-file#install"));
        }
      }
    }
    settings.setValue("interpreters/firstlaunch", true);
  }
}

ConfigurePython::~ConfigurePython()
{
  delete m_action;
}

QList<QAction*> ConfigurePython::actions() const
{
  return QList<QAction*>() << m_action;
}

QStringList ConfigurePython::menuPath(QAction*) const
{
  return QStringList() << tr("&Extensions");
}

void ConfigurePython::accept()
{
  if (m_dialog == nullptr)
    return;

  // Save the settings
  QSettings settings;
  settings.setValue("interpreters/python", m_dialog->currentOption());

  // check if the dialog has a conda environment selected
  if (!m_dialog->condaEnvironment().isEmpty()) {
    settings.setValue("interpreters/condaEnvironment",
                      m_dialog->condaEnvironment());
    // get the path to conda
    QString condaPath = m_dialog->condaPath();
    if (!condaPath.isEmpty()) {
      settings.setValue("interpreters/condaPath", condaPath);
    }
  }

  // TODO: reload the python interpreters
}

QStringList ConfigurePython::pythonPaths() const
{
  // Check for python interpreter in env var
  QString pythonInterp =
    QString::fromLocal8Bit(qgetenv("AVO_PYTHON_INTERPRETER"));
  if (pythonInterp.isEmpty()) {
    // Check settings
    QSettings settings;
    pythonInterp = settings.value("interpreters/python", QString()).toString();
  }
  // Use compile-time default if still not found.
  if (pythonInterp.isEmpty())
    pythonInterp = QString(pythonInterpreterPath);

  // get the list from the system path
  QStringList names;
#ifdef Q_OS_WIN
  names << "python3.exe"
        << "python.exe";
#else
  names << "python3"
        << "python";
#endif

  QStringList paths = findExecutablePaths(names);

  // Add the current interpreter to the list
  // it may be filtered out by the loop below
  if (!paths.contains(pythonInterp)) {
    paths.prepend(pythonInterp);
  }

#ifdef Q_OS_WIN
  // on Windows, check for a few possible locations
  // if they exist, add them to the list
  // e.g. C:\Program Files\Python*
  //      C:\Program Files (x86)\Python*
  QStringList programDirs;
  programDirs << "C:/Program Files"
              << "C:/Program Files (x86)";
  // might also be in the APPDATA folder
  QString homePath = QDir::homePath();
  if (!homePath.isEmpty()) {
    programDirs << homePath + "/AppData/Local/Programs";
    programDirs << homePath + "/AppData/Local/Programs/Python";
  }

  foreach (const QString& dir, programDirs) {
    QDir programFiles(dir);
    QStringList pythonDirs = programFiles.entryList(
      QStringList() << "Python*", QDir::Dirs | QDir::NoDotAndDotDot);
    // check if there's a python3.exe or python.exe
    foreach (const QString& pythonDir, pythonDirs) {
      QDir pythonDirInfo(dir + "/" + pythonDir);
      if (pythonDirInfo.exists("python3.exe"))
        paths << pythonDirInfo.absolutePath() + "/python3.exe";
      else if (pythonDirInfo.exists("python.exe"))
        paths << pythonDirInfo.absolutePath() + "/python.exe";
    }
  }
#endif

  // check to make sure each of the items are valid or remove them
  // (i.e., the python should return a version flag)
  QStringList validPaths;
  QStringList arguments;
  arguments << "-V";
  foreach (const QString& path, paths) {
    QFileInfo info(path);
    if (info.exists() && info.isExecutable()) {
      // try to run it to get the version
      QProcess process;
      process.start(path, arguments);
      if (process.waitForFinished()) {
        QString output = process.readAllStandardOutput();
        // should be like Python 3.10.14
        if (output.startsWith("Python")) {
          QString version = output.split(" ").at(1).simplified();
          // make sure it's at least Python 3
          // in the future, we can ensure particular releases
          if (version.startsWith("3"))
            validPaths << path;
        }
      }
      // if we didn't get results, it's not valid
    }
  }

  return validPaths;
}

void ConfigurePython::showDialog()
{
  if (m_dialog == nullptr) {
    m_dialog = new ConfigurePythonDialog(qobject_cast<QWidget*>(parent()));
    connect(m_dialog, SIGNAL(accepted()), SLOT(accept()));
  }

  // Populate the dialog with the current settings
  QStringList pythonInterps = pythonPaths();

  m_dialog->setOptions(pythonInterps);
  m_dialog->show();
  m_dialog->raise();
}

} // namespace Avogadro::QtPlugins
