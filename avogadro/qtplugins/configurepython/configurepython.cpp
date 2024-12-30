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
#include <QtCore/QSettings>
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
  connect(m_action, &QAction::triggered, this, &ConfigurePython::showDialog);

  // check for Python on first launch
  QStringList paths = pythonPaths();
  QSettings settings;

  if (paths.isEmpty()) { // show a warning
    if (settings.contains("interpreters/firstlaunch"))
      return; // the user ignored the warning

    // suggest the user install Python
    auto option = QMessageBox::information(
      qobject_cast<QWidget*>(parent()), tr("Install Python"),
      tr("Python is used for many Avogadro "
         "features. Do you want to download Python?"));
    if (option == QMessageBox::Yes) {
      //
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
        QDesktopServices::openUrl(QUrl("https://github.com/conda-forge/"
                                       "miniforge?tab=readme-ov-file#install"));
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

  // Add the current interpreter to the list if it's not already there.
  if (!paths.contains(pythonInterp))
    paths.prepend(pythonInterp);

  return paths;
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
}

} // namespace Avogadro::QtPlugins
