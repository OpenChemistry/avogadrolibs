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

void ConfigurePython::showDialog()
{
  if (m_dialog == nullptr) {
    m_dialog = new ConfigurePythonDialog(qobject_cast<QWidget*>(parent()));
    connect(m_dialog, SIGNAL(accepted()), SLOT(accept()));
    connect(m_dialog, SIGNAL(rejected()), SLOT(reject()));
  }

  // Populate the dialog with the current settings
  // TODO:
  // - check for conda environments
  // - get versions for each interpreter

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

  QStringList pythonInterps = findExecutablePaths(names);

  // Add the current interpreter to the list if it's not already there.
  if (!pythonInterps.contains(pythonInterp))
    pythonInterps.prepend(pythonInterp);

  m_dialog->setOptions(pythonInterps);
  m_dialog->show();
}

} // namespace Avogadro::QtPlugins
