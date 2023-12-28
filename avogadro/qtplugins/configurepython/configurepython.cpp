/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "configurepython.h"

#include "configurepythondialog.h"

#include <avogadro/qtgui/avogadropython.h>
#include <avogadro/qtgui/filebrowsewidget.h>

#include <QAction>
#include <QDebug>
#include <QDialogButtonBox>
#include <QLabel>
#include <QMessageBox>
#include <QSettings>
#include <QVBoxLayout>

namespace Avogadro::QtPlugins {

ConfigurePython::ConfigurePython(QObject* parent_)
  : Avogadro::QtGui::ExtensionPlugin(parent_)
{
  m_action = new QAction(this);
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
  // TODO:
  // - check for conda environments
  // - check for python in PATH
  // - offer choices for python interpreter
  // - .. or "other..." to set the path manually

  // Create objects
  QSettings settings;
  QDialog dlg(qobject_cast<QWidget*>(parent()));
  auto* label = new QLabel;
  auto* layout = new QVBoxLayout;
  auto* browser = new QtGui::FileBrowseWidget;
  auto* buttonBox = new QDialogButtonBox;

  // Configure objects
  // Check for python interpreter in env var
  QString pythonInterp =
    QString::fromLocal8Bit(qgetenv("AVO_PYTHON_INTERPRETER"));
  if (pythonInterp.isEmpty()) {
    // Check settings
    pythonInterp = settings.value("interpreters/python", QString()).toString();
  }
  // Use compile-time default if still not found.
  if (pythonInterp.isEmpty())
    pythonInterp = QString(pythonInterpreterPath);
  browser->setMode(QtGui::FileBrowseWidget::ExecutableFile);
  browser->setFileName(pythonInterp);

  buttonBox->setStandardButtons(QDialogButtonBox::Ok |
                                QDialogButtonBox::Cancel);

  dlg.setWindowTitle(tr("Set path to Python interpreter:"));
  label->setText(tr("Select the python interpreter used to run input generator "
                    "scripts.\nAvogadro must be restarted for any changes to "
                    "take effect."));

  // Build layout
  layout->addWidget(label);
  layout->addWidget(browser);
  layout->addWidget(buttonBox);
  dlg.setLayout(layout);

  // Connect
  connect(buttonBox, SIGNAL(accepted()), &dlg, SLOT(accept()));
  connect(buttonBox, SIGNAL(rejected()), &dlg, SLOT(reject()));

  // Show dialog
  auto response = static_cast<QDialog::DialogCode>(dlg.exec());
  if (response != QDialog::Accepted)
    return;

  // Handle response
  settings.setValue("interpreters/python", browser->fileName());
}

} // namespace Avogadro::QtPlugins
