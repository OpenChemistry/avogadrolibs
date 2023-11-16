/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "plugindownloader.h"
#include "downloaderwidget.h"
#include <avogadro/io/fileformatmanager.h>
#include <avogadro/qtgui/molecule.h>

#include <QtCore/QList>
#include <QtNetwork/QNetworkAccessManager>
#include <QtNetwork/QNetworkReply>
#include <QAction>
#include <QSettings>
#include <QtWidgets/QInputDialog>
#include <QtWidgets/QMessageBox>
#include <QtWidgets/QProgressDialog>

//#include <libarchive/archive.h>
namespace Avogadro::QtPlugins {

PluginDownloader::PluginDownloader(QObject* parent_)
  : ExtensionPlugin(parent_), m_configureAction(new QAction(this)),
  m_downloadAction(new QAction(this)),
   m_molecule(nullptr),
    m_network(nullptr), m_widget(nullptr)
{
  m_downloadAction->setEnabled(true);
  m_downloadAction->setText(tr("Download Plugins…"));
  m_downloadAction->setProperty("menu priority", 520);
  connect(m_downloadAction, SIGNAL(triggered()), SLOT(showDialog()));

  m_configureAction->setEnabled(true);
  m_configureAction->setText(tr("Configure Python…"));
  m_configureAction->setProperty("menu priority", 510);
  connect(m_configureAction, SIGNAL(triggered()), SLOT(configurePython()));
}

PluginDownloader::~PluginDownloader() = default;

QList<QAction*> PluginDownloader::actions() const
{
  return QList<QAction*>() << m_downloadAction << m_configureAction;
}

QStringList PluginDownloader::menuPath(QAction*) const
{
  return QStringList() << tr("&Extensions");
}

void PluginDownloader::setMolecule(QtGui::Molecule*)
{
}

bool PluginDownloader::readMolecule(QtGui::Molecule&)
{
  return true;
}

void PluginDownloader::configurePython()
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

void PluginDownloader::showDialog()
{
  if (m_widget == nullptr) {
    m_widget = new DownloaderWidget(qobject_cast<QWidget*>(parent()));
  }
  m_widget->show();
}

void PluginDownloader::replyFinished(QNetworkReply*)
{
}
}
