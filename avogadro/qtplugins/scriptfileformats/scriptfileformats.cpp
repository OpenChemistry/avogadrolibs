/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "scriptfileformats.h"

#include "fileformatscript.h"

#include <avogadro/io/fileformatmanager.h>
#include <avogadro/qtgui/scriptloader.h>
#include <avogadro/qtgui/utilities.h>

#include <QtCore/QCoreApplication>
#include <QtCore/QDebug>
#include <QtCore/QDir>
#include <QtCore/QFileInfo>
#include <QtCore/QStandardPaths>
#include <QtCore/QTimer>

namespace Avogadro::QtPlugins {

ScriptFileFormats::ScriptFileFormats(QObject* p)
  : ExtensionPlugin(p)
{
  refreshFileFormats();
}

ScriptFileFormats::~ScriptFileFormats() {}

QList<QAction*> ScriptFileFormats::actions() const
{
  return QList<QAction*>();
}

QStringList ScriptFileFormats::menuPath(QAction*) const
{
  return QStringList();
}

void ScriptFileFormats::setMolecule(QtGui::Molecule*) {}

void ScriptFileFormats::refreshFileFormats()
{
  unregisterFileFormats();
  qDeleteAll(m_formats);
  m_formats.clear();

  QMap<QString, QString> scriptPaths =
    QtGui::ScriptLoader::scriptList("formatScripts");
  foreach (const QString& filePath, scriptPaths) {
    auto* format = new FileFormatScript(filePath);
    if (format->isValid())
      m_formats.push_back(format);
    else
      delete format;
  }

  registerFileFormats();
}

void ScriptFileFormats::unregisterFileFormats()
{
  for (QList<Io::FileFormat*>::const_iterator it = m_formats.constBegin(),
                                              itEnd = m_formats.constEnd();
       it != itEnd; ++it) {
    Io::FileFormatManager::unregisterFormat((*it)->identifier());
  }
}

void ScriptFileFormats::registerFileFormats()
{
  for (QList<Io::FileFormat*>::const_iterator it = m_formats.constBegin(),
                                              itEnd = m_formats.constEnd();
       it != itEnd; ++it) {
    if (!Io::FileFormatManager::registerFormat((*it)->newInstance())) {
      qDebug() << "Could not register format" << (*it)->identifier().c_str()
               << "due to name conflict.";
    }
  }
}

} // end namespace Avogadro
