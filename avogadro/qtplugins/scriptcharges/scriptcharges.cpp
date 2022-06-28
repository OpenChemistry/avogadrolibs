/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "scriptchargesh"

#include "pythonchargemodel.h"

#include <avogadro/io/fileformatmanager.h>
#include <avogadro/qtgui/scriptloader.h>
#include <avogadro/qtgui/utilities.h>

#include <QtCore/QCoreApplication>
#include <QtCore/QDebug>
#include <QtCore/QDir>
#include <QtCore/QFileInfo>
#include <QtCore/QStandardPaths>
#include <QtCore/QTimer>

namespace Avogadro {
namespace QtPlugins {

ScriptCharges::ScriptCharges(QObject* p)
  : ExtensionPlugin(p)
{
  refreshModels();
}

ScriptCharges::~ScriptCharges() {}

QList<QAction*> ScriptCharges::actions() const
{
  return QList<QAction*>();
}

QStringList ScriptCharges::menuPath(QAction*) const
{
  return QStringList();
}

void ScriptCharges::setMolecule(QtGui::Molecule*) {}

void ScriptCharges::refreshModels()
{
  unregisterFileFormats();
  qDeleteAll(m_formats);
  m_formats.clear();

  QMap<QString, QString> scriptPaths =
    QtGui::ScriptLoader::scriptList("charges");
  foreach (const QString& filePath, scriptPaths) {
    FileFormatScript* format = new FileFormatScript(filePath);
    if (format->isValid())
      m_formats.push_back(format);
    else
      delete format;
  }

  registerModels();
}

void ScriptCharges::unregisterModels()
{
  for (QList<Io::FileFormat*>::const_iterator it = m_formats.constBegin(),
                                              itEnd = m_formats.constEnd();
       it != itEnd; ++it) {
    Io::FileFormatManager::unregisterFormat((*it)->identifier());
  }
}

void ScriptCharges::registerModels()
{
  for (QList<Io::FileFormat*>::const_iterator it = m_formats.constBegin(),
                                              itEnd = m_formats.constEnd();
       it != itEnd; ++it) {
    if (!Io::FileFormatManager::registerFormat((*it)->newInstance())) {
      qDebug() << "Could not register model" << (*it)->identifier().c_str()
               << "due to name conflict.";
    }
  }
}

} // end namespace QtPlugins
} // end namespace Avogadro
