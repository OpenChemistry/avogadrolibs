/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "scriptfileformats.h"

#include "fileformatscript.h"

#include <avogadro/io/fileformatmanager.h>
#include <avogadro/qtgui/packagemanager.h>
#include <avogadro/qtgui/scriptloader.h>
#include <avogadro/qtgui/utilities.h>

#include <QtCore/QDebug>

namespace Avogadro::QtPlugins {

ScriptFileFormats::ScriptFileFormats(QObject* p) : ExtensionPlugin(p)
{
  refreshFileFormats();

  // Connect to PackageManager for pyproject.toml-based packages
  auto* pm = QtGui::PackageManager::instance();
  connect(pm, &QtGui::PackageManager::featureRegistered, this,
          &ScriptFileFormats::registerFeature);
  connect(pm, &QtGui::PackageManager::featureRemoved, this,
          &ScriptFileFormats::unregisterFeature);
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
  m_packageFormats.clear();

  QMultiMap<QString, QString> scriptPaths =
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
  for (auto* format : m_formats)
    Io::FileFormatManager::unregisterFormat(format->identifier());
}

void ScriptFileFormats::registerFileFormats()
{
  for (auto* format : m_formats) {
    if (!Io::FileFormatManager::registerFormat(format->newInstance())) {
      qDebug() << "Could not register format" << format->identifier().c_str()
               << "due to name conflict.";
    }
  }
}

void ScriptFileFormats::registerFeature(const QString& type,
                                        const QString& packageDir,
                                        const QString& command,
                                        const QString& identifier,
                                        const QVariantMap& metadata)
{
  if (type != QLatin1String("file-formats"))
    return;

  auto* format = new FileFormatScript();
  format->setPackageInfo(packageDir, command, identifier);
  format->readMetaData(metadata);
  if (format->isValid()) {
    QString managerId = QString::fromStdString(format->identifier());
    if (!Io::FileFormatManager::registerFormat(format->newInstance())) {
      qDebug() << "Could not register file format" << identifier
               << "due to name conflict.";
      delete format;
    } else {
      m_formats.push_back(format);
      m_packageFormats.insert(identifier, managerId);
    }
  } else {
    delete format;
  }
}

void ScriptFileFormats::unregisterFeature(const QString& type,
                                          const QString& identifier)
{
  if (type != QLatin1String("file-formats"))
    return;

  const QList<QString> managerIds = m_packageFormats.values(identifier);
  if (managerIds.isEmpty())
    return;

  m_packageFormats.remove(identifier);
  for (const QString& managerId : managerIds) {
    Io::FileFormatManager::unregisterFormat(managerId.toStdString());
    for (int i = m_formats.size() - 1; i >= 0; --i) {
      if (QString::fromStdString(m_formats[i]->identifier()) == managerId)
        delete m_formats.takeAt(i);
    }
  }
}

} // namespace Avogadro::QtPlugins
