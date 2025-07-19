/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "scriptloader.h"

#include "interfacescript.h"
#include "utilities.h"

#include <QtCore/QCoreApplication>
#include <QtCore/QDateTime>
#include <QtCore/QDebug>
#include <QtCore/QDir>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QSettings>
#include <QtCore/QStandardPaths>

namespace Avogadro::QtGui {

ScriptLoader::ScriptLoader(QObject* parent_) : QObject(parent_) {}

ScriptLoader::~ScriptLoader() {}

bool ScriptLoader::queryProgramName(const QString& scriptFilePath,
                                    QString& displayName)
{
  InterfaceScript gen(scriptFilePath);
  displayName = gen.displayName();
  if (gen.hasErrors()) {
    displayName.clear();
    qWarning() << tr("Cannot load script %1").arg(scriptFilePath);
    return false;
  }
  return true;
}

QMultiMap<QString, QString> ScriptLoader::scriptList(const QString& type)
{
  // List of directories to check.
  /// @todo Custom script locations
  QStringList dirs;
  QMultiMap<QString, QString> scriptList;

  QSettings settings; // to cache the names of scripts
  QStringList scriptFiles = settings.value("scripts/" + type).toStringList();
  QStringList scriptNames =
    settings.value("scripts/" + type + "/names").toStringList();
  // hash from the last modified time and size of the scripts
  QStringList scriptHashes =
    settings.value("scripts/" + type + "/hashes").toStringList();

  // add the default paths
  QStringList stdPaths =
    QStandardPaths::standardLocations(QStandardPaths::AppLocalDataLocation);
  foreach (const QString& dirStr, stdPaths) {
    QString path = dirStr + '/' + type;
    dirs << path; // we'll check if these exist below
  }

  dirs << QCoreApplication::applicationDirPath() + "/../" +
            QtGui::Utilities::libraryDirectory() + "/avogadro2/scripts/" + type;

  // build up a list of possible files, then we check if they're real scripts
  QStringList fileList;
  foreach (const QString& dirStr, dirs) {
#ifndef NDEBUG
    qDebug() << tr("Checking for %1 scripts in path %2").arg(type).arg(dirStr);
#endif
    QDir dir(dirStr);
    if (dir.exists() && dir.isReadable()) {
      foreach (
        const QFileInfo& file,
        dir.entryInfoList(QDir::Files | QDir::Dirs | QDir::NoDotAndDotDot)) {
        QString filePath = file.absoluteFilePath();

        if (file.isDir()) {
          // handle subdirectory packages with plugins.json files
          QFileInfo jsonManifest(filePath + "/plugin.json");
          if (jsonManifest.isReadable()) {
            // load the JSON
            QFile jsonFile(jsonManifest.absoluteFilePath());
            jsonFile.open(QIODevice::ReadOnly | QIODevice::Text);
            QByteArray data = jsonFile.readAll();
            jsonFile.close();
            QJsonDocument d = QJsonDocument::fromJson(data);
            if (!d.isNull() && d.isObject()) {
              /* find the "commands" array
              { "name": "Gaussian", "command": "gaussian" },
              { "name": "MOPAC", "command": "mopac" },
              { "name": "ORCA", "command": "orca" },
              */
              QJsonValue commands = d.object()["commands"];
              if (commands.type() == QJsonValue::Array) {
                // check if "command.*" exists as a file
                QJsonArray list = commands.toArray();
                for (auto&& i : list) {
                  QJsonValue command = i.toObject()["command"];
                  QString name = command.toString();
                  if (name.isEmpty() || name.isNull())
                    continue;

                  QFileInfo commandFile(filePath + '/' + name);
                  if (commandFile.isReadable()) {
                    fileList << commandFile.absoluteFilePath();
                    continue;
                  }
                  // doesn't exist, so try the .py version
                  // TODO: set this up as a loop with name filters
                  commandFile.setFile(filePath + '/' + name + ".py");
                  if (commandFile.isReadable()) {
                    fileList << commandFile.absoluteFilePath();
                    continue;
                  }
                }
              } // "commands" JSON is array
            } // document is json
          } // plugin.json file exists

          continue;
        } // end reading subdirectories with plugin.json

        if (file.isReadable())
          fileList << filePath;
      }
    } // end dir.exists()
  } // end for directory list

  // go through the list of files to see if they're actually scripts
  foreach (const QString& filePath, fileList) {
    QFileInfo file(filePath);
    // check if we have this from the last time
    if (scriptFiles.contains(filePath)) {
      int index = scriptFiles.indexOf(filePath);
      if (index != -1) {
        QString hash = scriptHashes.at(index);
        // got a match?
        if (hash ==
            QString::number(file.size()) + file.lastModified().toString()) {
          scriptList.insert(scriptNames.at(index), filePath);
          continue;
        }
      }
    }

    QString displayName;
    if (queryProgramName(filePath, displayName)) {
      if (displayName.isEmpty())
        continue; // don't add empty menu items

      // Might be another script with the same name
      if (scriptList.contains(displayName)) {
        // check the last-modified-time of the existing case
        QFileInfo existingFile(scriptList.value(displayName));
        if (file.lastModified() > existingFile.lastModified()) {
          // replace existing with this new entry
          scriptList.replace(displayName, filePath);
          // update the cache
          int index = scriptFiles.indexOf(filePath);
          if (index != -1) {
            scriptFiles.replace(index, filePath);
            scriptNames.replace(index, displayName);
            scriptHashes.replace(index, QString::number(file.size()) +
                                          file.lastModified().toString());
          }
        }
      } else { // new entry
        scriptList.insert(displayName, filePath);
        // update the cache
        scriptFiles << filePath;
        scriptNames << displayName;
        scriptHashes << QString::number(file.size()) +
                          file.lastModified().toString(Qt::ISODate);
      }
    } // run queryProgramName
  } // foreach files

  return scriptList;
}

} // namespace Avogadro::QtGui
