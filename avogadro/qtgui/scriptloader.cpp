/******************************************************************************

  This source file is part of the Avogadro project.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

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
#include <QtCore/QStandardPaths>

namespace Avogadro {
namespace QtGui {

ScriptLoader::ScriptLoader(QObject* parent_)
  : QObject(parent_)
{}

ScriptLoader::~ScriptLoader() {}

bool ScriptLoader::queryProgramName(const QString& scriptFilePath,
                                    QString& displayName)
{
  InterfaceScript gen(scriptFilePath);
  displayName = gen.displayName();
  if (gen.hasErrors()) {
    displayName.clear();
    qWarning() << "ScriptLoader::queryProgramName: Unable to retrieve program "
                  "name for"
               << scriptFilePath << ";" << gen.errorList().join("\n\n");
    return false;
  }
  return true;
}

QMap<QString, QString> ScriptLoader::scriptList(const QString& type)
{
  // List of directories to check.
  /// @todo Custom script locations
  QStringList dirs;
  QMap<QString, QString> scriptList;

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
    qDebug() << "Checking for " << type << " scripts in" << dirStr;
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
                for (int i = 0; i < list.size(); ++i) {
                  QJsonValue command = list[i].toObject()["command"];
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
            }   // document is json
          }     // plugin.json file exists

          continue;
        } // end reading subdirectories with plugin.json

        if (file.isReadable())
          fileList << filePath;
      }
    } // end dir.exists()
  }   // end for directory list

  // go through the list of files to see if they're actually scripts
  foreach (const QString& filePath, fileList) {
    QString displayName;
    if (queryProgramName(filePath, displayName)) {
      if (displayName.isEmpty())
        continue; // don't add empty menu items

      // Might be another script with the same name
      if (scriptList.contains(displayName)) {
        // check the last-modified-time of the existing case
        QFileInfo file(filePath);
        QFileInfo existingFile(scriptList[displayName]);
        if (file.lastModified() > existingFile.lastModified()) {
          // replace existing with this new entry
          scriptList.insert(displayName, filePath);
        }
      } else // new entry
        scriptList.insert(displayName, filePath);
    } // run queryProgramName
  }   // foreach files

  return scriptList;
}

} // namespace QtGui
} // namespace Avogadro
