/******************************************************************************

  This source file is part of the MoleQueue project.

  Copyright 2012 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "jobobject.h"

#include <QtCore/QJsonArray>

namespace MoleQueue
{

JobObject::JobObject()
{
}

JobObject::~JobObject()
{
}

void JobObject::setValue(const QString &key, const QVariant &value_)
{
  m_value[key] = QJsonValue::fromVariant(value_);
}

QVariant JobObject::value(const QString &key,
                          const QVariant &defaultValue) const
{
  return m_value.contains(key) ? m_value[key].toVariant() : defaultValue;
}

void JobObject::setQueue(const QString &queueName)
{
  m_value["queue"] = queueName;
}

QString JobObject::queue() const
{
  return m_value["queue"].toString();
}

void JobObject::setProgram(const QString &programName)
{
  m_value["program"] = programName;
}

QString JobObject::program() const
{
  return m_value["program"].toString();
}

void JobObject::setDescription(const QString &descriptionText)
{
  m_value["description"] = descriptionText;
}

QString JobObject::description() const
{
  return m_value["description"].toString();
}

void JobObject::setInputFile(const QString &fileName, const QString &contents)
{
  m_value["inputFile"] = fileSpec(fileName, contents);
}

void JobObject::setInputFile(const QString &path)
{
  m_value["inputFile"] = fileSpec(path);
}

void JobObject::setInputFile(const QJsonObject &file)
{
  m_value["inputFile"] = file;
}

QJsonObject JobObject::inputFile() const
{
  return m_value["inputFile"].toObject();
}

void JobObject::appendAdditionalInputFile(const QString &fileName,
                                          const QString &contents)
{
  QJsonArray extraInputFiles;
  if (m_value["additionalInputFiles"].isArray())
    extraInputFiles = m_value["additionalInputFiles"].toArray();
  extraInputFiles.append(fileSpec(fileName, contents));
  m_value["additionalInputFiles"] = extraInputFiles;
}

void JobObject::appendAdditionalInputFile(const QString &path)
{
  QJsonArray extraInputFiles;
  if (m_value["additionalInputFiles"].isArray())
    extraInputFiles = m_value["additionalInputFiles"].toArray();
  extraInputFiles.append(fileSpec(path));
  m_value["additionalInputFiles"] = extraInputFiles;
}

void JobObject::setAdditionalInputFiles(const QJsonArray &files)
{
  m_value["additionalInputFiles"] = files;
}

void JobObject::clearAdditionalInputFiles()
{
  m_value.remove("additionalInputFiles");
}

QJsonArray JobObject::additionalInputFiles() const
{
  return m_value["additionalInputFiles"].toArray();
}

QJsonObject JobObject::fileSpec(const QString &fileName, const QString &contents)
{
  QJsonObject result;
  result["filename"] = fileName;
  result["contents"] = contents;
  return result;
}

QJsonObject JobObject::fileSpec(const QString &path)
{
  QJsonObject result;
  result["path"] = path;
  return result;
}

} // End namespace MoleQueue
