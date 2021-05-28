/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "inputgenerator.h"

#include <avogadro/core/coordinateblockgenerator.h>
#include <avogadro/core/molecule.h>

#include <avogadro/io/fileformat.h>
#include <avogadro/io/fileformatmanager.h>

#include <avogadro/qtgui/generichighlighter.h>
#include <avogadro/qtgui/pythonscript.h>

#include <QtCore/QDebug>
#include <QtCore/QFile>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>

namespace Avogadro {
namespace MoleQueue {

using QtGui::PythonScript;
using QtGui::GenericHighlighter;

InputGenerator::InputGenerator(const QString& scriptFilePath_, QObject* parent_)
  : QObject(parent_), m_interpreter(new PythonScript(scriptFilePath_, this)),
    m_moleculeExtension("Unknown")
{
}

InputGenerator::InputGenerator(QObject* parent_)
  : QObject(parent_), m_interpreter(new PythonScript(this)),
    m_moleculeExtension("Unknown")
{
}

InputGenerator::~InputGenerator()
{
}

bool InputGenerator::debug() const
{
  return m_interpreter->debug();
}

QJsonObject InputGenerator::options() const
{
  m_errors.clear();
  if (m_options.isEmpty()) {
    qDeleteAll(m_highlightStyles.values());
    m_highlightStyles.clear();

    // Retrieve/set options
    QByteArray json =
      m_interpreter->execute(QStringList() << "--print-options");

    if (m_interpreter->hasErrors()) {
      m_errors << m_interpreter->errorList();
      return m_options;
    }

    QJsonDocument doc;
    if (!parseJson(json, doc))
      return m_options;

    if (!doc.isObject()) {
      m_errors << tr("script --print-options output must be an JSON object "
                     "at top level. Received:\n%1")
                    .arg(json.constData());
      return m_options;
    }

    m_options = doc.object();

    // Check if the generator needs to read a molecule.
    m_moleculeExtension = "None";
    if (m_options.contains("inputMoleculeFormat") &&
        m_options["inputMoleculeFormat"].isString()) {
      m_moleculeExtension = m_options["inputMoleculeFormat"].toString();
    }

    if (m_options.contains("highlightStyles") &&
        m_options.value("highlightStyles").isArray()) {
      if (!parseHighlightStyles(m_options.value("highlightStyles").toArray())) {
        qDebug() << "Failed to parse highlighting styles.";
      }
    }
  }

  return m_options;
}

QString InputGenerator::displayName() const
{
  m_errors.clear();
  if (m_displayName.isEmpty()) {
    m_displayName =
      QString(m_interpreter->execute(QStringList() << "--display-name"));
    m_errors << m_interpreter->errorList();
    m_displayName = m_displayName.trimmed();
  }

  return m_displayName;
}

QString InputGenerator::scriptFilePath() const
{
  return m_interpreter->scriptFilePath();
}

void InputGenerator::setScriptFilePath(const QString& scriptFile)
{
  reset();
  m_interpreter->setScriptFilePath(scriptFile);
}

void InputGenerator::reset()
{
  m_interpreter->setDefaultPythonInterpretor();
  m_interpreter->setScriptFilePath(QString());
  m_moleculeExtension = "Unknown";
  m_displayName = QString();
  m_options = QJsonObject();
  m_warnings.clear();
  m_errors.clear();
  m_filenames.clear();
  m_mainFileName.clear();
  m_files.clear();
  m_fileHighlighters.clear();
  m_highlightStyles.clear();
}

bool InputGenerator::generateInput(const QJsonObject& options_,
                                   const Core::Molecule& mol)
{
  m_errors.clear();
  m_warnings.clear();
  m_filenames.clear();
  qDeleteAll(m_fileHighlighters.values());
  m_fileHighlighters.clear();
  m_mainFileName.clear();
  m_files.clear();

  // Add the molecule file to the options
  QJsonObject allOptions(options_);
  if (!insertMolecule(allOptions, mol))
    return false;

  QByteArray json(m_interpreter->execute(QStringList() << "--generate-input",
                                         QJsonDocument(allOptions).toJson()));

  if (m_interpreter->hasErrors()) {
    m_errors << m_interpreter->errorList();
    return false;
  }

  QJsonDocument doc;
  if (!parseJson(json, doc))
    return false;

  // Update cache
  bool result = true;
  if (doc.isObject()) {
    QJsonObject obj = doc.object();

    // Check for any warnings:
    if (obj.contains("warnings")) {
      if (obj["warnings"].isArray()) {
        foreach (const QJsonValue& warning, obj["warnings"].toArray()) {
          if (warning.isString())
            m_warnings << warning.toString();
          else
            m_errors << tr("Non-string warning returned.");
        }
      } else {
        m_errors << tr("'warnings' member is not an array.");
      }
    }

    // Extract input file text:
    if (obj.contains("files")) {
      if (obj["files"].isArray()) {
        foreach (const QJsonValue& file, obj["files"].toArray()) {
          if (file.isObject()) {
            QJsonObject fileObj = file.toObject();
            if (fileObj["filename"].isString()) {
              QString fileName = fileObj["filename"].toString();
              QString contents;
              if (fileObj["contents"].isString()) {
                contents = fileObj["contents"].toString();
              } else if (fileObj["filePath"].isString()) {
                QFile refFile(fileObj["filePath"].toString());
                if (refFile.exists() && refFile.open(QFile::ReadOnly)) {
                  contents = QString(refFile.readAll());
                } else {
                  contents = tr("Reference file '%1' does not exist.")
                               .arg(refFile.fileName());
                  m_warnings << tr("Error populating file %1: %2")
                                  .arg(fileName, contents);
                }
              } else {
                m_errors << tr("File '%1' poorly formed. Missing string "
                               "'contents' or 'filePath' members.")
                              .arg(fileName);
                contents = m_errors.back();
                result = false;
              }
              replaceKeywords(contents, mol);
              m_filenames << fileName;
              m_files.insert(fileObj["filename"].toString(), contents);

              // Concatenate the requested styles for this input file.
              if (fileObj["highlightStyles"].isArray()) {
                GenericHighlighter* highlighter(new GenericHighlighter(this));
                foreach (const QJsonValue& styleVal,
                         fileObj["highlightStyles"].toArray()) {
                  if (styleVal.isString()) {
                    QString styleName(styleVal.toString());
                    if (m_highlightStyles.contains(styleName)) {
                      *highlighter += *m_highlightStyles[styleName];
                    } else {
                      qDebug() << "Cannot find highlight style '" << styleName
                               << "' for file '" << fileName << "'";
                    }
                  }
                }
                if (highlighter->ruleCount() > 0)
                  m_fileHighlighters[fileName] = highlighter;
                else
                  highlighter->deleteLater();
              }
            } else {
              result = false;
              m_errors << tr("Malformed file entry: filename/contents missing"
                             " or not strings:\n%1")
                            .arg(QString(QJsonDocument(fileObj).toJson()));
            } // end if/else filename and contents are strings
          } else {
            result = false;
            m_errors << tr("Malformed file entry at index %1: Not an object.")
                          .arg(m_filenames.size());
          } // end if/else file is JSON object
        }   // end foreach file
      } else {
        result = false;
        m_errors << tr("'files' member not an array.");
      } // end if obj["files"] is JSON array
    } else {
      result = false;
      m_errors << tr("'files' member missing.");
    } // end if obj contains "files"

    // Extract main input filename:
    if (obj.contains("mainFile")) {
      if (obj["mainFile"].isString()) {
        QString mainFile = obj["mainFile"].toString();
        if (m_filenames.contains(mainFile)) {
          m_mainFileName = mainFile;
        } else {
          result = false;
          m_errors << tr("'mainFile' member does not refer to an entry in "
                         "'files'.");
        } // end if/else mainFile is known
      } else {
        result = false;
        m_errors << tr("'mainFile' member must be a string.");
      } // end if/else mainFile is string
    } else {
      // If no mainFile is specified and there is only one file, use it as the
      // main file. Otherwise, don't set a main input file -- all files will
      // be treated as supplemental input files
      if (m_filenames.size() == 1)
        m_mainFileName = m_filenames.first();
    } // end if/else object contains mainFile
  } else {
    result = false;
    m_errors << tr("Response must be a JSON object at top-level.");
  }

  if (result == false)
    m_errors << tr("Script output:\n%1").arg(QString(json));

  return result;
}

int InputGenerator::numberOfInputFiles() const
{
  return m_filenames.size();
}

QStringList InputGenerator::fileNames() const
{
  return m_filenames;
}

QString InputGenerator::mainFileName() const
{
  return m_mainFileName;
}

QString InputGenerator::fileContents(const QString& fileName) const
{
  return m_files.value(fileName, QString());
}

GenericHighlighter* InputGenerator::createFileHighlighter(
  const QString& fileName) const
{
  GenericHighlighter* toClone(m_fileHighlighters.value(fileName, nullptr));
  return toClone ? new GenericHighlighter(*toClone) : toClone;
}

void InputGenerator::setDebug(bool d)
{
  m_interpreter->setDebug(d);
}

bool InputGenerator::parseJson(const QByteArray& json, QJsonDocument& doc) const
{
  QJsonParseError error;
  doc = QJsonDocument::fromJson(json, &error);

  if (error.error != QJsonParseError::NoError) {
    m_errors << tr("Parse error at offset %L1: '%2'\nRaw JSON:\n\n%3")
                  .arg(error.offset)
                  .arg(error.errorString())
                  .arg(QString(json));
    return false;
  }
  return true;
}

bool InputGenerator::insertMolecule(QJsonObject& json,
                                    const Core::Molecule& mol) const
{
  // Update the cached options if the format is not set
  if (m_moleculeExtension == "Unknown")
    options();

  if (m_moleculeExtension == "None")
    return true;

  Io::FileFormatManager& formats = Io::FileFormatManager::instance();
  QScopedPointer<Io::FileFormat> format(
    formats.newFormatFromFileExtension(m_moleculeExtension.toStdString()));

  if (format.isNull()) {
    m_errors << tr("Error writing molecule representation to string: "
                   "Unrecognized file format: %1")
                  .arg(m_moleculeExtension);
    return false;
  }

  std::string str;
  if (!format->writeString(str, mol)) {
    m_errors << tr("Error writing molecule representation to string: %1")
                  .arg(QString::fromStdString(format->error()));
    return false;
  }

  if (m_moleculeExtension != "cjson") {
    json.insert(m_moleculeExtension, QJsonValue(QString::fromStdString(str)));
  } else {
    // If cjson was requested, embed the actual JSON, rather than the string.
    QJsonParseError error;
    QJsonDocument doc = QJsonDocument::fromJson(str.c_str(), &error);
    if (error.error != QJsonParseError::NoError) {
      m_errors << tr("Error generating cjson object: Parse error at offset %1: "
                     "%2\nRaw JSON:\n\n%3")
                    .arg(error.offset)
                    .arg(error.errorString())
                    .arg(QString::fromStdString(str));
      return false;
    }

    if (!doc.isObject()) {
      m_errors << tr("Error generator cjson object: Parsed JSON is not an "
                     "object:\n%1")
                    .arg(QString::fromStdString(str));
      return false;
    }

    json.insert(m_moleculeExtension, doc.object());
  }

  return true;
}

QString InputGenerator::generateCoordinateBlock(const QString& spec,
                                                const Core::Molecule& mol) const
{
  Core::CoordinateBlockGenerator gen;
  gen.setMolecule(&mol);
  gen.setSpecification(spec.toStdString());
  std::string tmp(gen.generateCoordinateBlock());
  if (!tmp.empty())
    tmp.resize(tmp.size() - 1); // Pop off the trailing newline
  return QString::fromStdString(tmp);
}

void InputGenerator::replaceKeywords(QString& str,
                                     const Core::Molecule& mol) const
{
  // Simple keywords:
  str.replace("$$atomCount$$", QString::number(mol.atomCount()));
  str.replace("$$bondCount$$", QString::number(mol.bondCount()));

  // Find each coordinate block keyword in the file, then generate and replace
  // it with the appropriate values.
  QRegExp coordParser("\\$\\$coords:([^\\$]*)\\$\\$");
  int ind = 0;
  while ((ind = coordParser.indexIn(str, ind)) != -1) {
    // Extract spec and prepare the replacement
    const QString keyword = coordParser.cap(0);
    const QString spec = coordParser.cap(1);

    // Replace all blocks with this signature
    str.replace(keyword, generateCoordinateBlock(spec, mol));

  } // end for coordinate block
}

bool InputGenerator::parseHighlightStyles(const QJsonArray& json) const
{
  bool result(true);
  foreach (QJsonValue styleVal, json) {
    if (!styleVal.isObject()) {
      qDebug() << "Non-object in highlightStyles array.";
      result = false;
      continue;
    }
    QJsonObject styleObj(styleVal.toObject());

    if (!styleObj.contains("style")) {
      qDebug() << "Style object missing 'style' member.";
      result = false;
      continue;
    }
    if (!styleObj.value("style").isString()) {
      qDebug() << "Style object contains non-string 'style' member.";
      result = false;
      continue;
    }
    QString styleName(styleObj.value("style").toString());

    if (m_highlightStyles.contains(styleName)) {
      qDebug() << "Duplicate highlight style: " << styleName;
      result = false;
      continue;
    }

    if (!styleObj.contains("rules")) {
      qDebug() << "Style object" << styleName << "missing 'rules' member.";
      result = false;
      continue;
    }
    if (!styleObj.value("rules").isArray()) {
      qDebug() << "Style object" << styleName
               << "contains non-array 'rules' member.";
      result = false;
      continue;
    }
    QJsonArray rulesArray(styleObj.value("rules").toArray());

    GenericHighlighter* highlighter(
      new GenericHighlighter(const_cast<InputGenerator*>(this)));
    if (!parseRules(rulesArray, *highlighter)) {
      qDebug() << "Error parsing style" << styleName << endl
               << QString(QJsonDocument(styleObj).toJson());
      highlighter->deleteLater();
      result = false;
      continue;
    }
    m_highlightStyles.insert(styleName, highlighter);
  }

  return result;
}

bool InputGenerator::parseRules(const QJsonArray& json,
                                GenericHighlighter& highligher) const
{
  bool result(true);
  foreach (QJsonValue ruleVal, json) {
    if (!ruleVal.isObject()) {
      qDebug() << "Rule is not an object.";
      result = false;
      continue;
    }
    QJsonObject ruleObj(ruleVal.toObject());

    if (!ruleObj.contains("patterns")) {
      qDebug() << "Rule missing 'patterns' array:" << endl
               << QString(QJsonDocument(ruleObj).toJson());
      result = false;
      continue;
    }
    if (!ruleObj.value("patterns").isArray()) {
      qDebug() << "Rule 'patterns' member is not an array:" << endl
               << QString(QJsonDocument(ruleObj).toJson());
      result = false;
      continue;
    }
    QJsonArray patternsArray(ruleObj.value("patterns").toArray());

    if (!ruleObj.contains("format")) {
      qDebug() << "Rule missing 'format' object:" << endl
               << QString(QJsonDocument(ruleObj).toJson());
      result = false;
      continue;
    }
    if (!ruleObj.value("format").isObject()) {
      qDebug() << "Rule 'format' member is not an object:" << endl
               << QString(QJsonDocument(ruleObj).toJson());
      result = false;
      continue;
    }
    QJsonObject formatObj(ruleObj.value("format").toObject());

    GenericHighlighter::Rule& rule = highligher.addRule();

    foreach (QJsonValue patternVal, patternsArray) {
      QRegExp pattern;
      if (!parsePattern(patternVal, pattern)) {
        qDebug() << "Error while parsing pattern:" << endl
                 << QString(QJsonDocument(patternVal.toObject()).toJson());
        result = false;
        continue;
      }
      rule.addPattern(pattern);
    }

    QTextCharFormat format;
    if (!parseFormat(formatObj, format)) {
      qDebug() << "Error while parsing format:" << endl
               << QString(QJsonDocument(formatObj).toJson());
      result = false;
    }
    rule.setFormat(format);
  }

  return result;
}

bool InputGenerator::parseFormat(const QJsonObject& json,
                                 QTextCharFormat& format) const
{
  // Check for presets first:
  if (json.contains("preset")) {
    if (!json["preset"].isString()) {
      qDebug() << "Preset is not a string.";
      return false;
    }

    QString preset(json["preset"].toString());
    /// @todo Store presets in a singleton that can be configured in the GUI,
    /// rather than hardcoding them.
    if (preset == "title") {
      format.setFontFamily("serif");
      format.setForeground(Qt::darkGreen);
      format.setFontWeight(QFont::Bold);
    } else if (preset == "keyword") {
      format.setFontFamily("mono");
      format.setForeground(Qt::darkBlue);
    } else if (preset == "property") {
      format.setFontFamily("mono");
      format.setForeground(Qt::darkRed);
    } else if (preset == "literal") {
      format.setFontFamily("mono");
      format.setForeground(Qt::darkMagenta);
    } else if (preset == "comment") {
      format.setFontFamily("serif");
      format.setForeground(Qt::darkGreen);
      format.setFontItalic(true);
    } else {
      qDebug() << "Invalid style preset: " << preset;
      return false;
    }
    return true;
  }

  // Extract an RGB tuple from 'array' as a QBrush:
  struct
  {
    QBrush operator()(const QJsonArray& array, bool* ok)
    {
      *ok = false;
      QBrush result;

      if (array.size() != 3)
        return result;

      int rgb[3];
      for (int i = 0; i < 3; ++i) {
        if (!array.at(i).isDouble())
          return result;
        rgb[i] = static_cast<int>(array.at(i).toDouble());
        if (rgb[i] < 0 || rgb[i] > 255) {
          qDebug() << "Warning: Color component value invalid: " << rgb[i]
                   << " (Valid range is 0-255).";
        }
      }

      result.setColor(QColor(rgb[0], rgb[1], rgb[2]));
      result.setStyle(Qt::SolidPattern);
      *ok = true;
      return result;
    }
  } colorParser;

  if (json.contains("foreground") && json.value("foreground").isArray()) {
    QJsonArray foregroundArray(json.value("foreground").toArray());
    bool ok;
    format.setForeground(colorParser(foregroundArray, &ok));
    if (!ok)
      return false;
  }

  if (json.contains("background") && json.value("background").isArray()) {
    QJsonArray backgroundArray(json.value("background").toArray());
    bool ok;
    format.setBackground(colorParser(backgroundArray, &ok));
    if (!ok)
      return false;
  }

  if (json.contains("attributes") && json.value("attributes").isArray()) {
    QJsonArray attributesArray(json.value("attributes").toArray());
    format.setFontWeight(attributesArray.contains(QLatin1String("bold"))
                           ? QFont::Bold
                           : QFont::Normal);
    format.setFontItalic(attributesArray.contains(QLatin1String("italic")));
    format.setFontUnderline(
      attributesArray.contains(QLatin1String("underline")));
  }

  if (json.contains("family") && json.value("family").isString()) {
    format.setFontFamily(json.value("family").toString());
  }

  return true;
}

bool InputGenerator::parsePattern(const QJsonValue& json,
                                  QRegExp& pattern) const
{
  if (!json.isObject())
    return false;

  QJsonObject patternObj(json.toObject());

  if (patternObj.contains("regexp") && patternObj.value("regexp").isString()) {
    pattern.setPatternSyntax(QRegExp::RegExp2);
    pattern.setPattern(patternObj.value("regexp").toString());
  } else if (patternObj.contains("wildcard") &&
             patternObj.value("wildcard").isString()) {
    pattern.setPatternSyntax(QRegExp::WildcardUnix);
    pattern.setPattern(patternObj.value("wildcard").toString());
  } else if (patternObj.contains("string") &&
             patternObj.value("string").isString()) {
    pattern.setPatternSyntax(QRegExp::FixedString);
    pattern.setPattern(patternObj.value("string").toString());
  } else {
    return false;
  }

  if (patternObj.contains("caseSensitive")) {
    pattern.setCaseSensitivity(patternObj.value("caseSensitive").toBool(true)
                                 ? Qt::CaseSensitive
                                 : Qt::CaseInsensitive);
  }

  return true;
}

} // namespace MoleQueue
} // namespace Avogadro
