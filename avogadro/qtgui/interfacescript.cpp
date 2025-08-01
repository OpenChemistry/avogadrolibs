/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "interfacescript.h"

#include <avogadro/core/coordinateblockgenerator.h>
#include <avogadro/core/molecule.h>

#include <avogadro/io/fileformat.h>
#include <avogadro/io/fileformatmanager.h>

#include <avogadro/qtgui/generichighlighter.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/pythonscript.h>
#include <avogadro/qtgui/rwmolecule.h>

#include <QtCore/QDebug>
#include <QtCore/QFile>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>

#include <QtWidgets/QMessageBox>

namespace Avogadro::QtGui {

using QtGui::GenericHighlighter;
using QtGui::PythonScript;

InterfaceScript::InterfaceScript(const QString& scriptFilePath_,
                                 QObject* parent_)
  : QObject(parent_), m_interpreter(new PythonScript(scriptFilePath_, this)),
    m_moleculeExtension(QStringLiteral("Unknown"))
{
}

InterfaceScript::InterfaceScript(QObject* parent_)
  : QObject(parent_), m_interpreter(new PythonScript(this)),
    m_moleculeExtension(QStringLiteral("Unknown"))
{
}

InterfaceScript::~InterfaceScript() {}

bool InterfaceScript::debug() const
{
  return m_interpreter->debug();
}

QJsonObject InterfaceScript::options() const
{
  m_errors.clear();
  if (m_options.isEmpty()) {
    qDeleteAll(m_highlightStyles.values());
    m_highlightStyles.clear();

    // Retrieve/set options
    QByteArray json = m_interpreter->execute(
      QStringList() << QStringLiteral("--print-options"));

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

    if (m_options.contains(QStringLiteral("highlightStyles")) &&
        m_options.value(QStringLiteral("highlightStyles")).isArray()) {
      if (!parseHighlightStyles(
            m_options.value(QStringLiteral("highlightStyles")).toArray())) {
        qDebug() << "Failed to parse highlighting styles.";
      }
    }
  }

  // Check if the generator needs to read a molecule.
  m_moleculeExtension = QLatin1String("cjson");
  if (m_options.contains(QStringLiteral("inputMoleculeFormat")) &&
      m_options[QStringLiteral("inputMoleculeFormat")].isString()) {
    m_moleculeExtension =
      m_options[QStringLiteral("inputMoleculeFormat")].toString();
  }

  return m_options;
}

QString InterfaceScript::displayName() const
{
  m_errors.clear();
  if (m_displayName.isEmpty()) {
    m_displayName = QString(m_interpreter->execute(
      QStringList() << QStringLiteral("--display-name")));
    m_errors << m_interpreter->errorList();
    m_displayName = m_displayName.trimmed();
  }

  return m_displayName;
}

QString InterfaceScript::menuPath() const
{
  m_errors.clear();
  if (m_menuPath.isEmpty()) {
    m_menuPath = QString(
      m_interpreter->execute(QStringList() << QStringLiteral("--menu-path")));
    m_errors << m_interpreter->errorList();
    m_menuPath = m_menuPath.trimmed();
  }

  return m_menuPath;
}

QString InterfaceScript::scriptFilePath() const
{
  return m_interpreter->scriptFilePath();
}

void InterfaceScript::setScriptFilePath(const QString& scriptFile)
{
  reset();
  m_interpreter->setScriptFilePath(scriptFile);
}

void InterfaceScript::reset()
{
  m_interpreter->setDefaultPythonInterpreter();
  m_interpreter->setScriptFilePath(QString());
  m_moleculeExtension = QLatin1String("Unknown");
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

bool InterfaceScript::runCommand(const QJsonObject& options_,
                                 Core::Molecule* mol)
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
  if (!insertMolecule(allOptions, *mol))
    return false;

  connect(m_interpreter, &PythonScript::finished, this,
          &::Avogadro::QtGui::InterfaceScript::commandFinished);
  m_interpreter->asyncExecute(QStringList() << QStringLiteral("--run-command"),
                              QJsonDocument(allOptions).toJson());
  return true;
}

void InterfaceScript::commandFinished()
{
  emit finished();
}

bool InterfaceScript::processCommand(Core::Molecule* mol)
{
  if (m_interpreter == nullptr)
    return false;

  QByteArray json(m_interpreter->asyncResponse());

  if (m_interpreter->hasErrors()) {
    m_errors << m_interpreter->errorList();
    return false;
  }

  QJsonDocument doc;
  if (!parseJson(json, doc)) {
    return false;
  }

  // Update cache
  bool result = true;
  if (doc.isObject()) {
    QJsonObject obj = doc.object();

    // Check for any warnings:
    if (obj.contains(QStringLiteral("warnings"))) {
      if (obj[QStringLiteral("warnings")].isArray()) {
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

    m_moleculeExtension = "cjson";
    if (obj.contains("moleculeFormat") && obj["moleculeFormat"].isString()) {
      m_moleculeExtension = obj["moleculeFormat"].toString();
    }

    Io::FileFormatManager& formats = Io::FileFormatManager::instance();
    QScopedPointer<Io::FileFormat> format(
      formats.newFormatFromFileExtension(m_moleculeExtension.toStdString()));

    if (format.isNull()) {
      m_errors << tr("Error reading molecule representation: "
                     "Unrecognized file format: %1")
                    .arg(m_moleculeExtension);
      return false;
    }

    auto* guiMol = static_cast<QtGui::Molecule*>(mol);
    QtGui::Molecule newMol(guiMol->parent());
    if (m_moleculeExtension == "cjson") {
      // convert the "cjson" field to a string
      QJsonObject cjsonObj = obj["cjson"].toObject();
      QJsonDocument doc2(cjsonObj);
      QString strCJSON(doc2.toJson(QJsonDocument::Compact));
      if (!strCJSON.isEmpty()) {
        result = format->readString(strCJSON.toStdString(), newMol);
      }
    } else if (obj.contains(m_moleculeExtension) &&
               obj[m_moleculeExtension].isString()) {
      QString strFile = obj[m_moleculeExtension].toString();
      result = format->readString(strFile.toStdString(), newMol);
    }

    // check if the script wants us to perceive bonds first
    if (obj["bond"].toBool()) {
      newMol.perceiveBondsSimple();
      newMol.perceiveBondOrders();
    }

    // how do we handle this result?
    if (obj["readProperties"].toBool()) {
      guiMol->readProperties(newMol);
      guiMol->emitChanged(Molecule::Properties | Molecule::Added);
    } else if (obj["append"].toBool()) {
      guiMol->undoMolecule()->appendMolecule(newMol, m_displayName);
    } else { // replace the whole molecule
      Molecule::MoleculeChanges changes = (Molecule::Atoms | Molecule::Bonds |
                                           Molecule::Added | Molecule::Removed);
      guiMol->undoMolecule()->modifyMolecule(newMol, changes, m_displayName);
    }

    // select some atoms
    if (obj.contains("selectedAtoms") && obj["selectedAtoms"].isArray()) {
      QJsonArray selectedList = obj["selectedAtoms"].toArray();
      for (auto&& i : selectedList) {
        if (i.isDouble()) {
          auto index = static_cast<Index>(i.toDouble());
          if (index < guiMol->atomCount())
            guiMol->undoMolecule()->setAtomSelected(index, true);
        }
      }
      guiMol->emitChanged(Molecule::Atoms);
    }

    // check if there are messages for the user
    if (obj.contains("message")) {
      QString message;

      if (obj["message"].isString())
        message = obj["message"].toString();
      else if (obj["message"].isArray()) {
        QJsonArray messageList = obj["message"].toArray();
        for (int i = 0; i < messageList.size(); ++i) {
          if (messageList[i].isString())
            message += messageList[i].toString() + "\n";
        }
      }
      if (!message.isEmpty()) {
        QMessageBox::information(qobject_cast<QWidget*>(parent()),
                                 tr("%1 Message").arg(m_displayName), message);
      }
    }
  }
  return result;
}

bool InterfaceScript::generateInput(const QJsonObject& options_,
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

  QByteArray json(
    m_interpreter->execute(QStringList() << QStringLiteral("--generate-input"),
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
    if (obj.contains(QStringLiteral("warnings"))) {
      if (obj[QStringLiteral("warnings")].isArray()) {
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
    if (obj.contains(QStringLiteral("files"))) {
      if (obj[QStringLiteral("files")].isArray()) {
        foreach (const QJsonValue& file, obj["files"].toArray()) {
          if (file.isObject()) {
            QJsonObject fileObj = file.toObject();
            if (fileObj[QStringLiteral("filename")].isString()) {
              QString fileName = fileObj[QStringLiteral("filename")].toString();
              QString contents;
              if (fileObj[QStringLiteral("contents")].isString()) {
                contents = fileObj[QStringLiteral("contents")].toString();
              } else if (fileObj[QStringLiteral("filePath")].isString()) {
                QFile refFile(fileObj[QStringLiteral("filePath")].toString());
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
              m_files.insert(fileObj[QStringLiteral("filename")].toString(),
                             contents);

              // Concatenate the requested styles for this input file.
              if (fileObj[QStringLiteral("highlightStyles")].isArray()) {
                auto* highlighter(new GenericHighlighter(this));
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
        } // end foreach file
      } else {
        result = false;
        m_errors << tr("'files' member not an array.");
      } // end if obj["files"] is JSON array
    } else {
      result = false;
      m_errors << tr("'files' member missing.");
    } // end if obj contains "files"

    // Extract main input filename:
    if (obj.contains(QStringLiteral("mainFile"))) {
      if (obj[QStringLiteral("mainFile")].isString()) {
        QString mainFile = obj[QStringLiteral("mainFile")].toString();
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

int InterfaceScript::numberOfInputFiles() const
{
  return m_filenames.size();
}

QStringList InterfaceScript::fileNames() const
{
  return m_filenames;
}

QString InterfaceScript::mainFileName() const
{
  return m_mainFileName;
}

QString InterfaceScript::fileContents(const QString& fileName) const
{
  return m_files.value(fileName, QString());
}

GenericHighlighter* InterfaceScript::createFileHighlighter(
  const QString& fileName) const
{
  GenericHighlighter* toClone(m_fileHighlighters.value(fileName, nullptr));
  return toClone ? new GenericHighlighter(*toClone) : toClone;
}

void InterfaceScript::setDebug(bool d)
{
  m_interpreter->setDebug(d);
}

bool InterfaceScript::parseJson(const QByteArray& json,
                                QJsonDocument& doc) const
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

bool InterfaceScript::insertMolecule(QJsonObject& json,
                                     const Core::Molecule& mol) const
{
  // Update the cached options if the format is not set
  if (m_moleculeExtension == QLatin1String("Unknown"))
    options();

  if (m_moleculeExtension == QLatin1String("None"))
    return true;

  // Always insert the selected atoms
  QJsonArray selectedList;
  for (Index i = 0; i < mol.atomCount(); ++i) {
    if (mol.atomSelected(i))
      selectedList.append(static_cast<qint64>(i));
  }
  json.insert("selectedAtoms", selectedList);

  // insert the total charge
  json.insert("charge", mol.totalCharge());

  // insert the spin multiplicity
  json.insert("spin", mol.totalSpinMultiplicity());

  Io::FileFormatManager& formats = Io::FileFormatManager::instance();
  QScopedPointer<Io::FileFormat> format(
    formats.newFormatFromFileExtension(m_moleculeExtension.toStdString()));
  QScopedPointer<Io::FileFormat> cjsonFormat(
    formats.newFormatFromFileExtension("cjson"));

  // If we want something *other* than CJSON, check that we can supply that
  // format
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

  // if we need a different format, insert it
  if (m_moleculeExtension != QLatin1String("cjson")) {
    json.insert(m_moleculeExtension, QJsonValue(QString::fromStdString(str)));
  }

  // We will *always* write the CJSON representation
  // Embed CJSON as actual JSON, rather than a string,
  // .. so we'll have to re-parse it
  cjsonFormat->writeString(str, mol);
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

  json.insert("cjson", doc.object());

  return true;
}

QString InterfaceScript::generateCoordinateBlock(
  const QString& spec, const Core::Molecule& mol) const
{
  Core::CoordinateBlockGenerator gen;
  gen.setMolecule(&mol);
  gen.setSpecification(spec.toStdString());
  std::string tmp(gen.generateCoordinateBlock());
  if (!tmp.empty())
    tmp.resize(tmp.size() - 1); // Pop off the trailing newline
  return QString::fromStdString(tmp);
}

void InterfaceScript::replaceKeywords(QString& str,
                                      const Core::Molecule& mol) const
{
  // Simple keywords:
  str.replace(QLatin1String("$$atomCount$$"), QString::number(mol.atomCount()));
  str.replace(QLatin1String("$$bondCount$$"), QString::number(mol.bondCount()));

  // Find each coordinate block keyword in the file, then generate and replace
  // it with the appropriate values.
  QRegularExpression coordParser(R"(\$\$coords:([^\$]*)\$\$)");
  QRegularExpressionMatch match;
  int ind = 0;
  // Not sure while this needs to be a while statement since we replace all in
  // one go? We never iterate ind...
  while ((match = coordParser.match(str, ind)).hasMatch()) {
    // Extract spec and prepare the replacement
    const QString keyword = match.captured(0);
    const QString spec = match.captured(1);

    // Replace all blocks with this signature
    str.replace(keyword, generateCoordinateBlock(spec, mol));

  } // end for coordinate block
}

bool InterfaceScript::parseHighlightStyles(const QJsonArray& json) const
{
  bool result(true);
  foreach (QJsonValue styleVal, json) {
    if (!styleVal.isObject()) {
      qDebug() << "Non-object in highlightStyles array.";
      result = false;
      continue;
    }
    QJsonObject styleObj(styleVal.toObject());

    if (!styleObj.contains(QStringLiteral("style"))) {
      qDebug() << "Style object missing 'style' member.";
      result = false;
      continue;
    }
    if (!styleObj.value(QStringLiteral("style")).isString()) {
      qDebug() << "Style object contains non-string 'style' member.";
      result = false;
      continue;
    }
    QString styleName(styleObj.value(QStringLiteral("style")).toString());

    if (m_highlightStyles.contains(styleName)) {
      qDebug() << "Duplicate highlight style: " << styleName;
      result = false;
      continue;
    }

    if (!styleObj.contains(QStringLiteral("rules"))) {
      qDebug() << "Style object" << styleName << "missing 'rules' member.";
      result = false;
      continue;
    }
    if (!styleObj.value(QStringLiteral("rules")).isArray()) {
      qDebug() << "Style object" << styleName
               << "contains non-array 'rules' member.";
      result = false;
      continue;
    }
    QJsonArray rulesArray(styleObj.value(QStringLiteral("rules")).toArray());

    auto* highlighter(
      new GenericHighlighter(const_cast<InterfaceScript*>(this)));
    if (!parseRules(rulesArray, *highlighter)) {
      qDebug() << "Error parsing style" << styleName << '\n'
               << QString(QJsonDocument(styleObj).toJson());
      highlighter->deleteLater();
      result = false;
      continue;
    }
    m_highlightStyles.insert(styleName, highlighter);
  }

  return result;
}

bool InterfaceScript::parseRules(const QJsonArray& json,
                                 GenericHighlighter& highlighter) const
{
  bool result(true);
  foreach (QJsonValue ruleVal, json) {
    if (!ruleVal.isObject()) {
      qDebug() << "Rule is not an object.";
      result = false;
      continue;
    }
    QJsonObject ruleObj(ruleVal.toObject());

    if (!ruleObj.contains(QStringLiteral("patterns"))) {
      qDebug() << "Rule missing 'patterns' array:" << '\n'
               << QString(QJsonDocument(ruleObj).toJson());
      result = false;
      continue;
    }
    if (!ruleObj.value(QStringLiteral("patterns")).isArray()) {
      qDebug() << "Rule 'patterns' member is not an array:" << '\n'
               << QString(QJsonDocument(ruleObj).toJson());
      result = false;
      continue;
    }
    QJsonArray patternsArray(
      ruleObj.value(QStringLiteral("patterns")).toArray());

    if (!ruleObj.contains(QStringLiteral("format"))) {
      qDebug() << "Rule missing 'format' object:" << '\n'
               << QString(QJsonDocument(ruleObj).toJson());
      result = false;
      continue;
    }
    if (!ruleObj.value(QStringLiteral("format")).isObject()) {
      qDebug() << "Rule 'format' member is not an object:" << '\n'
               << QString(QJsonDocument(ruleObj).toJson());
      result = false;
      continue;
    }
    QJsonObject formatObj(ruleObj.value(QStringLiteral("format")).toObject());

    GenericHighlighter::Rule& rule = highlighter.addRule();

    foreach (QJsonValue patternVal, patternsArray) {
      QRegularExpression pattern;
      if (!parsePattern(patternVal, pattern)) {
        qDebug() << "Error while parsing pattern:" << '\n'
                 << QString(QJsonDocument(patternVal.toObject()).toJson());
        result = false;
        continue;
      }
      rule.addPattern(pattern);
    }

    QTextCharFormat format;
    if (!parseFormat(formatObj, format)) {
      qDebug() << "Error while parsing format:" << '\n'
               << QString(QJsonDocument(formatObj).toJson());
      result = false;
    }
    rule.setFormat(format);
  }

  return result;
}

bool InterfaceScript::parseFormat(const QJsonObject& json,
                                  QTextCharFormat& format) const
{
  // Check for presets first:
  if (json.contains(QStringLiteral("preset"))) {
    if (!json[QStringLiteral("preset")].isString()) {
      qDebug() << "Preset is not a string.";
      return false;
    }

    QString preset(json[QStringLiteral("preset")].toString());
    /// @todo Store presets in a singleton that can be configured in the GUI,
    /// rather than hardcoding them.
    if (preset == QLatin1String("title")) {
      format.setFontFamily(QStringLiteral("serif"));
      format.setForeground(Qt::darkGreen);
      format.setFontWeight(QFont::Bold);
    } else if (preset == QLatin1String("keyword")) {
      format.setFontFamily(QStringLiteral("mono"));
      format.setForeground(Qt::darkBlue);
    } else if (preset == QLatin1String("property")) {
      format.setFontFamily(QStringLiteral("mono"));
      format.setForeground(Qt::darkRed);
    } else if (preset == QLatin1String("literal")) {
      format.setFontFamily(QStringLiteral("mono"));
      format.setForeground(Qt::darkMagenta);
    } else if (preset == QLatin1String("comment")) {
      format.setFontFamily(QStringLiteral("serif"));
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

  if (json.contains(QStringLiteral("foreground")) &&
      json.value(QStringLiteral("foreground")).isArray()) {
    QJsonArray foregroundArray(
      json.value(QStringLiteral("foreground")).toArray());
    bool ok;
    format.setForeground(colorParser(foregroundArray, &ok));
    if (!ok)
      return false;
  }

  if (json.contains(QStringLiteral("background")) &&
      json.value(QStringLiteral("background")).isArray()) {
    QJsonArray backgroundArray(
      json.value(QStringLiteral("background")).toArray());
    bool ok;
    format.setBackground(colorParser(backgroundArray, &ok));
    if (!ok)
      return false;
  }

  if (json.contains(QStringLiteral("attributes")) &&
      json.value(QStringLiteral("attributes")).isArray()) {
    QJsonArray attributesArray(
      json.value(QStringLiteral("attributes")).toArray());
    format.setFontWeight(attributesArray.contains(QLatin1String("bold"))
                           ? QFont::Bold
                           : QFont::Normal);
    format.setFontItalic(attributesArray.contains(QLatin1String("italic")));
    format.setFontUnderline(
      attributesArray.contains(QLatin1String("underline")));
  }

  if (json.contains(QStringLiteral("family")) &&
      json.value(QStringLiteral("family")).isString()) {
    format.setFontFamily(json.value(QStringLiteral("family")).toString());
  }

  return true;
}

bool InterfaceScript::parsePattern(const QJsonValue& json,
                                   QRegularExpression& pattern) const
{
  if (!json.isObject())
    return false;

  QJsonObject patternObj(json.toObject());
  QString regexPattern;
  QRegularExpression::PatternOptions patternOptions =
    QRegularExpression::NoPatternOption;

  if (patternObj.contains(QStringLiteral("regexp")) &&
      patternObj.value(QStringLiteral("regexp")).isString()) {
    // Use the provided regular expression as-is
    regexPattern = patternObj.value(QStringLiteral("regexp")).toString();
  } else if (patternObj.contains(QStringLiteral("wildcard")) &&
             patternObj.value(QStringLiteral("wildcard")).isString()) {
    // Convert wildcard pattern (* -> .* and ? -> .)
    QString wildcard = patternObj.value(QStringLiteral("wildcard")).toString();
    regexPattern = QRegularExpression::escape(wildcard)
                     .replace("\\*", ".*")
                     .replace("\\?", ".");
  } else if (patternObj.contains(QStringLiteral("string")) &&
             patternObj.value(QStringLiteral("string")).isString()) {
    // Escape the string so it is treated literally in the regex
    regexPattern = QRegularExpression::escape(
      patternObj.value(QStringLiteral("string")).toString());
  } else {
    return false;
  }

  // Set case sensitivity if specified
  if (patternObj.contains(QStringLiteral("caseSensitive"))) {
    bool caseSensitive =
      patternObj.value(QStringLiteral("caseSensitive")).toBool(true);
    if (!caseSensitive) {
      patternOptions |= QRegularExpression::CaseInsensitiveOption;
    }
  }

  // Set the final pattern with options
  pattern = QRegularExpression(regexPattern, patternOptions);

  return pattern.isValid();
}

} // namespace Avogadro::QtGui
