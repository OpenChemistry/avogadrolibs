/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <fuzzer/FuzzedDataProvider.h>

#include <QtCore/QCoreApplication>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>

#include <avogadro/core/molecule.h>
#include <avogadro/qtgui/generichighlighter.h>
#include <avogadro/qtgui/interfacescript.h>

#include <QRegularExpression>
#include <QTextCharFormat>

#include "fuzzhelpers.h"

using namespace Avogadro;
using namespace Avogadro::QtGui;

namespace {

constexpr size_t kMaxJsonLen = 8192;
constexpr size_t kMaxStringLen = 4096;

QCoreApplication* ensureApp()
{
  static int argc = 1;
  static char arg0[] = "fuzz";
  static char* argv[] = { arg0, nullptr };
  static QCoreApplication app(argc, argv);
  return &app;
}

/// Thin subclass to access protected parsing methods for fuzzing.
class FuzzableInterfaceScript : public InterfaceScript
{
public:
  explicit FuzzableInterfaceScript(QObject* parent = nullptr)
    : InterfaceScript(parent)
  {
  }

  bool fuzzParseJson(const QByteArray& json, QJsonDocument& doc) const
  {
    return parseJson(json, doc);
  }

  bool fuzzParseHighlightStyles(const QJsonArray& json) const
  {
    return parseHighlightStyles(json);
  }

  bool fuzzParseRules(const QJsonArray& json,
                      GenericHighlighter& highlighter) const
  {
    return parseRules(json, highlighter);
  }

  bool fuzzParseFormat(const QJsonObject& json, QTextCharFormat& format) const
  {
    return parseFormat(json, format);
  }

  bool fuzzParsePattern(const QJsonValue& json,
                        QRegularExpression& pattern) const
  {
    return parsePattern(json, pattern);
  }

  void fuzzReplaceKeywords(QString& str, const Core::Molecule& mol) const
  {
    replaceKeywords(str, mol);
  }
};

} // namespace

// Fuzz InterfaceScript JSON parsing: highlight styles, rules, patterns,
// formats, and keyword replacement.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
  ensureApp();

  FuzzedDataProvider fdp(Data, Size);
  FuzzableInterfaceScript script;

  // Split the fuzz input: use part as JSON, part as a string for keywords
  size_t jsonLen = fdp.ConsumeIntegralInRange<size_t>(0, kMaxJsonLen);
  std::string jsonStr = fdp.ConsumeRandomLengthString(jsonLen);
  QByteArray jsonBytes(jsonStr.data(), static_cast<int>(jsonStr.size()));

  // 1. Fuzz parseJson
  QJsonDocument doc;
  if (!script.fuzzParseJson(jsonBytes, doc))
    goto keywords; // Not valid JSON — skip to keyword testing

  // 2. If the top level is an array, fuzz parseHighlightStyles
  if (doc.isArray()) {
    script.fuzzParseHighlightStyles(doc.array());
  }

  // 3. If the top level is an object, try multiple parsing paths
  if (doc.isObject()) {
    QJsonObject obj = doc.object();

    // Try parseFormat
    {
      QTextCharFormat fmt;
      script.fuzzParseFormat(obj, fmt);
    }

    // Try parsePattern (expects an object with regexp/wildcard/string)
    {
      QRegularExpression pattern;
      script.fuzzParsePattern(QJsonValue(obj), pattern);
    }

    // If object has "rules" array, try parseRules
    if (obj.contains("rules") && obj["rules"].isArray()) {
      GenericHighlighter highlighter;
      script.fuzzParseRules(obj["rules"].toArray(), highlighter);
    }

    // If object has "highlightStyles" array, try parseHighlightStyles
    if (obj.contains("highlightStyles") && obj["highlightStyles"].isArray()) {
      script.fuzzParseHighlightStyles(obj["highlightStyles"].toArray());
    }
  }

keywords:
  // 4. Fuzz replaceKeywords with a random string and a fuzzed molecule
  if (fdp.remaining_bytes() > 0) {
    Core::Molecule mol = FuzzHelpers::buildMolecule(fdp);
    std::string kwStr = fdp.ConsumeRandomLengthString(kMaxStringLen);
    QString text = QString::fromStdString(kwStr);
    script.fuzzReplaceKeywords(text, mol);
  }

  return 0;
}
