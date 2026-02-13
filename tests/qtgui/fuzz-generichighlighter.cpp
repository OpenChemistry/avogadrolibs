/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <fuzzer/FuzzedDataProvider.h>

#include <QtCore/QCoreApplication>
#include <QtGui/QTextDocument>

#include <avogadro/qtgui/generichighlighter.h>

#include <QRegularExpression>

using namespace Avogadro::QtGui;

namespace {

constexpr size_t kMaxPatternLen = 256;
constexpr size_t kMaxTextLen = 4096;
constexpr size_t kMaxRules = 16;
constexpr size_t kMaxPatternsPerRule = 4;

QCoreApplication* ensureApp()
{
  static int argc = 1;
  static char arg0[] = "fuzz";
  static char* argv[] = { arg0, nullptr };
  static QCoreApplication app(argc, argv);
  return &app;
}

} // namespace

// Fuzz GenericHighlighter with random regex patterns and text.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
  ensureApp();

  FuzzedDataProvider fdp(Data, Size);

  // Build a text document (required parent for QSyntaxHighlighter)
  QTextDocument doc;
  GenericHighlighter highlighter(&doc);

  // Create random rules with random regex patterns
  size_t numRules = fdp.ConsumeIntegralInRange<size_t>(1, kMaxRules);
  for (size_t i = 0; i < numRules && fdp.remaining_bytes() > 0; ++i) {
    GenericHighlighter::Rule& rule = highlighter.addRule();

    size_t numPatterns =
      fdp.ConsumeIntegralInRange<size_t>(1, kMaxPatternsPerRule);
    for (size_t j = 0; j < numPatterns && fdp.remaining_bytes() > 0; ++j) {
      std::string patStr = fdp.ConsumeRandomLengthString(kMaxPatternLen);
      QRegularExpression re(QString::fromStdString(patStr));
      // Only add valid patterns (invalid ones would just be skipped in
      // production code too, but we test that isValid() doesn't crash)
      if (re.isValid())
        rule.addPattern(re);
    }

    // Set a simple format
    QTextCharFormat fmt;
    fmt.setFontWeight(fdp.ConsumeBool() ? QFont::Bold : QFont::Normal);
    fmt.setFontItalic(fdp.ConsumeBool());
    rule.setFormat(fmt);
  }

  // Generate text to highlight and set it on the document
  // (setting text triggers highlightBlock for each block)
  std::string text = fdp.ConsumeRandomLengthString(kMaxTextLen);
  doc.setPlainText(QString::fromStdString(text));

  // Also test copy construction and operator+=
  if (highlighter.ruleCount() > 0) {
    GenericHighlighter copy(highlighter);
    GenericHighlighter combined(&doc);
    combined += copy;
  }

  return 0;
}
