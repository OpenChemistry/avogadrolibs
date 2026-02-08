/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/qtgui/generichighlighter.h>

#include <QtGui/QBrush>
#include <QtGui/QTextCharFormat>
#include <QtGui/QTextCursor>
#include <QtGui/QTextDocument>
#include <QtGui/QTextDocumentFragment>
#include <QtGui/QTextLayout>

using Avogadro::QtGui::GenericHighlighter;

namespace {

// Extended GenericHighlighter that can export to html. Taken from
// http://stackoverflow.com/questions/15280452
// This is used to verify that the rules properly highlight the correct portions
// of text.
// (You'd think QTextDocument::toHtml() would do this. It doesn't. :-/ )
class GenericHighlighterHtml : public GenericHighlighter
{
public:
  void asHtml(QString& html)
  {
    // Create a new document from all the selected text document.
    QTextCursor cursor(document());
    cursor.select(QTextCursor::Document);
    QTextDocument* tempDocument(new QTextDocument);
    Q_ASSERT(tempDocument);
    QTextCursor tempCursor(tempDocument);

    tempCursor.insertFragment(cursor.selection());
    tempCursor.select(QTextCursor::Document);
    // Set the default foreground for the inserted characters.
    QTextCharFormat textfmt = tempCursor.charFormat();
    textfmt.setForeground(Qt::gray);
    tempCursor.setCharFormat(textfmt);

    // Apply the additional formats set by the syntax highlighter
    QTextBlock start = document()->findBlock(cursor.selectionStart());
    QTextBlock end = document()->findBlock(cursor.selectionEnd());
    end = end.next();
    const int selectionStart = cursor.selectionStart();
    const int endOfDocument = tempDocument->characterCount() - 1;
    for (QTextBlock current = start; current.isValid() && current != end;
         current = current.next()) {
      const QTextLayout* layout(current.layout());

      foreach (const QTextLayout::FormatRange& range, layout->formats()) {
        const int startIdx = current.position() + range.start - selectionStart;
        const int endIdx = startIdx + range.length;
        if (endIdx <= 0 || startIdx >= endOfDocument)
          continue;
        tempCursor.setPosition(qMax(startIdx, 0));
        tempCursor.setPosition(qMin(endIdx, endOfDocument),
                               QTextCursor::KeepAnchor);
        tempCursor.setCharFormat(range.format);
      }
    }

    // Reset the user states since they are not interesting
    for (QTextBlock block = tempDocument->begin(); block.isValid();
         block = block.next()) {
      block.setUserState(-1);
    }

    // Make sure the text appears pre-formatted, and set the background we want.
    tempCursor.select(QTextCursor::Document);
    QTextBlockFormat blockFormat = tempCursor.blockFormat();
    blockFormat.setNonBreakableLines(true);
    // blockFormat.setBackground(Qt::black);
    tempCursor.setBlockFormat(blockFormat);

    // Finally retrieve the syntax highlighted and formatted html.
    html = tempCursor.selection().toHtml();
    delete tempDocument;
  }
};

} // namespace

TEST(GenericHighlighterTest, exercise)
{
  QTextDocument doc("A regexp will turn this blue.\n"
                    "Only this and that will be yellow.\n"
                    "A wildcard expression will turn this red.\n"
                    "This string will be green.\n");

  GenericHighlighterHtml highlighter;
  QTextCharFormat format;

  GenericHighlighter::Rule& regexpRule = highlighter.addRule();
  regexpRule.addPattern(QRegularExpression("^.*regexp.*$"));
  format.setForeground(Qt::blue);
  regexpRule.setFormat(format);

  GenericHighlighter::Rule& regexpCapRule = highlighter.addRule();
  regexpCapRule.addPattern(QRegularExpression("^.*(this)[^\n]*(that).*$"));
  format.setForeground(Qt::yellow);
  regexpCapRule.setFormat(format);

  // Regex equivalent of the old QRegExp wildcard "A wildcard*red."
  GenericHighlighter::Rule& wildcardRule = highlighter.addRule();
  wildcardRule.addPattern(QRegularExpression("^A wildcard.*red\\.$"));
  format.setForeground(Qt::red);
  wildcardRule.setFormat(format);

  GenericHighlighter::Rule& stringRule = highlighter.addRule();
  stringRule.addPattern(QRegularExpression("This string will be green."));
  format.setForeground(Qt::green);
  stringRule.setFormat(format);

  highlighter.setDocument(&doc);
  highlighter.rehighlight();

  QString html;
  highlighter.asHtml(html);

  // Verify the highlighted spans are present (Qt version-independent checks)
  EXPECT_TRUE(html.contains("color:#0000ff;\">A regexp will turn this blue."))
    << "Blue regexp rule should highlight first line";
  EXPECT_TRUE(html.contains("color:#ffff00;\">this"))
    << "Yellow capture rule should highlight 'this'";
  EXPECT_TRUE(html.contains("color:#ffff00;\">that"))
    << "Yellow capture rule should highlight 'that'";
  EXPECT_TRUE(
    html.contains("color:#ff0000;\">A wildcard expression will turn this red."))
    << "Red wildcard rule should highlight third line";
  EXPECT_TRUE(html.contains("color:#00ff00;\">This string will be green."))
    << "Green string rule should highlight fourth line";
}
