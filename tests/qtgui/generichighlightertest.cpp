/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

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

      foreach (const QTextLayout::FormatRange& range,
               layout->additionalFormats()) {
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

} // end anon namespace

// This currently seg faults...
TEST(DISABLED_GenericHighlighterTest, exercise)
{
  QTextDocument doc("A regexp will turn this blue.\n"
                    "Only this and that will be yellow.\n"
                    "A wildcard expression will turn this red.\n"
                    "This string will be green.\n");

  GenericHighlighterHtml highlighter;
  QTextCharFormat format;

  GenericHighlighter::Rule& regexpRule = highlighter.addRule();
  regexpRule.addPattern(
    QRegExp("^.*regexp.*$", Qt::CaseSensitive, QRegExp::RegExp));
  format.setForeground(Qt::blue);
  regexpRule.setFormat(format);

  GenericHighlighter::Rule& regexpCapRule = highlighter.addRule();
  regexpCapRule.addPattern(
    QRegExp("^.*(this)[^\n]*(that).*$", Qt::CaseSensitive, QRegExp::RegExp));
  format.setForeground(Qt::yellow);
  regexpCapRule.setFormat(format);

  GenericHighlighter::Rule& wildcardRule = highlighter.addRule();
  wildcardRule.addPattern(
    QRegExp("A w*red.", Qt::CaseSensitive, QRegExp::Wildcard));
  format.setForeground(Qt::red);
  wildcardRule.setFormat(format);

  GenericHighlighter::Rule& stringRule = highlighter.addRule();
  stringRule.addPattern(QRegExp("This string will be green.", Qt::CaseSensitive,
                                QRegExp::FixedString));
  format.setForeground(Qt::green);
  stringRule.setFormat(format);

  highlighter.setDocument(&doc);
  highlighter.rehighlight();

  QString html;
  highlighter.asHtml(html);

  QString refHtml(
    "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" "
    "\"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
    "<html><head><meta name=\"qrichtext\" content=\"1\" />"
    "<style type=\"text/css\">\n"
    "p, li { white-space: pre-wrap; }\n"
    "</style></head><body>\n"
    "<pre style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; "
    "margin-right:0px; -qt-block-indent:0; text-indent:0px;\">"
    "<!--StartFragment--><span style=\" color:#0000ff;\">"
    "A regexp will turn this blue.</span></pre>\n"
    "<pre style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; "
    "margin-right:0px; -qt-block-indent:0; text-indent:0px;\">"
    "<span style=\" color:#a0a0a4;\">"
    "Only </span><span style=\" color:#ffff00;\">"
    "this</span><span style=\" color:#a0a0a4;\"> "
    "and </span><span style=\" color:#ffff00;\">"
    "that</span><span style=\" color:#a0a0a4;\"> "
    "will be yellow.</span></pre>\n"
    "<pre style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; "
    "margin-right:0px; -qt-block-indent:0; text-indent:0px;\">"
    "<span style=\" color:#ff0000;\">"
    "A wildcard expression will turn this red.</span></pre>\n"
    "<pre style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; "
    "margin-right:0px; -qt-block-indent:0; text-indent:0px;\">"
    "<span style=\" color:#00ff00;\">"
    "This string will be green.</span></pre>\n"
    "<pre style=\"-qt-paragraph-type:empty; margin-top:0px; "
    "margin-bottom:0px; margin-left:0px; margin-right:0px; "
    "-qt-block-indent:0; text-indent:0px; color:#a0a0a4;\">"
    "<br /><!--EndFragment--></pre></body></html>");

  EXPECT_STREQ(qPrintable(refHtml), qPrintable(html));
}
