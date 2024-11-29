/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef GAMESSHIGHLIGHTER_H
#define GAMESSHIGHLIGHTER_H

#include <QSyntaxHighlighter>

#include <QRegularExpression>
#include <QStringList>
#include <QTextCharFormat>

class QTextDocument;

namespace Avogadro {
namespace QtPlugins {

class GamessHighlighter : public QSyntaxHighlighter
{
  Q_OBJECT

public:
  GamessHighlighter(QTextDocument* parent_ = nullptr);

protected:
  void highlightBlock(const QString& text) override;

private:
  struct HighlightingRule
  {
    QRegularExpression pattern;
    QTextCharFormat format;
  };
  QVector<HighlightingRule> m_highlightingRules;

  QStringList m_keywords;

  QRegularExpression m_commentStartExpression;
  QRegularExpression m_commentEndExpression;

  QTextCharFormat m_keywordFormat;
  QTextCharFormat m_numberFormat;
  QTextCharFormat m_singleLineCommentFormat;
  QTextCharFormat m_inDataBlockFormat;
  QTextCharFormat m_errorFormat;
};

} // End namespace QtPlugins
} // End namespace Avogadro

#endif // GAMESSHIGHLIGHTER_H
