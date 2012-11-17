/**********************************************************************
  GamessHighlighter - syntax highlighting for Gamess input files

  Copyright (C) 2009 Marcus D. Hanwell

  This file is part of the Avogadro molecular editor project.
  For more information, see <http://avogadro.openmolecules.net/>

  This library is free software; you can redistribute it and/or modify
  it under the terms of the GNU Library General Public License as
  published by the Free Software Foundation; either version 2.1 of the
  License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
  02110-1301, USA.
 **********************************************************************/

#ifndef GAMESSHIGHLIGHTER_H
#define GAMESSHIGHLIGHTER_H

#include <QSyntaxHighlighter>

#include <QTextCharFormat>
#include <QRegExp>
#include <QStringList>

class QTextDocument;

namespace Avogadro {
namespace QtPlugins {

  class GamessHighlighter : public QSyntaxHighlighter
  {
    Q_OBJECT

  public:
    GamessHighlighter(QTextDocument *parent = 0);

  protected:
    void highlightBlock(const QString &text);

  private:
    struct HighlightingRule {
      QRegExp pattern;
      QTextCharFormat format;
    };
    QVector<HighlightingRule> m_highlightingRules;

    QStringList m_keywords;

    QRegExp m_commentStartExpression;
    QRegExp m_commentEndExpression;

    QTextCharFormat m_keywordFormat;
    QTextCharFormat m_numberFormat;
    QTextCharFormat m_singleLineCommentFormat;
    QTextCharFormat m_inDataBlockFormat;
    QTextCharFormat m_errorFormat;

  };

} // End namespace QtPlugins
} // End namespace Avogadro

#endif // GAMESSHIGHLIGHTER_H
