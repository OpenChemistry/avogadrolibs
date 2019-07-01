/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright (C) 2009 Marcus D. Hanwell

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef SIMUNESIESTAHIGHLIGHTER_H
#define SIMUNESIESTAHIGHLIGHTER_H

#include <QSyntaxHighlighter>

#include <QTextCharFormat>
#include <QRegExp>
#include <QStringList>

class QTextDocument;

namespace Avogadro {
namespace QtPlugins {

  class SimuneSiestaHighlighter : public QSyntaxHighlighter
  {
    Q_OBJECT

  public:
    SimuneSiestaHighlighter(QTextDocument *parent_ = 0);

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
    QTextCharFormat m_routeLineCommentFormat;
    QTextCharFormat m_procsLineCommentFormat;
    QTextCharFormat m_inDataBlockFormat;
    QTextCharFormat m_errorFormat;

  };

} // End namespace QtPlugins
} // End namespace Avogadro

#endif // SIMUNESIESTAHIGHLIGHTER_H
