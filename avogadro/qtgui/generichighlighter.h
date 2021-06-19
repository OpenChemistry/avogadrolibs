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

#ifndef AVOGADRO_QTPLUGINS_GENERICHIGHLIGHTER_H
#define AVOGADRO_QTPLUGINS_GENERICHIGHLIGHTER_H

#include "avogadroqtguiexport.h"

#include <avogadro/core/avogadrocore.h>

#include <QtGui/QSyntaxHighlighter>
#include <QtGui/QTextCharFormat>

class QRegExp;

namespace Avogadro {
namespace QtGui {

/**
 * @brief The GenericHighlighter class provides a regexp-based programmable
 * syntax highlighter.
 */
class AVOGADROQTGUI_EXPORT GenericHighlighter : public QSyntaxHighlighter
{
  Q_OBJECT
public:
  /**
   * @brief The Rule class stores a syntax highlighting rule as a set of QRegExp
   * patterns and a text format.
   */
  class AVOGADROQTGUI_EXPORT Rule
  {
  public:
    Rule() {}
    ~Rule() {}

    /** Add the pattern @a regexp to this Rule. */
    void addPattern(const QRegExp& regexp);

    /** Set this Rule's text format. */
    void setFormat(const QTextCharFormat& format);

    /** Apply this rule to the string of text, updating the highlighter if any
     *  matches are found. */
    void apply(const QString& text, GenericHighlighter& highlighter);

  private:
    QList<QRegExp> m_patterns;
    QTextCharFormat m_format;
  };

  /** Construct a highlighter with an empty rule set. */
  explicit GenericHighlighter(QObject* parent_ = nullptr);

  ~GenericHighlighter() override;

  /** Construct a new highlighter using the rule set of @a other. */
  GenericHighlighter(const GenericHighlighter& other);

  /** Replace this highlighter's rule set with that of @a other. */
  GenericHighlighter& operator=(GenericHighlighter other);

  /** Concatenate @a other's rule set with this highlighter's rule set. */
  GenericHighlighter& operator+=(const GenericHighlighter& other);

  /** Add a new rule to this highlighter, returning a reference to the new
   *  rule. */
  Rule& addRule();

  /** @return The number of rules in this highlighter. */
  int ruleCount() const;

  /** @return A reference to the rule at the specified zero-based index. */
  Rule& rule(int idx);

  /** @return A reference to the rule at the specified zero-based index. */
  const Rule& rule(int idx) const;

  /** @return An ordered list of this highlighter's rules. */
  QList<Rule> rules() const;

  friend void swap(GenericHighlighter& first, GenericHighlighter& second)
  {
    using std::swap;
    swap(first.m_rules, second.m_rules);
  }

protected:
  void highlightBlock(const QString& text) override;

private:
  QList<Rule> m_rules;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_GENERICHIGHLIGHTER_H
