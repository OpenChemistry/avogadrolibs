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

#include <QtGui/QSyntaxHighlighter>
#include <QtGui/QTextCharFormat>

class QRegExp;

namespace Avogadro {
namespace QtPlugins {

/**
 * @brief The GenericHighlighter class provides a regexp-based programmable
 * syntax highlighter.
 */
class GenericHighlighter : public QSyntaxHighlighter
{
  Q_OBJECT
public:
  class Rule
  {
  public:
    Rule() {}
    ~Rule() {}

    void addPattern(const QRegExp &regexp);
    void setFormat(const QTextCharFormat &format);

    void apply(const QString &text, GenericHighlighter &highligher);

  private:
    QList<QRegExp> m_patterns;
    QTextCharFormat m_format;
  };

  explicit GenericHighlighter(QObject *parent_ = 0);
  ~GenericHighlighter();
  GenericHighlighter(const GenericHighlighter &other);
  GenericHighlighter& operator=(GenericHighlighter other);
  GenericHighlighter& operator+=(const GenericHighlighter &other);

  Rule& addRule();
  int ruleCount() const;
  Rule& rule(int idx);
  const Rule& rule(int idx) const;
  QList<Rule> rules() const;

  friend void swap(GenericHighlighter &first, GenericHighlighter &second)
  {
    using std::swap;
    swap(first.m_rules, second.m_rules);
  }

protected:
  void highlightBlock(const QString &text);

private:
  QList<Rule> m_rules;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_GENERICHIGHLIGHTER_H
