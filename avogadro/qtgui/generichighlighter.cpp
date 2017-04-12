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

#include "generichighlighter.h"

#include <cassert>

namespace Avogadro {
namespace QtGui {

GenericHighlighter::GenericHighlighter(QObject* parent_)
  : QSyntaxHighlighter(parent_)
{
}

GenericHighlighter::~GenericHighlighter()
{
}

GenericHighlighter::GenericHighlighter(const GenericHighlighter& other)
  : QSyntaxHighlighter(static_cast<QTextDocument*>(nullptr))
{
  m_rules = other.m_rules;
}

GenericHighlighter& GenericHighlighter::operator=(GenericHighlighter other)
{
  swap(*this, other);
  return *this;
}

GenericHighlighter& GenericHighlighter::operator+=(
  const GenericHighlighter& other)
{
  m_rules.append(other.m_rules);
  return *this;
}

GenericHighlighter::Rule& GenericHighlighter::addRule()
{
  m_rules.push_back(Rule());
  return m_rules.back();
}

int GenericHighlighter::ruleCount() const
{
  return m_rules.size();
}

GenericHighlighter::Rule& GenericHighlighter::rule(int idx)
{
  assert("idx in bounds" && idx < m_rules.size());
  return m_rules[idx];
}

const GenericHighlighter::Rule& GenericHighlighter::rule(int idx) const
{
  assert("idx in bounds" && idx < m_rules.size());
  return m_rules[idx];
}

QList<GenericHighlighter::Rule> GenericHighlighter::rules() const
{
  return m_rules;
}

void GenericHighlighter::highlightBlock(const QString& text)
{
  typedef QList<Rule>::iterator RuleIter;
  for (RuleIter it = m_rules.begin(), end = m_rules.end(); it != end; ++it)
    it->apply(text, *this);
}

void GenericHighlighter::Rule::apply(const QString& text,
                                     GenericHighlighter& highlighter)
{
  typedef QList<QRegExp>::iterator PatternIter;
  for (PatternIter it = m_patterns.begin(), end = m_patterns.end(); it != end;
       ++it) {
    int index = it->indexIn(text);
    while (index >= 0) {
      // If using a regex with capture groups defined, only highlight the
      // capture groups.
      if (it->captureCount() > 0) {
        QStringList capturedTexts(it->capturedTexts());
        QString match(capturedTexts.takeFirst());
        foreach (const QString& capture, capturedTexts) {
          int capOffset(match.indexOf(capture));
          while (capOffset > 0) {
            int capLength(capture.size());
            highlighter.setFormat(index + capOffset, capLength, m_format);
            capOffset = match.indexOf(capture, capOffset + capLength);
          }
        }
        index = it->indexIn(text, index + match.size());
      } else {
        int length(it->matchedLength());
        highlighter.setFormat(index, length, m_format);
        index = it->indexIn(text, index + length);
      }
    }
  }
}

void GenericHighlighter::Rule::addPattern(const QRegExp& regexp)
{
  m_patterns.append(regexp);
}

void GenericHighlighter::Rule::setFormat(const QTextCharFormat& format)
{
  m_format = format;
}

} // namespace QtPlugins
} // namespace Avogadro
