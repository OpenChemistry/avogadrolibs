/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "generichighlighter.h"

#include <cassert>

namespace Avogadro::QtGui {

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
  for (auto & m_rule : m_rules)
    m_rule.apply(text, *this);
}

void GenericHighlighter::Rule::apply(const QString& text,
                                     GenericHighlighter& highlighter)
{
  typedef QList<QRegExp>::iterator PatternIter;
  for (auto & m_pattern : m_patterns) {
    int index = m_pattern.indexIn(text);
    while (index >= 0) {
      // If using a regex with capture groups defined, only highlight the
      // capture groups.
      if (m_pattern.captureCount() > 0) {
        QStringList capturedTexts(m_pattern.capturedTexts());
        QString match(capturedTexts.takeFirst());
        foreach (const QString& capture, capturedTexts) {
          int capOffset(match.indexOf(capture));
          while (capOffset > 0) {
            int capLength(capture.size());
            highlighter.setFormat(index + capOffset, capLength, m_format);
            capOffset = match.indexOf(capture, capOffset + capLength);
          }
        }
        index = m_pattern.indexIn(text, index + match.size());
      } else {
        int length(m_pattern.matchedLength());
        highlighter.setFormat(index, length, m_format);
        index = m_pattern.indexIn(text, index + length);
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

} // namespace Avogadro
