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

GenericHighlighter::~GenericHighlighter() {}

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
  for (auto& m_rule : m_rules)
    m_rule.apply(text, *this);
}

void GenericHighlighter::Rule::apply(const QString& text,
                                     GenericHighlighter& highlighter)
{
  for (auto& m_pattern : m_patterns) {
    // each m_pattern is a QRegularExpression
    // We want to highlight every occurrence of m_pattern
    QRegularExpressionMatchIterator iterator = m_pattern.globalMatch(text);
    while (iterator.hasNext()) {
      QRegularExpressionMatch match = iterator.next();
      // If using a regex with capture groups defined, we explicitly don't want
      // to highlight the whole expression, only the capture groups
      if (m_pattern.captureCount() > 0) {
        // Iterate over capture groups, skipping the implicit group 0
        for (int i = 1; i <= match.lastCapturedIndex(); ++i) {
          QString captured = match.captured(i);
          if (!captured.isNull()) {
            // According to StackOverflow user "peppe", who claims to have
            // written the whole QRegularExpression class, the index returned is
            // relative to the whole string, not to the current match
            // https://stackoverflow.com/questions/28725588/qregularexpression-match-position-in-the-source-string
            int index = match.capturedStart(i);
            int length = match.capturedLength(i);
            highlighter.setFormat(index, length, m_format);
          }
        }
      } else {
        // Straightforward regex with no capture groups, highlight whole match
        int index = match.capturedStart(0);
        int length = match.capturedLength(0);
        highlighter.setFormat(index, length, m_format);
      }
    }
  }
}

void GenericHighlighter::Rule::addPattern(const QRegularExpression& regexp)
{
  m_patterns.append(regexp);
}

void GenericHighlighter::Rule::setFormat(const QTextCharFormat& format)
{
  m_format = format;
}

} // namespace Avogadro::QtGui
