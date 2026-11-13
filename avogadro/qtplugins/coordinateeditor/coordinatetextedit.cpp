/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "coordinatetextedit.h"

#include <avogadro/qtgui/colortheme.h>

#include <QtGui/QColor>
#include <QtGui/QHelpEvent>
#include <QtGui/QPalette>
#include <QtGui/QTextCursor>
#include <QtWidgets/QApplication>
#include <QtWidgets/QToolTip>

#include <QtCore/QListIterator>

namespace Avogadro::QtPlugins {

CoordinateTextEdit::CoordinateTextEdit(QWidget* p)
  : QTextEdit(p), m_hasInvalidMarks(false)
{
  setMouseTracking(true);

  m_unmarkedFormat.setUnderlineStyle(QTextCharFormat::NoUnderline);
  m_invalidFormat.setUnderlineStyle(QTextCharFormat::SpellCheckUnderline);
  m_validFormat.setUnderlineStyle(QTextCharFormat::NoUnderline);
  updateFormatColors();
}

void CoordinateTextEdit::updateFormatColors()
{
  // Pick shades for the light or dark theme, so marked text keeps at least
  // 4.5:1 contrast in both.
  const QPalette& pal = palette();
  const bool darkMode = QtGui::colorTheme() == QtGui::ColorTheme::Dark;

  m_unmarkedFormat.setForeground(pal.color(QPalette::Text));
  m_unmarkedFormat.setBackground(pal.color(QPalette::Base));

  if (darkMode) {
    m_invalidFormat.setForeground(QColor(255, 150, 150));
    m_invalidFormat.setBackground(QColor(70, 25, 25));
    m_validFormat.setForeground(QColor(120, 220, 120));
  } else {
    m_invalidFormat.setForeground(QColor(170, 0, 0));
    m_invalidFormat.setBackground(QColor(255, 235, 235));
    m_validFormat.setForeground(QColor(0, 120, 0));
  }
}

void CoordinateTextEdit::changeEvent(QEvent* e)
{
  // New text is marked with the current theme's colors after a switch.
  if (e->type() == QEvent::PaletteChange)
    updateFormatColors();
  QTextEdit::changeEvent(e);
}

void CoordinateTextEdit::resetMarks()
{
  m_hasInvalidMarks = false;
  m_marks.clear();
  if (!document()->isEmpty()) {
    QTextCursor cur(document());
    cur.movePosition(QTextCursor::End, QTextCursor::KeepAnchor);
    cur.mergeCharFormat(m_unmarkedFormat);
  }
}

void CoordinateTextEdit::markInvalid(QTextCursor& cur, const QString& tooltip)
{
  m_hasInvalidMarks = true;
  cur.mergeCharFormat(m_invalidFormat);
  m_marks.append(Mark(cur.anchor(), cur.position(), tooltip));
}

void CoordinateTextEdit::markValid(QTextCursor& cur, const QString& tooltip)
{
  cur.mergeCharFormat(m_validFormat);
  m_marks.append(Mark(cur.anchor(), cur.position(), tooltip));
}

bool CoordinateTextEdit::event(QEvent* e)
{
  if (e->type() == QEvent::ToolTip) {
    auto* helpEvent = dynamic_cast<QHelpEvent*>(e);
    showToolTip(helpEvent);
    return true;
  }
  return QTextEdit::event(e);
}

void CoordinateTextEdit::showToolTip(QHelpEvent* e) const
{
  int position(cursorForPosition(e->pos()).position());
  bool handled(false);

  if (position >= 0) {
    // Iterate backwards -- this ensures that "line too short" errors are shown
    // instead of the token-specific messages in that line.
    QListIterator<Mark> iter(m_marks);
    iter.toBack();
    while (iter.hasPrevious()) {
      const Mark& mark = iter.previous();
      if (mark.contains(position)) {
        QToolTip::showText(e->globalPos(), mark.tooltip);
        handled = true;
        break;
      }
    }
  }

  if (!handled) {
    QToolTip::hideText();
    e->ignore();
  }
}

} // namespace Avogadro::QtPlugins
