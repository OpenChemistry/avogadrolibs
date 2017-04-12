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

#include "coordinatetextedit.h"

#include <QtGui/QHelpEvent>
#include <QtGui/QTextCursor>
#include <QtWidgets/QApplication>
#include <QtWidgets/QToolTip>

#include <QtCore/QListIterator>

namespace Avogadro {
namespace QtPlugins {

CoordinateTextEdit::CoordinateTextEdit(QWidget* p)
  : QTextEdit(p), m_hasInvalidMarks(false)
{
  setMouseTracking(true);

  m_unmarkedFormat.setUnderlineStyle(QTextCharFormat::NoUnderline);
  m_unmarkedFormat.setForeground(qApp->palette().foreground().color());
  m_unmarkedFormat.setBackground(qApp->palette().base().color());

  m_invalidFormat.setUnderlineStyle(QTextCharFormat::SpellCheckUnderline);
  m_invalidFormat.setForeground(Qt::darkRed);
  m_invalidFormat.setBackground(Qt::lightGray);

  m_validFormat.setUnderlineStyle(QTextCharFormat::NoUnderline);
  m_validFormat.setForeground(Qt::darkGreen);
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
    QHelpEvent* helpEvent = static_cast<QHelpEvent*>(e);
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

} // namespace QtPlugins
} // namespace Avogadro
