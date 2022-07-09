/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_COORDINATETEXTEDIT_H
#define AVOGADRO_QTPLUGINS_COORDINATETEXTEDIT_H

#include <QtWidgets/QTextEdit>

#include <QtGui/QTextCharFormat>

class QHelpEvent;

namespace Avogadro {
namespace QtPlugins {

/**
 * @brief The CoordinateTextEdit class extends QTextEdit to provide context
 * tooltips and highlighting for syntax errors.
 */
class CoordinateTextEdit : public QTextEdit
{
  Q_OBJECT
public:
  explicit CoordinateTextEdit(QWidget* p = nullptr);

  bool hasInvalidMarks() const { return m_hasInvalidMarks; }

public slots:
  void resetMarks();
  void markInvalid(QTextCursor& cur, const QString& tooltip);
  void markValid(QTextCursor& cur, const QString& tooltip);

protected:
  bool event(QEvent* e) override;

private:
  void showToolTip(QHelpEvent* e) const;

  struct Mark
  {
    int start;
    int end;
    QString tooltip;
    Mark(int s, int e, const QString& t)
      : start(s)
      , end(e)
      , tooltip(t)
    {}
    bool contains(int i) const { return i >= start && i <= end; }
  };
  QList<Mark> m_marks;
  bool m_hasInvalidMarks;

  QTextCharFormat m_unmarkedFormat;
  QTextCharFormat m_invalidFormat;
  QTextCharFormat m_validFormat;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_COORDINATETEXTEDIT_H
