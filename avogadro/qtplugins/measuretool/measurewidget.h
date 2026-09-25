/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_MEASUREWIDGET_H
#define AVOGADRO_QTPLUGINS_MEASUREWIDGET_H

#include <QtWidgets/QWidget>

#include <array>

class QDoubleSpinBox;
class QLabel;

namespace Avogadro {
namespace QtPlugins {

/**
 * One editable internal coordinate the panel can show. There are at most
 * six, depending on how many atoms are picked (see MeasureWidget::setAtoms).
 * The values also serve as the field id MeasureTool hands to
 * QtGui::UndoMergeTracker, so consecutive edits of the same row merge into
 * one undo step.
 */
enum class MeasureField
{
  Distance12,
  Distance23,
  Distance34,
  Angle123,
  Angle234,
  Dihedral1234
};

/// The number of MeasureField values, for sizing arrays indexed by one.
constexpr int MeasureFieldCount = 6;

/**
 * @class MeasureWidget measurewidget.h
 * <avogadro/qtplugins/measuretool/measurewidget.h>
 * @brief The Measure tool's panel: an editable row for each distance, angle and
 * dihedral they define.
 *
 * This widget only displays and edits values; it holds no molecule state
 * and does no geometry math of its own. MeasureTool owns the picked atoms,
 * computes each value from their positions, and applies edits through
 * QtGui::FragmentTools; this class only lays the numbers out, reports what
 * the user typed via valueEdited(), and shows whatever refusal message
 * MeasureTool sends back.
 */
class MeasureWidget : public QWidget
{
  Q_OBJECT
public:
  explicit MeasureWidget(QWidget* parent_ = nullptr);

  /**
   * Show or hide rows to match @p count picked atoms (0-1: none; 2:
   * Distance12; 3: Distance12, Distance23, Angle123; 4: all six), and update
   * the "#1 stays fixed..." line. The atoms themselves are already labelled
   * #1-#4 in the view, so the panel doesn't repeat them. A change in count
   * means a different set of atoms, so it also clears any refusal message.
   * Does not touch row values; call setValue() for each row afterwards.
   */
  void setAtomCount(int count);

  /// Write @p value into @p field's spin box without emitting valueEdited().
  void setValue(MeasureField field, double value);

  /// Show an inline refusal message in place of the fixed/moves line.
  void setMessage(const QString& message);
  /// Hide the refusal message and bring the fixed/moves line back, e.g.
  /// after the next successful edit.
  void clearMessage();

Q_SIGNALS:
  /// @p field's spin box was given a new value, by typing or by the arrows
  /// or wheel.
  void valueEdited(MeasureField field, double value);
  /// @p field's spin box lost keyboard focus. MeasureTool uses this to end
  /// an undo-merge run, so the next arrow press after refocusing starts a
  /// new undo step rather than continuing the old one.
  void editingFinished(MeasureField field);

private:
  struct Row
  {
    QLabel* label = nullptr;
    QDoubleSpinBox* spinBox = nullptr;
  };

  Row& row(MeasureField field);
  void addRow(MeasureField field, const QString& name, const QString& suffix,
              double minimum, double maximum, double singleStep, bool wrap);

  QWidget* m_content;
  QLabel* m_emptyLabel;
  QLabel* m_fixedMovesLabel;
  QLabel* m_messageLabel;
  int m_atomCount;
  std::array<Row, MeasureFieldCount> m_rows;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_MEASUREWIDGET_H
