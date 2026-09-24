/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "measurewidget.h"

#include <QtWidgets/QDoubleSpinBox>
#include <QtWidgets/QGridLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QVBoxLayout>

#include <QtCore/QSignalBlocker>
#include <QtGui/QColor>
#include <QtGui/QPalette>

namespace Avogadro::QtPlugins {

MeasureWidget::MeasureWidget(QWidget* parent_)
  : QWidget(parent_), m_content(nullptr), m_emptyLabel(nullptr),
    m_fixedMovesLabel(nullptr), m_messageLabel(nullptr), m_atomCount(-1)
{
  m_emptyLabel = new QLabel(tr("Click up to four atoms to measure them.\n"
                               "Type a new value to move the atoms."),
                            this);
  m_emptyLabel->setWordWrap(true);

  m_content = new QWidget(this);

  auto* grid = new QGridLayout;
  // Distances: any positive length, up to a fairly generous ceiling -- big
  // enough for a supercell edge, small enough that a fat-fingered "1000"
  // doesn't fling an atom out of the universe.
  addRow(MeasureField::Distance12, tr("Distance 1–2"), tr(" Å"), 0.001, 500.0,
         0.01, false);
  addRow(MeasureField::Distance23, tr("Distance 2–3"), tr(" Å"), 0.001, 500.0,
         0.01, false);
  addRow(MeasureField::Distance34, tr("Distance 3–4"), tr(" Å"), 0.001, 500.0,
         0.01, false);
  addRow(MeasureField::Angle123, tr("Angle 1–2–3"), tr("°"), 0.0, 180.0, 1.0,
         false);
  addRow(MeasureField::Angle234, tr("Angle 2–3–4"), tr("°"), 0.0, 180.0, 1.0,
         false);
  addRow(MeasureField::Dihedral1234, tr("Dihedral 1–2–3–4"), tr("°"), -180.0,
         180.0, 1.0, true);

  int gridRow = 0;
  for (auto field : { MeasureField::Distance12, MeasureField::Distance23,
                      MeasureField::Distance34, MeasureField::Angle123,
                      MeasureField::Angle234, MeasureField::Dihedral1234 }) {
    Row& r = row(field);
    grid->addWidget(r.label, gridRow, 0);
    grid->addWidget(r.spinBox, gridRow, 1);
    ++gridRow;
  }

  m_fixedMovesLabel = new QLabel(m_content);
  m_fixedMovesLabel->setWordWrap(true);

  m_messageLabel = new QLabel(m_content);
  m_messageLabel->setWordWrap(true);
  // An amber that reads on both light and dark window backgrounds.
  QPalette warningPalette = m_messageLabel->palette();
  warningPalette.setColor(QPalette::WindowText, QColor(200, 120, 0));
  m_messageLabel->setPalette(warningPalette);
  m_messageLabel->hide();

  auto* contentLayout = new QVBoxLayout;
  contentLayout->addLayout(grid);
  // The message and the fixed/moves line take turns in the same spot, so a
  // refusal doesn't make an already tall panel taller.
  contentLayout->addWidget(m_fixedMovesLabel);
  contentLayout->addWidget(m_messageLabel);
  m_content->setLayout(contentLayout);

  auto* layout = new QVBoxLayout;
  layout->addWidget(m_emptyLabel);
  layout->addWidget(m_content);
  layout->addStretch(1);
  setLayout(layout);

  setAtomCount(0);
}

MeasureWidget::Row& MeasureWidget::row(MeasureField field)
{
  return m_rows[static_cast<size_t>(field)];
}

void MeasureWidget::addRow(MeasureField field, const QString& name,
                           const QString& suffix, double minimum,
                           double maximum, double singleStep, bool wrap)
{
  Row& r = row(field);
  r.label = new QLabel(name, m_content);

  r.spinBox = new QDoubleSpinBox(m_content);
  // Editing is a deliberate, typed value, not something to react to on
  // every keystroke -- keyboardTracking(false) means valueChanged() (wired
  // up by MeasureTool) only fires once editing is finished, e.g. on Enter
  // or focus-out, not after every digit.
  r.spinBox->setKeyboardTracking(false);
  r.spinBox->setDecimals(3);
  r.spinBox->setSuffix(suffix);
  r.spinBox->setRange(minimum, maximum);
  r.spinBox->setSingleStep(singleStep);
  r.spinBox->setWrapping(wrap);
  r.spinBox->setAlignment(Qt::AlignRight);

  connect(r.spinBox, QOverload<double>::of(&QDoubleSpinBox::valueChanged), this,
          [this, field](double value) { emit valueEdited(field, value); });
  connect(r.spinBox, &QDoubleSpinBox::editingFinished, this,
          [this, field]() { emit editingFinished(field); });
}

void MeasureWidget::setAtomCount(int count)
{
  if (count != m_atomCount)
    clearMessage();
  m_atomCount = count;

  m_emptyLabel->setVisible(count < 2);
  m_content->setVisible(count >= 2);
  if (count < 2)
    return;

  row(MeasureField::Distance12).label->setVisible(true);
  row(MeasureField::Distance12).spinBox->setVisible(true);

  const bool haveThird = count >= 3;
  row(MeasureField::Distance23).label->setVisible(haveThird);
  row(MeasureField::Distance23).spinBox->setVisible(haveThird);
  row(MeasureField::Angle123).label->setVisible(haveThird);
  row(MeasureField::Angle123).spinBox->setVisible(haveThird);

  const bool haveFourth = count >= 4;
  row(MeasureField::Distance34).label->setVisible(haveFourth);
  row(MeasureField::Distance34).spinBox->setVisible(haveFourth);
  row(MeasureField::Angle234).label->setVisible(haveFourth);
  row(MeasureField::Angle234).spinBox->setVisible(haveFourth);
  row(MeasureField::Dihedral1234).label->setVisible(haveFourth);
  row(MeasureField::Dihedral1234).spinBox->setVisible(haveFourth);

  m_fixedMovesLabel->setText(
    tr("#1 stays fixed; edits move toward #%1.").arg(count));
}

void MeasureWidget::setValue(MeasureField field, double value)
{
  QDoubleSpinBox* spinBox = row(field).spinBox;
  // Block signals so writing the computed value back never itself looks
  // like a user edit and triggers valueEdited() -- that would either loop
  // forever or apply a no-op edit for every refresh.
  const QSignalBlocker blocker(spinBox);
  spinBox->setValue(value);
}

void MeasureWidget::setMessage(const QString& message)
{
  if (message.isEmpty()) {
    clearMessage();
    return;
  }
  m_messageLabel->setText(message);
  m_fixedMovesLabel->hide();
  m_messageLabel->show();
}

void MeasureWidget::clearMessage()
{
  m_messageLabel->clear();
  m_messageLabel->hide();
  m_fixedMovesLabel->show();
}

} // namespace Avogadro::QtPlugins
