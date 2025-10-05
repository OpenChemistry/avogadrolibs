/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "chartdialog.h"
#include "chartwidget.h"

#include <QVBoxLayout>

namespace Avogadro::QtGui {

ChartDialog::ChartDialog(QWidget* p)
  : QDialog(p), m_chartWidget(new ChartWidget(this))
{
  auto* layout = new QVBoxLayout();
  layout->addWidget(m_chartWidget);
  layout->setContentsMargins(0, 0, 0, 0);
  setLayout(layout);
}

ChartDialog::~ChartDialog() = default;

ChartWidget* ChartDialog::chartWidget()
{
  return m_chartWidget;
}

QSize ChartDialog::sizeHint() const
{
  return QSize(600, 400);
}

QSize ChartDialog::minimumSizeHint() const
{
  return QSize(200, 200);
}

} // namespace Avogadro::QtGui
