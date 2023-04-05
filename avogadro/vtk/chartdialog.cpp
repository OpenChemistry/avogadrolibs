/* This source file is part of the Avogadro project.
   It is released under the 3-Clause BSD License, see "LICENSE". */

#include "chartdialog.h"

#include "chartwidget.h"

namespace Avogadro::VTK {

ChartDialog::ChartDialog(QWidget* p)
  : QDialog(p), m_chartWidget(new ChartWidget(this))
{
}

ChartDialog::~ChartDialog() = default;

ChartWidget* ChartDialog::chartWidget()
{
  return m_chartWidget;
}

} // namespace Avogadro::VTK