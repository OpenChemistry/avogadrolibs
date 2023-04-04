/* This source file is part of the Avogadro project.
   It is released under the 3-Clause BSD License, see "LICENSE". */

#include "chartwidget.h"

#include "qvtkwidget.h"

#include <vtkChartXY.h>
#include <vtkContextScene.h>
#include <vtkContextView.h>
#include <vtkFloatArray.h>
#include <vtkPlot.h>
#include <vtkRenderWindow.h>
#include <vtkTable.h>

#include <QHBoxLayout>

namespace Avogadro::VTK {

ChartWidget::ChartWidget(QWidget* p) : QWidget(p), m_qvtk(new QVTKWidget(this))
{
  m_view->SetRenderWindow(m_qvtk->renderWindow());
  m_view->SetInteractor(m_qvtk->interactor());
  m_view->GetScene()->AddItem(m_chart);
  auto hLayout = new QHBoxLayout(this);
  hLayout->addWidget(m_qvtk);
  setLayout(hLayout);
  setMinimumWidth(400);
  setMinimumHeight(400);
}

ChartWidget::~ChartWidget() = default;

bool ChartWidget::addPlot(const std::vector<float>& x,
                          const std::vector<float>& y)
{
  // The x and y arrays must be of the same length, otherwise it is not x, y...
  if (x.size() != y.size())
    return false;

  vtkNew<vtkFloatArray> xArr;
  xArr->SetName("x");
  vtkNew<vtkFloatArray> yArr;
  yArr->SetName("y");

  m_table->AddColumn(xArr);
  m_table->AddColumn(yArr);
  m_table->SetNumberOfRows(x.size());

  for (size_t i = 0; i < x.size(); ++i)
    xArr->SetValue(i, x[i]);
  for (size_t i = 0; i < y.size(); ++i)
    yArr->SetValue(i, y[i]);

  auto* line = m_chart->AddPlot(vtkChart::LINE);
  line->SetInputData(m_table, 0, 1);
  return true;
}

} // namespace Avogadro::VTK