/* This source file is part of the Avogadro project.
   It is released under the 3-Clause BSD License, see "LICENSE". */

#include "chartwidget.h"

#include "qvtkwidget.h"

#include <vtkAxis.h>
#include <vtkChartXY.h>
#include <vtkContextScene.h>
#include <vtkContextView.h>
#include <vtkDoubleArray.h>
#include <vtkFloatArray.h>
#include <vtkPlot.h>
#include <vtkRenderWindow.h>
#include <vtkStringArray.h>
#include <vtkTable.h>
#include <vtkTextProperty.h>

#include <QDebug>
#include <QHBoxLayout>

namespace Avogadro::VTK {

ChartWidget::ChartWidget(QWidget* p) : QWidget(p), m_qvtk(new QVTKWidget(this))
{
  m_view->SetRenderWindow(m_qvtk->renderWindow());
  m_view->SetInteractor(m_qvtk->interactor());
  m_view->GetScene()->AddItem(m_chart);
  auto hLayout = new QHBoxLayout(this);
  hLayout->setContentsMargins(0, 0, 0, 0);
  hLayout->addWidget(m_qvtk);
  setLayout(hLayout);
  setMinimumWidth(100);
  setMinimumHeight(100);
}

ChartWidget::~ChartWidget() = default;

bool ChartWidget::addPlot(const std::vector<float>& x,
                          const std::vector<float>& y,
                          const std::array<unsigned char, 4>& color)
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
  line->SetWidth(m_lineWidth);
  line->SetColor(color[0], color[1], color[2], color[3]);
  return true;
}

bool ChartWidget::addSeries(const std::vector<float>& newSeries,
                            const std::array<unsigned char, 4>& color)
{
  if (newSeries.empty())
    return false;

  // check to see if the newSeries has the same number of rows
  // as the existing table
  if (m_table->GetNumberOfRows() != newSeries.size()) {
    return false;
  }

  // okay, we add a new column
  vtkNew<vtkFloatArray> yArr;
  // new column name
  auto numColumns = m_table->GetNumberOfColumns();
  yArr->SetName(("y" + std::to_string(numColumns)).c_str());
  yArr->SetNumberOfValues(newSeries.size());
  m_table->AddColumn(yArr);

  for (size_t i = 0; i < newSeries.size(); ++i) {
    yArr->SetValue(i, newSeries[i]);
  }

  auto* line = m_chart->AddPlot(vtkChart::LINE);
  line->SetInputData(m_table, 0, numColumns);
  line->SetWidth(m_lineWidth);
  line->SetColor(color[0], color[1], color[2], color[3]);
  return true;
}

bool ChartWidget::addPlots(const std::vector<std::vector<float>>& plotData,
                           const std::array<unsigned char, 4>& color)
{
  // Need at least an x and a y.
  if (plotData.size() < 2)
    return false;

  // All arrays must be the same size to go in the same table.
  auto xSize = plotData[0].size();
  for (const auto& d : plotData)
    if (xSize != d.size())
      return false;

  std::vector<vtkFloatArray*> vtkArrays;

  int col = 0;
  for (const auto& d : plotData) {
    // The vtkTable will hold a reference, the temp std::vector doesn't need to.
    AVO_UNUSED(d);
    vtkNew<vtkFloatArray> vtkArray;
    // Runtime errors without unique names, so construct something.
    vtkArray->SetName(("c" + std::to_string(col++)).c_str());
    m_table->AddColumn(vtkArray);
    vtkArrays.push_back(vtkArray);
  }

  m_table->SetNumberOfRows(xSize);

  for (size_t i = 0; i < plotData.size(); ++i) {
    auto& s = plotData[i];
    auto* d = vtkArrays[i];
    // This is a fast path in VTK for setting array values with a known type.
    for (size_t j = 0; j < s.size(); ++j) {
      d->SetValue(j, s[j]);
    }
    // Add the plot.
    auto* line = m_chart->AddPlot(vtkChart::LINE);
    line->SetInputData(m_table, 0, i);
    line->SetWidth(m_lineWidth);
    line->SetColor(color[0], color[1], color[2], color[3]);
  }

  return true;
}

void ChartWidget::clearPlots()
{
  m_chart->ClearPlots();
  m_table->RemoveAllColumns();
}

void ChartWidget::setXAxisTitle(const std::string& title)
{
  auto* axis = m_chart->GetAxis(vtkAxis::BOTTOM);
  axis->SetTitle(title);
  axis->SetTitleVisible(true);
  axis->GetTitleProperties()->SetBold(true);

  axis->GetLabelProperties()->SetFontSize(14);
}

void ChartWidget::setYAxisTitle(const std::string& title)
{
  auto* axis = m_chart->GetAxis(vtkAxis::LEFT);
  axis->SetTitle(title);
  axis->SetTitleVisible(true);
  axis->GetTitleProperties()->SetBold(true);
}

void ChartWidget::setFontSize(int size)
{
  int titleSize = round(size * 1.25);

  auto* axis = m_chart->GetAxis(vtkAxis::BOTTOM);
  axis->GetLabelProperties()->SetFontSize(size);
  axis->GetTitleProperties()->SetFontSize(titleSize);

  axis = m_chart->GetAxis(vtkAxis::LEFT);
  axis->GetLabelProperties()->SetFontSize(size);
  axis->GetTitleProperties()->SetFontSize(titleSize);
}

void ChartWidget::setLineWidth(float width)
{
  m_lineWidth = width;
  for (int i = 0; i < m_chart->GetNumberOfPlots(); ++i) {
    auto* plot = m_chart->GetPlot(i);
    plot->SetWidth(width);
  }
}

void ChartWidget::setTickLabels(Axis a, const std::vector<float>& tickPositions,
                                const std::vector<std::string>& tickLabels)
{
  auto customAxis = axis(a);

  // We need a valid axis and equal sizes vectors of points/labels.
  if (!customAxis)
    return;
  if (tickPositions.size() != tickLabels.size())
    return;

  vtkNew<vtkDoubleArray> doubleArray;
  doubleArray->SetName("Tick Positions");
  for (const auto& pos : tickPositions)
    doubleArray->InsertNextValue(pos);

  vtkNew<vtkStringArray> stringArray;
  stringArray->SetName("Tick Labels");
  for (const auto& label : tickLabels)
    stringArray->InsertNextValue(label);

  customAxis->SetCustomTickPositions(doubleArray, stringArray);
}

void ChartWidget::setAxisLimits(Axis a, float min, float max)
{
  auto customAxis = axis(a);

  // We need a valid axis and equal sizes vectors of points/labels.
  if (!customAxis)
    return;

  customAxis->SetRange(min, max);
  customAxis->SetBehavior(vtkAxis::FIXED);
}

void ChartWidget::setXAxisLimits(float min, float max)
{
  setAxisLimits(Axis::x, min, max);
}

void ChartWidget::setYAxisLimits(float min, float max)
{
  setAxisLimits(Axis::y, min, max);
}

void ChartWidget::setAxisLogScale(Axis a, bool logScale)
{
  auto customAxis = axis(a);

  // We need a valid axis and equal sizes vectors of points/labels.
  if (!customAxis)
    return;

  customAxis->SetLogScale(logScale);
}

vtkAxis* ChartWidget::axis(Axis a)
{
  if (a == Axis::x)
    return m_chart->GetAxis(vtkAxis::BOTTOM);
  else if (a == Axis::y)
    return m_chart->GetAxis(vtkAxis::LEFT);

  return nullptr;
}

} // namespace Avogadro::VTK
