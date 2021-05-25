/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2018 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include <iostream>
#include <string>

#include <vtkAxis.h>
#include <vtkChartXY.h>
#include <vtkContextScene.h>
#include <vtkContextView.h>
#include <vtkDoubleArray.h>
#include <vtkFloatArray.h>
#include <vtkGenericOpenGLRenderWindow.h>
#include <vtkNew.h>
#include <vtkPen.h>
#include <vtkPlot.h>
#include <vtkRenderWindowInteractor.h>
#include <vtkRenderer.h>
#include <vtkStringArray.h>
#include <vtkTable.h>
#include <vtkTextProperty.h>

#include <QSurfaceFormat>
#include <QVTKOpenGLWidget.h>

#include "vtkplot.h"

using std::array;
using std::string;
using std::vector;

namespace Avogadro {
namespace VTK {

VtkPlot::VtkPlot() : m_widget(new QVTKOpenGLWidget)
{
  m_widget->SetRenderWindow(m_renderWindow);

  // Set up the view
  m_widget->setFormat(QVTKOpenGLWidget::defaultFormat());
  m_view->SetRenderWindow(m_renderWindow);
  m_view->GetRenderer()->SetBackground(1.0, 1.0, 1.0);
  m_view->GetRenderWindow()->SetSize(600, 600);

  // Add the chart
  m_view->GetScene()->AddItem(m_chart);

  vtkAxis* bottomAxis = m_chart->GetAxis(vtkAxis::BOTTOM);
  vtkAxis* leftAxis = m_chart->GetAxis(vtkAxis::LEFT);

  // Increase the title font sizes
  bottomAxis->GetTitleProperties()->SetFontSize(20);
  leftAxis->GetTitleProperties()->SetFontSize(20);

  // Increase the tick font sizes
  bottomAxis->GetLabelProperties()->SetFontSize(20);
  leftAxis->GetLabelProperties()->SetFontSize(20);
}

VtkPlot::~VtkPlot() = default;

void VtkPlot::setData(const vector<vector<double>>& data)
{
  if (data.size() < 2) {
    std::cerr << "Error in " << __FUNCTION__
              << ": data must be of size 2 or greater!\n";
    return;
  }

  // All of the rows must be equal in size currently. Otherwise, we get
  // a garbage plot. We may be able to improve on this in the future.
  size_t numRows = data[0].size();
  for (size_t i = 1; i < data.size(); ++i) {
    if (data[i].size() != numRows) {
      std::cerr << "Error in " << __FUNCTION__ << ": all of the data must "
                << "have the same number of rows!\n";
      return;
    }
  }

  // Erase the current table
  while (m_table->GetNumberOfRows() > 0)
    m_table->RemoveRow(0);

  for (size_t i = 0; i < data.size(); ++i) {
    vtkNew<vtkFloatArray> array;
    // Unique column names are necessary to prevent vtk from crashing.
    array->SetName(("Column " + std::to_string(i)).c_str());
    m_table->AddColumn(array);
  }

  // Put the data in the table
  m_table->SetNumberOfRows(numRows);
  for (size_t i = 0; i < data.size(); ++i) {
    for (size_t j = 0; j < data[i].size(); ++j) {
      m_table->SetValue(j, i, data[i][j]);
    }
  }
}

void VtkPlot::setWindowName(const char* windowName)
{
  m_view->GetRenderWindow()->SetWindowName(windowName);
}

void VtkPlot::setXTitle(const char* xTitle)
{
  vtkAxis* bottomAxis = m_chart->GetAxis(vtkAxis::BOTTOM);
  bottomAxis->SetTitle(xTitle);
}

void VtkPlot::setYTitle(const char* yTitle)
{
  vtkAxis* leftAxis = m_chart->GetAxis(vtkAxis::LEFT);
  leftAxis->SetTitle(yTitle);
}

void VtkPlot::setCustomTickLabels(Axis _axis,
                                  const vector<double>& customTickPositions,
                                  const vector<string>& customTickLabels)
{
  vtkAxis* axis = getAxis(_axis);
  if (!axis) {
    std::cerr << "Error in " << __FUNCTION__ << ": invalid axis\n";
    return;
  }

  // These must be equal in size
  if (customTickPositions.size() != customTickLabels.size()) {
    std::cerr << "Error in " << __FUNCTION__ << ": custom tick labels "
              << "must be equal in size to custom tick positions!\n";
    return;
  }

  vtkNew<vtkDoubleArray> doubleArray;
  doubleArray->SetName("Custom Tick Positions");
  for (const auto& pos : customTickPositions)
    doubleArray->InsertNextValue(pos);

  vtkNew<vtkStringArray> stringArray;
  stringArray->SetName("Custom Tick Labels");

  for (const auto& label : customTickLabels)
    stringArray->InsertNextValue(label);

  axis->SetCustomTickPositions(doubleArray, stringArray);
}

static int convertLineStyleEnum(VTK::VtkPlot::LineStyle style)
{
  using LineStyle = VTK::VtkPlot::LineStyle;

  if (style == LineStyle::noLine)
    return vtkPen::NO_PEN;
  else if (style == LineStyle::solidLine)
    return vtkPen::SOLID_LINE;
  else if (style == LineStyle::dashLine)
    return vtkPen::DASH_LINE;
  else if (style == LineStyle::dotLine)
    return vtkPen::DOT_LINE;
  else if (style == LineStyle::dashDotLine)
    return vtkPen::DASH_DOT_LINE;
  else if (style == LineStyle::dashDotDotLine)
    return vtkPen::DASH_DOT_DOT_LINE;

  std::cerr << "Error in " << __FUNCTION__ << ": unknown line style.\n";
  std::cerr << "Defaulting to solid line.\n";
  return vtkPen::SOLID_LINE;
}

void VtkPlot::show()
{
  // First, clear all previous plots
  m_chart->ClearPlots();

  // Add the lines to the chart
  for (size_t i = 1; i < m_table->GetNumberOfColumns(); ++i) {
    vtkPlot* line = m_chart->AddPlot(vtkChart::LINE);
    line->SetInputData(m_table, 0, i);

    // If we have a label for this line, set it
    if (i <= m_lineLabels.size())
      line->SetLabel(m_lineLabels[i - 1]);

    // If we have a color for this line, set it (rgba)
    if (i <= m_lineColors.size()) {
      line->SetColor(m_lineColors[i - 1][0], m_lineColors[i - 1][1],
                     m_lineColors[i - 1][2], m_lineColors[i - 1][3]);
    }

    // If we have a line style for this line, set it
    if (i <= m_lineStyles.size() && line->GetPen())
      line->GetPen()->SetLineType(convertLineStyleEnum(m_lineStyles[i - 1]));

    line->SetWidth(2.0);
  }

  m_widget->show();
}

void VtkPlot::setAxisLimits(Axis _axis, double min, double max)
{
  vtkAxis* axis = getAxis(_axis);
  if (!axis) {
    std::cerr << "Error in " << __FUNCTION__ << ": invalid axis\n";
    return;
  }

  axis->SetMinimumLimit(min);
  axis->SetMaximumLimit(max);
}

vtkAxis* VtkPlot::getAxis(Axis axis)
{
  if (axis == Axis::xAxis) {
    return m_chart->GetAxis(vtkAxis::BOTTOM);
  } else if (axis == Axis::yAxis) {
    return m_chart->GetAxis(vtkAxis::LEFT);
  }

  // If we get here, there is an error...
  std::cerr << "Error in " << __FUNCTION__ << ": unknown axis\n";
  return nullptr;
}

} // namespace VTK
} // namespace Avogadro
