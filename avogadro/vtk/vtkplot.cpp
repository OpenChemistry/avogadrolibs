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
#include <vtkFloatArray.h>
#include <vtkGenericOpenGLRenderWindow.h>
#include <vtkNew.h>
#include <vtkPlot.h>
#include <vtkRenderWindowInteractor.h>
#include <vtkRenderer.h>
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

void VtkPlot::generatePlot(const vector<vector<double>>& data,
                           const vector<string>& lineLabels,
                           const vector<array<double, 4>>& lineColors,
                           const char* xTitle, const char* yTitle,
                           const char* windowName)
{
  if (data.size() < 2) {
    std::cerr << "Error in " << __FUNCTION__
              << ": data must be of size 2 or greater!\n";
    return;
  }

  // Create a table and add the data as columns
  vtkNew<vtkTable> table;

  for (size_t i = 0; i < data.size(); ++i) {
    vtkNew<vtkFloatArray> array;
    // Unique column names are necessary to prevent vtk from crashing.
    array->SetName(("Column " + std::to_string(i)).c_str());
    table->AddColumn(array);
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

  // Put the data in the table
  table->SetNumberOfRows(numRows);
  for (size_t i = 0; i < data.size(); ++i) {
    for (size_t j = 0; j < data[i].size(); ++j) {
      table->SetValue(j, i, data[i][j]);
    }
  }

  // Set up the view
  vtkNew<vtkGenericOpenGLRenderWindow> renderWindow;
  QVTKOpenGLWidget* widget = new QVTKOpenGLWidget();
  widget->SetRenderWindow(renderWindow);
  // Hackish, but at least it won't leak
  widget->setAttribute(Qt::WA_DeleteOnClose);
  widget->setFormat(QVTKOpenGLWidget::defaultFormat());
  vtkNew<vtkContextView> view;
  view->SetRenderWindow(renderWindow);
  view->GetRenderer()->SetBackground(1.0, 1.0, 1.0);
  view->GetRenderWindow()->SetSize(600, 600);
  view->GetRenderWindow()->SetWindowName(windowName);

  // Add the chart
  vtkNew<vtkChartXY> chart;
  view->GetScene()->AddItem(chart);

  vtkAxis* bottomAxis = chart->GetAxis(vtkAxis::BOTTOM);
  vtkAxis* leftAxis = chart->GetAxis(vtkAxis::LEFT);

  // Set the axis titles
  bottomAxis->SetTitle(xTitle);
  leftAxis->SetTitle(yTitle);

  // Increase the title font sizes
  bottomAxis->GetTitleProperties()->SetFontSize(20);
  leftAxis->GetTitleProperties()->SetFontSize(20);

  // Increase the tick font sizes
  bottomAxis->GetLabelProperties()->SetFontSize(20);
  leftAxis->GetLabelProperties()->SetFontSize(20);

  // Adjust the range on the x axis
  bottomAxis->SetBehavior(vtkAxis::FIXED);
  bottomAxis->SetRange(data[0].front(), data[0].back());

  // Add the lines to the chart
  for (size_t i = 1; i < data.size(); ++i) {
    vtkPlot* line = chart->AddPlot(vtkChart::LINE);
    line->SetInputData(table, 0, i);

    // If we have a label for this line, set it
    if (i <= lineLabels.size())
      line->SetLabel(lineLabels[i - 1]);

    // If we have a color for this line, set it (rgba)
    if (i <= lineColors.size()) {
      line->SetColor(lineColors[i - 1][0], lineColors[i - 1][1],
                     lineColors[i - 1][2], lineColors[i - 1][3]);
    }

    line->SetWidth(2.0);
  }

  // Start the widget, we probably want to improve this in future.
  widget->show();
}

} // namespace VTK
} // namespace Avogadro
