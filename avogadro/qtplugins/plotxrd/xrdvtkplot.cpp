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

#include <vtkAxis.h>
#include <vtkChartXY.h>
#include <vtkContextScene.h>
#include <vtkContextView.h>
#include <vtkFloatArray.h>
#include <vtkPlot.h>
#include <vtkRenderWindow.h>
#include <vtkRenderWindowInteractor.h>
#include <vtkRenderer.h>
#include <vtkNew.h>
#include <vtkTable.h>
#include <vtkTextProperty.h>

#include "xrdvtkplot.h"

namespace Avogadro {
namespace QtPlugins {

void XrdVtkPlot::generatePlot(
  const std::vector<std::pair<double, double>>& data)
{
  // Save the axes titles
  const char* xTitle = "2 Theta";
  const char* yTitle = "Intensity";

  // Create a table and add two columns
  vtkNew<vtkTable> table;

  vtkNew<vtkFloatArray> arrX;
  arrX->SetName(xTitle);
  table->AddColumn(arrX);

  vtkNew<vtkFloatArray> arrY;
  arrY->SetName(yTitle);
  table->AddColumn(arrY);

  // Put the data in the table
  table->SetNumberOfRows(data.size());
  for (size_t i = 0; i < data.size(); ++i) {
    table->SetValue(i, 0, data[i].first);
    table->SetValue(i, 1, data[i].second);
  }

  // Set up the view
  vtkNew<vtkContextView> view;
  view->GetRenderer()->SetBackground(1.0, 1.0, 1.0);
  view->GetRenderWindow()->SetSize(600, 600);
  view->GetRenderWindow()->SetWindowName("Theoretical XRD Pattern");

  // Add the chart
  vtkNew<vtkChartXY> chart;
  view->GetScene()->AddItem(chart);

  vtkAxis* bottomAxis = chart->GetAxis(vtkAxis::BOTTOM);
  vtkAxis* leftAxis = chart->GetAxis(vtkAxis::LEFT);

  // Set the axis titles
  bottomAxis->SetTitle(xTitle);
  leftAxis->SetTitle(yTitle);

  // Increase their title font sizes
  bottomAxis->GetTitleProperties()->SetFontSize(20);
  leftAxis->GetTitleProperties()->SetFontSize(20);

  // Increase the tick font sizes
  bottomAxis->GetLabelProperties()->SetFontSize(20);
  leftAxis->GetLabelProperties()->SetFontSize(20);

  // Adjust the range on the x axis
  bottomAxis->SetBehavior(vtkAxis::FIXED);
  bottomAxis->SetRange(data.front().first, data.back().first);

  // Add the data to the chart
  vtkPlot* line = chart->AddPlot(vtkChart::LINE);
  line->SetInputData(table, 0, 1);
  line->SetColor(255, 0, 0, 255);
  line->SetWidth(2.0);

  // Start interactor
  view->GetInteractor()->Initialize();
  view->GetInteractor()->Start();
}

} // namespace QtPlugins
} // namespace Avogadro
