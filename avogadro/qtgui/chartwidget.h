/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTGUI_CHARTWIDGET_H
#define AVOGADRO_QTGUI_CHARTWIDGET_H

#include "avogadroqtguiexport.h"

#include <QWidget>

#include <array>
#include <string>

namespace Avogadro::QtGui {

/**
 * @brief A color with 4 unsigned bytes (RGBA)
 */
typedef std::array<unsigned char, 4> color4ub;

/**
 * @class ChartWidget chartwidget.h <avogadro/qtgui/chartwidget.h>
 * @brief A Qt widget for displaying charts via JKQtPlotter
 *
 * A wrapper around the JKQtPlotter library, providing a widget
 * for displaying line charts, with multiple series, configurable
 * axes, and a legend, etc.
 */
class AVOGADROQTGUI_EXPORT ChartWidget : public QWidget
{
  Q_OBJECT

public:
  explicit ChartWidget(QWidget* p = nullptr);
  ~ChartWidget() override;

  /**
   * @brief Axis enumeration
   */
  enum class Axis
  {
    x,
    y
  };

  /**
   * @brief Legend location enumeration, relative to the plot
   */
  enum class LegendLocation
  {
    None,
    TopLeft,
    TopRight,
    BottomLeft,
    BottomRight
  };

  /**
   * @brief Add a plot to the chart
   * @param x The x values
   * @param y The y values
   * @param color The color of the line
   * @param xName The name of the x axis
   * @param yName The name of the y axis
   * @return True if successful
   */
  bool addPlot(const std::vector<float>& x, const std::vector<float>& y,
               const color4ub& color = color4ub{ 0, 0, 0, 255 },
               const QString& xName = "x", const QString& yName = "y");

  /**
   * @brief Add a series to an existing chart
   * @param y The y values
   * @param color The color of the line
   * @param name The name of the series
   * @return True if successful
   */
  bool addSeries(const std::vector<float>& y,
                 const color4ub& color = color4ub{ 0, 0, 0, 255 },
                 const QString& name = "");

  /**
   * @brief Add multiple lines to the chart
   * @param plotData The data for the plots, column[0] is x, rest are y
   * @param color The color of the lines
   * @param names The names of the lines (including for the x axis)
   * @return True if successful
   */
  bool addPlots(const std::vector<std::vector<float>>& plotData,
                const color4ub& color = color4ub{ 0, 0, 0, 255 },
                const QStringList& names = {});

  /**
   * @brief Clear all plots and data
   */
  void clearPlots();

  /**
   * @brief Set the title of the x axis
   * @param title The title
   */
  void setXAxisTitle(const QString& title);

  /**
   * @brief Set the title of the y axis
   * @param title The title
   */
  void setYAxisTitle(const QString& title);

  /**
   * @brief Set the custom tick positions and labels for an axis
   * @param a The axis
   * @param tickPositions The tick positions
   * @param tickLabels The tick labels
   * @return True if successful
   */
  void setTickLabels(Axis a, const std::vector<float>& tickPositions,
                     const QStringList& tickLabels);

  /**
   * @brief Set the default axis limits
   * @param a The axis
   * @param min The minimum value
   * @param max The maximum value
   * @return True if successful
   *
   * If minimum is bigger than maximum, the axis will be reversed
   */
  void setAxisLimits(Axis a, float min, float max);

  /**
   * @brief Set the default x-axis limits
   * @param min The minimum value
   * @param max The maximum value
   * @return True if successful
   *
   * If minimum is bigger than maximum, the axis will be reversed
   */
  void setXAxisLimits(float min, float max);
  /**
   * @brief Set the default y-axis limits
   * @param min The minimum value
   * @param max The maximum value
   * @return True if successful
   *
   * If minimum is bigger than maximum, the axis will be reversed
   */
  void setYAxisLimits(float min, float max);

  /**
   * @brief Set the font size for the ticks and axis titles
   * @param size The font size
   * @return True if successful
   */
  void setFontSize(int size = 14);
  /**
   * @brief Set the line width of the graph lines (in pt)
   * @param width The line width
   * @return True if successful
   */
  void setLineWidth(float width = 1.0);

  /**
   * @brief Set to logarithmic scale
   * @param a The axis
   * @param logScale True for log scale, false for linear
   * @return True if successful
   */
  void setAxisLogScale(Axis a, bool logScale);

  /**
   * @brief Set the number of digits to display in tick labels
   * @param a The axis
   * @param digits The number of digits
   * @return True if successful
   */
  void setAxisDigits(Axis a, int digits = 2);

  /**
   * @brief Label peaks in the plot
   * @param yColumn The column of the y values
   * @param threshold The threshold for peak detection
   * @param windowSize The window size for peak detection (in samples along the
   * x-axis)
   */
  void labelPeaks(int yColumn = 1, float threshold = 1.0, int windowSize = 5);

  /**
   * @brief Set the color of an axis
   * @param a The axis
   * @param color The color
   */
  void setAxisColor(Axis a, const color4ub& color);
  /**
   * @brief Set the color of the plot area
   * @param color The color
   */
  void setBackgroundColor(const color4ub& color);

  /**
   * @brief Set the location of the legend
   * @param location The location
   */
  void setLegendLocation(LegendLocation location);

signals:
  /**
   * @brief Emitted when the user single-clicks on the chart
   */
  void clicked(float x, float y, Qt::KeyboardModifiers modifiers);

public slots:
  /**
   * @brief register a callback for when the user clicks on the chart
   */
  void plotClicked(double x, double y, Qt::KeyboardModifiers modifiers,
                   Qt::MouseButton button);

  /** @brief Reset the zoom level of the plot (auto-scale to data)
   */
  void resetZoom();

private:
  void renderViews();
  float m_lineWidth = 1.0;

  // private members
  class ChartWidgetImpl;
  ChartWidgetImpl* m_impl;
};

} // namespace Avogadro::QtGui

#endif // AVOGADRO_QTGUI_CHARTWIDGET_H
