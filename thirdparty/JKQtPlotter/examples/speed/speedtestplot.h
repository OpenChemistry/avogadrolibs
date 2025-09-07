#pragma once
#include <array>
#include <random>
#include <chrono>

#include "jkqtplotter/jkqtplotter.h"

#define NDATA 500

class SpeedTestPlot : public JKQTPlotter
{
  Q_OBJECT
protected:
  std::array<double, NDATA> X, Y, Y2;
  const double dx;
  double x0;
  std::chrono::system_clock::time_point t_lastplot;
  QAction* actAntiAliase;
  QAction* actTwoGraphs;
  QAction* actFixedXAxis;

public:
  SpeedTestPlot();

  virtual ~SpeedTestPlot();
public slots:
  void plotNewData();
};
