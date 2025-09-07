#include "TestWidgetLogGraphs.h"
#include <QDebug>
#include <QDate>
#include <QDateTime>
#include <QApplication>

#define N2 50

TestWidgetLogGraphs::TestWidgetLogGraphs(QWidget* parent) : QWidget(parent)
{

  JKQTPlotter* plotLOG = new JKQTPlotter(this);
  plotLOG->setPlotUpdateEnabled(false);
  plotLOG->setObjectName("plotLOG");
  plotLOG->getPlotter()->setUserSettigsFilename(
    QApplication::applicationDirPath() + "/usersettings.ini", "plotLOG/");

  JKQTPDatastore* ds = plotLOG->getPlotter()->getDatastore();
  QVector<double> x, y;
  for (unsigned int i = 0; i < N2; i++) {
    const double xx =
      static_cast<double>(i + 1) / static_cast<double>(N2) * 15.0;
    x << xx;
    y << pow(5, xx / 5.0);
  }

  size_t cx2 = ds->addCopiedColumn(x, "x2");
  size_t cy23 = ds->addCopiedColumn(y, "y23");

  QVBoxLayout* layout = new QVBoxLayout();
  layout->addWidget(plotLOG);
  QFormLayout* layWid = new QFormLayout;
  layout->addLayout(layWid);
  setLayout(layout);
  resize(1000, 800);

  JKQTPXYLineGraph* gLines;
  plotLOG->getPlotter()->addGraph(gLines = new JKQTPXYLineGraph(plotLOG));
  gLines->setXColumn(cx2);
  gLines->setYColumn(cy23);
  gLines->setTitle("data, $f(x)=5^{x/5}$");

  plotLOG->setPlotUpdateEnabled(true);
  plotLOG->getPlotter()->zoomToFit(true, true); //, true);
  plotLOG->getPlotter()->setKeyAutosize(true);

  QCheckBox* chklogX = new QCheckBox("logarithmic X-axis", this);
  QCheckBox* chklogY = new QCheckBox("logarithmic Y-axis", this);
  connect(chklogX, SIGNAL(toggled(bool)), plotLOG->getPlotter()->getXAxis(),
          SLOT(setLogAxis(bool)));
  connect(chklogY, SIGNAL(toggled(bool)), plotLOG->getPlotter()->getYAxis(),
          SLOT(setLogAxis(bool)));
  layWid->addWidget(chklogX);
  layWid->addWidget(chklogY);

  QCheckBox* chkXMinorTicks = new QCheckBox("minor X-tick labels", this);
  QCheckBox* chkYMinorTicks = new QCheckBox("minor Y-tick labels", this);
  connect(chkXMinorTicks, SIGNAL(toggled(bool)),
          plotLOG->getPlotter()->getXAxis(),
          SLOT(setMinorTickLabelsEnabled(bool)));
  connect(chkYMinorTicks, SIGNAL(toggled(bool)),
          plotLOG->getPlotter()->getYAxis(),
          SLOT(setMinorTickLabelsEnabled(bool)));
  layWid->addWidget(chkXMinorTicks);
  layWid->addWidget(chkYMinorTicks);

  QCheckBox* chkFullNumberMinor = new QCheckBox("full minor numbers", this);
  connect(chkFullNumberMinor, SIGNAL(toggled(bool)),
          plotLOG->getPlotter()->getXAxis(),
          SLOT(setMinorTickLabelFullNumber(bool)));
  connect(chkFullNumberMinor, SIGNAL(toggled(bool)),
          plotLOG->getPlotter()->getYAxis(),
          SLOT(setMinorTickLabelFullNumber(bool)));
  layWid->addWidget(chkFullNumberMinor);

  QComboBox* cmbTickMode = new QComboBox(this);
  cmbTickMode->addItem("JKQTPLTMLinOrLog");
  cmbTickMode->addItem("JKQTPLTMLin");
  cmbTickMode->addItem("JKQTPLTMPower");
  connect(cmbTickMode, SIGNAL(currentIndexChanged(int)),
          plotLOG->getPlotter()->getXAxis(), SLOT(setTickMode(int)));
  layWid->addRow("X-Axis TickMode", cmbTickMode);

  cmbTickMode = new QComboBox(this);
  cmbTickMode->addItem("JKQTPLTMLinOrLog");
  cmbTickMode->addItem("JKQTPLTMLin");
  cmbTickMode->addItem("JKQTPLTMPower");
  connect(cmbTickMode, SIGNAL(currentIndexChanged(int)),
          plotLOG->getPlotter()->getYAxis(), SLOT(setTickMode(int)));
  layWid->addRow("Y-Axis TickMode", cmbTickMode);
  cmbTickMode->setCurrentIndex(0);
  plotLOG->getPlotter()->getYAxis()->setTickMode(JKQTPLTMLinOrPower);
  plotLOG->getPlotter()->getYAxis()->setMinorTicks(1);

  plotLOG->getPlotter()->getYAxis()->setDrawMode2(JKQTPCADMcomplete);
  plotLOG->getPlotter()->getXAxis()->setDrawMode2(JKQTPCADMcomplete);

  QSpinBox* spinMinTicks = new QSpinBox(this);
  spinMinTicks->setRange(0, 999);
  connect(spinMinTicks, SIGNAL(valueChanged(int)),
          plotLOG->getPlotter()->getXAxis(), SLOT(setMinorTicks(int)));
  connect(spinMinTicks, SIGNAL(valueChanged(int)),
          plotLOG->getPlotter()->getYAxis(), SLOT(setMinorTicks(int)));
  layWid->addRow("X/Y-axis minor tick count", spinMinTicks);
  spinMinTicks->setValue(1);

  QDoubleSpinBox* spinLOGAngle = new QDoubleSpinBox(this);
  spinLOGAngle->setRange(-90, 90);
  spinLOGAngle->setSuffix(QLatin1String("�"));
  connect(spinLOGAngle, SIGNAL(valueChanged(double)),
          plotLOG->getPlotter()->getXAxis(), SLOT(setTickLabelAngle(double)));
  layWid->addRow("X-Axis tick label angle", spinLOGAngle);
  spinLOGAngle->setValue(0);

  spinLOGAngle = new QDoubleSpinBox(this);
  spinLOGAngle->setRange(-90, 90);
  spinLOGAngle->setSuffix(QLatin1String("�"));
  connect(spinLOGAngle, SIGNAL(valueChanged(double)),
          plotLOG->getPlotter()->getYAxis(), SLOT(setTickLabelAngle(double)));
  layWid->addRow(tr("Y-axis label angle = "), spinLOGAngle);
  spinLOGAngle->setValue(0);
}
