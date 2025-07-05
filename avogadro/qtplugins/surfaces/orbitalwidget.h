/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_ORBITALWIDGET_H
#define AVOGADRO_QTPLUGINS_ORBITALWIDGET_H

#include <QWidget>

#include "orbitaltablemodel.h"
#include "ui_orbitalwidget.h"

namespace Avogadro::Core {
class BasisSet;
}

namespace Avogadro::QtPlugins {

class OrbitalSettingsDialog;
class OrbitalTableModel;

class OrbitalWidget : public QWidget
{
  Q_OBJECT

public:
  enum OrbitalQuality
  {
    OQ_VeryLow = 0,
    OQ_Low,
    OQ_Medium,
    OQ_High,
    OQ_VeryHigh
  };

  //! Constructor
  explicit OrbitalWidget(QWidget* parent = nullptr,
                         Qt::WindowFlags f = Qt::Widget);
  //! Deconstructor
  ~OrbitalWidget() override;

  double isovalue() { return m_isovalue; };
  OrbitalQuality defaultQuality() { return m_quality; };

  bool precalcLimit() { return m_precalc_limit; }
  int precalcRange() { return m_precalc_range; }

  static double OrbitalQualityToDouble(OrbitalQuality q);
  static double OrbitalQualityToDouble(int i)
  {
    return OrbitalQualityToDouble(OrbitalQuality(i));
  };

public slots:
  void readSettings();
  void writeSettings();
  void reject();

  void fillTable(Core::BasisSet* basis);
  void setQuality(OrbitalQuality q);
  void selectOrbital(unsigned int orbital);
  void setDefaults(OrbitalWidget::OrbitalQuality quality, double isovalue,
                   bool HOMOFirst);
  void setPrecalcSettings(bool limit, int range);
  void initializeProgress(int orbital, int min, int max, int stage,
                          int totalStages);
  void nextProgressStage(int orbital, int newmin, int newmax);
  void updateProgress(int orbital, int current);
  void calculationComplete(int orbital);
  void calculationQueued(int orbital);

signals:
  void orbitalSelected(unsigned int orbital);
  void renderRequested(unsigned int orbital, double resolution);
  void calculateAll();

private slots:
  void tableClicked(const QItemSelection&);
  void renderClicked();
  void configureClicked();

private:
  Ui::OrbitalWidget ui;
  OrbitalSettingsDialog* m_settings;
  OrbitalQuality m_quality;
  double m_isovalue;

  bool m_precalc_limit;
  int m_precalc_range;

  OrbitalTableModel* m_tableModel;
  OrbitalSortingProxyModel* m_sortedTableModel;
};

} // namespace Avogadro::QtPlugins

#endif
