/* This source file is part of the Avogadro project.
   It is released under the 3-Clause BSD License, see "LICENSE". */

#ifndef AVOGADRO_QTPLUGINS_COMDIALOG_H
#define AVOGADRO_QTPLUGINS_COMDIALOG_H

#include <QtWidgets/QDialog>

namespace Ui {
class ComDialog;
}

namespace Avogadro {
class HistogramWidget;
namespace QtGui {
class Molecule;
}
namespace QtPlugins {

class ComDialog : public QDialog
{
  Q_OBJECT

public:
  ComDialog(QWidget* parent = nullptr, Qt::WindowFlags f = 0);
  ~ComDialog() override;

  HistogramWidget* histogramWidget();

  void setMolecule(QtGui::Molecule* mol);

protected slots:
  void enableVolume(int enable);
  void enableIsosurface(int enable);
  void setIsoValue(double value);
  void setOpacity(double value);

signals:
  void renderNeeded();

private:
  Ui::ComDialog* m_ui = nullptr;

  QtGui::Molecule* m_molecule = nullptr;
};

} // End namespace QtPlugins
} // End namespace Avogadro

#endif
