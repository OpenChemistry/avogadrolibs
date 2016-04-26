#ifndef AVOGADRO_QTPLUGINS_SURFACEDIALOG_H
#define AVOGADRO_QTPLUGINS_SURFACEDIALOG_H

#include <QtWidgets/QDialog>

namespace Ui {
class SurfaceDialog;
}

namespace Avogadro {
namespace QtPlugins {

class SurfaceDialog : public QDialog
{
  Q_OBJECT

public:
  SurfaceDialog(QWidget *parent = 0, Qt::WindowFlags f = 0);
  ~SurfaceDialog();

  void setupBasis(int numElectrons, int numMOs);
  void setupCube(int numCubes);
  void reenableCalculateButton();

public slots:

protected slots:
  void resolutionComboChanged(int n);
  void calculateClicked();

signals:
  void calculateClickedSignal(int index, float isosurfaceValue,
                              float resolutionStepSize);

private:
  Ui::SurfaceDialog *m_ui;
};

} // End namespace QtPlugins
} // End namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_SURFACEDIALOG_H
