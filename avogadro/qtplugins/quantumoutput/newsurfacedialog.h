#ifndef AVOGADRO_QTPLUGINS_NEWSURFACEDIALOG_H
#define AVOGADRO_QTPLUGINS_NEWSURFACEDIALOG_H

#include <QtWidgets/QDialog>

namespace Ui {
class NewSurfaceDialog;
}

namespace Avogadro {
namespace QtPlugins {

class NewSurfaceDialog : public QDialog
{
  Q_OBJECT

public:
  NewSurfaceDialog(QWidget *parent = 0, Qt::WindowFlags f = 0);
  ~NewSurfaceDialog();

  void setupBasis(int numElectrons, int numMOs);
  void setupCube(int numCubes);

public slots:

protected slots:
  void resolutionComboChanged(int n);
  void calculateClicked();

signals:
  void calculateClickedSignal(int index, float isosurfaceValue,
                              float resolutionStepSize);

private:
  Ui::NewSurfaceDialog *m_ui;
};

} // End namespace QtPlugins
} // End namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_NEWSURFACEDIALOG_H
