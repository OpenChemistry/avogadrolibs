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

public slots:

protected slots:
  void surfaceTypeComboChanged(int n);
  void resolutionComboChanged(int n);
  void surfaceComboChanged(int n);
  void displayComboChanged(int n);
  void showClicked();
  void calculateClicked();

signals:
  void showSurface();

private:
  Ui::NewSurfaceDialog *m_ui;
};

} // End namespace QtPlugins
} // End namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_NEWSURFACEDIALOG_H
