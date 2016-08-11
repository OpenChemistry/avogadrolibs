#ifndef AVOGADRO_QTGUI_ThreeDMOLDIALOG_H
#define AVOGADRO_QTGUI_ThreeDMOLDIALOG_H

#include <QtWidgets/QDialog>

namespace Avogadro {

namespace QtGui {
class Molecule;
}

namespace QtPlugins {

namespace Ui {
class ThreeDMolDialog;
}

/**
 * @class ThreeDMolDialog 3dmoldialog.h <avogadrolibs/qtgui/3dmoldialog.h>
 * @brief The ThreeDMolDialog class provides a dialog which displays
 * basic molecular properties.
 * @author Barry E. Moore II
 *
 * @todo IUPAC name fetch (need inchi key).
 */
class ThreeDMolDialog : public QDialog
{
  Q_OBJECT

public:
  explicit ThreeDMolDialog(QtGui::Molecule *mol, QWidget *parent_ = 0);
  ~ThreeDMolDialog();

  QtGui::Molecule* molecule() { return m_molecule; }

public slots:
  void setMolecule(QtGui::Molecule *mol);

private slots:
  void updateLabels();
  void updateTextBrowser();
  void moleculeDestroyed();

private:
  QtGui::Molecule *m_molecule;
  Ui::ThreeDMolDialog *m_ui;
};


} // namespace QtPlugins
} // namespace Avogadro
#endif // AVOGADRO_QTGUI_ThreeDMOLDIALOG_H
