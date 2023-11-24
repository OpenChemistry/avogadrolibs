/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_XRDOPTIONSDIALOG_H
#define AVOGADRO_QTPLUGINS_XRDOPTIONSDIALOG_H

#include <memory>

#include <QDialog>

namespace Avogadro {
namespace QtPlugins {

namespace Ui {
class XrdOptionsDialog;
}

/**
 * @brief Dialog to set options for a theoretical XRD pattern calculation.
 */
class XrdOptionsDialog : public QDialog
{
  Q_OBJECT

public:
  explicit XrdOptionsDialog(QWidget* parent = nullptr);
  ~XrdOptionsDialog();

  double wavelength() const;
  double peakWidth() const;
  size_t numDataPoints() const;
  double max2Theta() const;

protected slots:
  void accept();

private:
  std::unique_ptr<Ui::XrdOptionsDialog> m_ui;
};

} // namespace QtPlugins
} // namespace Avogadro
#endif // AVOGADRO_QTPLUGINS_XRDOPTIONSDIALOG_H
