/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTGUI_TIMEDPROGRESSDIALOG_H
#define AVOGADRO_QTGUI_TIMEDPROGRESSDIALOG_H

#include "avogadroqtguiexport.h"

#include <QProgressDialog>
#include <QElapsedTimer>
#include <QString>

namespace Avogadro::QtGui {

/**
 * @class TimedProgressDialog timedprogressdialog.h
 * <avogadro/qtgui/timedprogressdialog.h>
 * @brief A progress dialog with a time remaining label
 * @author Geoff Hutchison
 */
class AVOGADROQTGUI_EXPORT TimedProgressDialog : public QProgressDialog
{
  Q_OBJECT

public:
  TimedProgressDialog(QWidget* parent);
  TimedProgressDialog(const QString& labelText = QString(),
                      const QString& cancelButtonText = QString(),
                      int minimum = 0, int maximum = 100,
                      QWidget* parent = nullptr);

  /**
   * @brief show the progress dialog and start the timer
   */
  void show();

  /**
   * @brief restart the elapsed timer, discarding any time measured so far
   *
   * Useful when a job spends an unknown amount of time setting up before it
   * can report determinate progress: restarting once the real work begins
   * keeps that setup time out of the estimate.
   */
  void restartTimer();

  /**
   * @brief set the default label text
   */
  void setLabelText(const QString& labelText)
  {
    originalLabelText = labelText;
    QProgressDialog::setLabelText(labelText);
  }

public slots:
  /**
   * @brief set the value of the progress dialog
   * and update the time remaining
   */
  void setValue(int value);

private:
  /**
   * convert the time to a translatable
   * human-readable string like 2 minutes remaining
   * @param seconds the time in seconds
   */
  QString formatTime(double seconds);

  QElapsedTimer elapsedTimer;
  QString originalLabelText;
};

} // namespace Avogadro::QtGui

#endif // AVOGADRO_QTGUI_TIMEDPROGRESSDIALOG_H
