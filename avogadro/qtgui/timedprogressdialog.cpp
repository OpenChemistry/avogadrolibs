/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "timedprogressdialog.h"

namespace Avogadro::QtGui {

TimedProgressDialog::TimedProgressDialog(QWidget* parent)
  : QProgressDialog(parent)
{
}

TimedProgressDialog::TimedProgressDialog(const QString& labelText,
                                         const QString& cancelButtonText,
                                         int minimum, int maximum,
                                         QWidget* parent)
  : QProgressDialog(labelText, cancelButtonText, minimum, maximum, parent),
    originalLabelText(labelText)
{
}

void TimedProgressDialog::show()
{
  elapsedTimer.start();
  QProgressDialog::show();
}

void TimedProgressDialog::setValue(int value)
{
  QProgressDialog::setValue(value);

  if (!elapsedTimer.isValid()) {
    return;
  }

  // Calculate progress percentage
  float progress =
    static_cast<float>(value - minimum()) / (maximum() - minimum());

  // Avoid division by zero
  if (progress <= 0) {
    return;
  }
  // Ignore early progress (e.g., unreliable progress bar)
  if (progress < 0.1) {
    return;
  }

  // Calculate elapsed time in seconds
  float elapsedSeconds = elapsedTimer.elapsed() / 1000.0f;

  // Estimate total time and remaining time
  float estimatedTotal = elapsedSeconds / progress;
  float remainingSeconds = estimatedTotal - elapsedSeconds;

  // Format the time string
  QString remaining = formatTime(remainingSeconds);

  // Update label with original text and time remaining
  QString labelText = originalLabelText;
  if (!labelText.isEmpty()) {
    labelText += "\n" + remaining;
  } else {
    labelText = remaining;
  }

  QProgressDialog::setLabelText(labelText);
}

QString TimedProgressDialog::formatTime(double seconds)
{
  if (seconds < 0) {
    return tr("Calculating…");
  }

  if (seconds < 1) {
    return tr("Less than a second remaining");
  } else if (seconds < 60) {
    int sec = static_cast<int>(seconds);
    return tr("%n second(s) remaining", "", sec);
  } else if (seconds < 3600) {
    int minutes = static_cast<int>(seconds / 60);
    return tr("%n minute(s) remaining", "", minutes);
  } else {
    // hopefully we don't have anything this slow
    int hours = static_cast<int>(seconds / 3600);
    return tr("%n hour(s) remaining", "", hours);
  }
}

} // namespace Avogadro::QtGui
