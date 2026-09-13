/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "timedprogressdialog.h"

namespace Avogadro::QtGui {

TimedProgressDialog::TimedProgressDialog(QWidget* parent)
  : QProgressDialog(parent)
{
  // Start counting immediately: a dialog left to appear on its own after
  // minimumDuration() is shown through QProgressDialog::forceShow(), which
  // does not go through our show(), so construction is the only reliable
  // point to start the clock.
  elapsedTimer.start();
}

TimedProgressDialog::TimedProgressDialog(const QString& labelText,
                                         const QString& cancelButtonText,
                                         int minimum, int maximum,
                                         QWidget* parent)
  : QProgressDialog(labelText, cancelButtonText, minimum, maximum, parent),
    originalLabelText(labelText)
{
  elapsedTimer.start();
}

void TimedProgressDialog::show()
{
  elapsedTimer.start();
  QProgressDialog::show();
}

void TimedProgressDialog::restartTimer()
{
  elapsedTimer.start();
}

void TimedProgressDialog::setValue(int value)
{
  QProgressDialog::setValue(value);

  if (!elapsedTimer.isValid()) {
    return;
  }

  // An indeterminate (or otherwise empty) range has no percentage to report.
  if (maximum() <= minimum()) {
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
    int minutes = static_cast<int>((static_cast<int>(seconds) % 3600) / 60);
    if (hours == 1 && minutes > 0) {
      // give a message for under 2 hours, e.g.
      // "1 hour 10 minutes remaining"
      return tr("1 hour %n minute(s) remaining", "", minutes);
    } else {
      // one hour or 2 hours, etc.
      return tr("%n hour(s) remaining", "", hours);
    }
  }
}

} // namespace Avogadro::QtGui
