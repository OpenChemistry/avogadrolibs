/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/qtgui/timedprogressdialog.h>

#include <QtCore/QCoreApplication>
#include <QtCore/QEvent>
#include <QtCore/QRegularExpression>
#include <QtCore/QString>
#include <QtTest/QTest>
#include <QtWidgets/QApplication>

using Avogadro::QtGui::TimedProgressDialog;

namespace {

const QString label = QStringLiteral("Conformer 3 of 25");

/**
 * TimedProgressDialog is a QWidget, so a plain QCoreApplication is not enough.
 * Other tests in this binary may have created one already; if that instance is
 * not a QApplication there is no way to upgrade it, and the caller skips.
 */
QApplication* ensureApp()
{
  if (QCoreApplication::instance() != nullptr)
    return qobject_cast<QApplication*>(QCoreApplication::instance());

  static int argc = 1;
  static char arg0[] = "timedprogressdialogtest";
  static char* argv[] = { arg0, nullptr };
  // Run without a display so this works in CI.
  if (qEnvironmentVariableIsEmpty("QT_QPA_PLATFORM"))
    qputenv("QT_QPA_PLATFORM", "offscreen");
  static QApplication app(argc, argv);
  return &app;
}

/// The estimate the dialog appended, or an empty string if it added none.
QString remainingText(const TimedProgressDialog& dialog)
{
  const QString text = dialog.labelText();
  const int split = text.indexOf('\n');
  return split < 0 ? QString() : text.mid(split + 1);
}

/**
 * The whole seconds in an estimate, for comparing two of them. The strings
 * are built for humans ("Less than a second remaining", "4 second(s)
 * remaining", "2 minute(s) remaining"), so pull the leading number back out
 * and scale it; anything without one is under a second.
 */
int remainingSeconds(const TimedProgressDialog& dialog)
{
  const QString text = remainingText(dialog);
  const int digit = text.indexOf(QRegularExpression(QStringLiteral("\\d")));
  if (digit < 0)
    return 0;

  int end = digit;
  while (end < text.size() && text.at(end).isDigit())
    ++end;
  const int value = text.mid(digit, end - digit).toInt();

  if (text.contains(QStringLiteral("hour")))
    return value * 3600;
  if (text.contains(QStringLiteral("minute")))
    return value * 60;
  return value;
}

} // namespace

/**
 * Every case needs a QApplication before it can build a widget, and skips
 * rather than fails if another test in this binary got in first with a plain
 * QCoreApplication.
 */
class TimedProgressDialogTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    if (ensureApp() == nullptr)
      GTEST_SKIP() << "a non-GUI QCoreApplication already exists";
  }

  void TearDown() override
  {
    if (QCoreApplication::instance() != nullptr)
      QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
  }
};

TEST_F(TimedProgressDialogTest, EstimatesFromTheStepsReported)
{
  TimedProgressDialog dialog(label, QStringLiteral("Cancel"), 0, 25, nullptr);
  QTest::qSleep(300);
  dialog.setValue(5);

  // The message the caller gave is kept, with the estimate on its own line.
  EXPECT_TRUE(dialog.labelText().startsWith(label + '\n'))
    << dialog.labelText().toStdString();
  EXPECT_TRUE(remainingText(dialog).contains(QStringLiteral("remaining")))
    << dialog.labelText().toStdString();
}

TEST_F(TimedProgressDialogTest, LaterMessagesKeepTheirEstimate)
{
  TimedProgressDialog dialog(label, QStringLiteral("Cancel"), 0, 25, nullptr);
  QTest::qSleep(300);

  // Callers report the step, then its number: setLabelText() replaces the
  // text wholesale and setValue() re-appends the estimate to the new message.
  const QString next = QStringLiteral("Conformer 10 of 25");
  dialog.setLabelText(next);
  dialog.setValue(10);

  EXPECT_TRUE(dialog.labelText().startsWith(next + '\n'))
    << dialog.labelText().toStdString();
}

TEST_F(TimedProgressDialogTest, EarlyProgressIsTooUnreliableToReport)
{
  TimedProgressDialog dialog(label, QStringLiteral("Cancel"), 0, 100, nullptr);
  QTest::qSleep(50);
  dialog.setValue(1); // 1%, below the 10% the estimate needs

  EXPECT_EQ(dialog.labelText(), label);
}

TEST_F(TimedProgressDialogTest, IndeterminateRangeReportsNothing)
{
  // A 0..0 dialog has no percentage to work from; it must not divide by the
  // empty range and print whatever that produces.
  TimedProgressDialog dialog(label, QStringLiteral("Cancel"), 0, 0, nullptr);
  QTest::qSleep(50);
  dialog.setValue(1);

  EXPECT_EQ(dialog.labelText(), label);
}

TEST_F(TimedProgressDialogTest, RestartTimerDropsStartupTime)
{
  // Two dialogs reaching the same step after the same amount of work, one of
  // which spent a while starting up first. Only the work should be counted.
  TimedProgressDialog withStartup(label, QStringLiteral("Cancel"), 0, 25,
                                  nullptr);
  TimedProgressDialog restarted(label, QStringLiteral("Cancel"), 0, 25,
                                nullptr);
  QTest::qSleep(1000);
  restarted.restartTimer();
  QTest::qSleep(100);

  withStartup.setValue(5);
  restarted.setValue(5);

  EXPECT_LT(remainingSeconds(restarted), remainingSeconds(withStartup))
    << restarted.labelText().toStdString() << " vs "
    << withStartup.labelText().toStdString();
}
