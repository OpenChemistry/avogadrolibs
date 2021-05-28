/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "molequeuedialog.h"
#include "molequeuewidget.h"
#include "ui_molequeuedialog.h"

#include <QtWidgets/QMessageBox>
#include <QtWidgets/QProgressDialog>

#include <QtCore/QEventLoop>
#include <QtCore/QTimer>

namespace Avogadro {
namespace MoleQueue {

MoleQueueDialog::MoleQueueDialog(QWidget* parent_)
  : QDialog(parent_), m_ui(new Ui::MoleQueueDialog)
{
  m_ui->setupUi(this);
}

MoleQueueDialog::~MoleQueueDialog()
{
  delete m_ui;
}

MoleQueueDialog::SubmitStatus MoleQueueDialog::submitJob(
  QWidget* parent_, const QString& caption, JobObject& jobTemplate,
  SubmitOptions options, unsigned int* moleQueueId, int* submissionRequestId)
{
  // initialize return args
  if (moleQueueId)
    *moleQueueId = MoleQueueWidget::InvalidMoleQueueId;
  if (submissionRequestId)
    *submissionRequestId = -1;

  MoleQueueDialog dlg(parent_);
  dlg.setWindowTitle(caption);
  dlg.widget().setJobTemplate(jobTemplate);

  if (options & SelectProgramFromTemplate)
    dlg.widget().showAndSelectProgram(jobTemplate.program());

  for (;;) {
    int dlgResult = dlg.exec();

    if (dlgResult != QDialog::Accepted)
      return SubmissionAborted;

    int requestId = dlg.widget().submitJobRequest();

    if (options & WaitForSubmissionResponse || dlg.widget().openOutput()) {
      QProgressDialog progress;
      progress.setCancelButton(nullptr);
      progress.setLabelText(tr("Submitting job to MoleQueue..."));
      progress.setRange(0, 0);
      progress.setValue(0);
      progress.show();

      QList<MetaMethod> submittedSignal;
      submittedSignal << MetaMethod(&dlg.widget(), SIGNAL(jobSubmitted(bool)));
      if (!dlg.waitForSignal(submittedSignal)) {
        progress.hide();
        QMessageBox::information(&dlg, tr("Job Submission Timeout"),
                                 tr("Avogadro timed out waiting for a reply "
                                    "from MoleQueue."));
        continue;
      }

      if (dlg.widget().submissionSuccess()) {
        if (submissionRequestId != nullptr)
          *submissionRequestId = dlg.widget().requestId();
        if (moleQueueId != nullptr)
          *moleQueueId = dlg.widget().moleQueueId();

        // Do we need to wait for the job to finish?
        if (!dlg.widget().openOutput())
          return SubmissionSuccessful;

        // Update progress dialog
        progress.setLabelText(tr("Waiting for job %1 '%2' to finish...")
                                .arg(dlg.widget().moleQueueId())
                                .arg(jobTemplate.description()));
        progress.setCancelButtonText(tr("Stop waiting"));

        // Wait for job completion or progress bar cancellation.
        QList<MetaMethod> completionSignals;
        completionSignals << MetaMethod(&dlg.widget(),
                                        SIGNAL(jobFinished(bool)))
                          << MetaMethod(&progress, SIGNAL(canceled()));

        dlg.waitForSignal(completionSignals, -1);

        // Did the user cancel?
        if (progress.wasCanceled())
          return SubmissionSuccessful;

        // Error occurred:
        if (!dlg.widget().jobSuccess())
          return JobFailed;

        // Update progress bar:
        progress.setLabelText(tr("Fetching completed job information..."));
        progress.setCancelButton(nullptr);

        // Job completed -- overwrite job template with updated job details.
        connect(&dlg.widget(), SIGNAL(jobUpdated(MoleQueue::JobObject)),
                &dlg.widget(), SLOT(setJobTemplate(MoleQueue::JobObject)));
        QList<MetaMethod> lookupSignal;
        lookupSignal << MetaMethod(&dlg.widget(),
                                   SIGNAL(jobUpdated(MoleQueue::JobObject)));
        dlg.widget().requestJobLookup();
        if (!dlg.waitForSignal(lookupSignal)) {
          progress.hide();
          QMessageBox::information(&dlg, tr("Job Retrieval Timeout"),
                                   tr("Avogadro timed out waiting for the "
                                      "finished job details from MoleQueue."));
          return JobFailed;
        }

        jobTemplate = dlg.widget().jobTemplate();
        return JobFinished;
      } else {
        progress.hide();
        QMessageBox::warning(&dlg, tr("Error Submitting Job"),
                             tr("The job has been rejected by MoleQueue: %1")
                               .arg(dlg.widget().submissionError()));
        continue;
      }
    } else {
      if (requestId >= 0) {
        if (submissionRequestId != nullptr)
          *submissionRequestId = requestId;
        return SubmissionAttempted;
      } else {
        return SubmissionFailed;
      }
    }
  }
}

bool MoleQueueDialog::promptForJobOptions(QWidget* windowParent,
                                          const QString& caption,
                                          MoleQueue::JobObject& jobTemplate)
{
  MoleQueueDialog dlg(windowParent);
  dlg.setWindowTitle(caption);
  dlg.widget().setBatchMode(true);
  dlg.widget().setJobTemplate(jobTemplate);
  if (!jobTemplate.program().isEmpty())
    dlg.widget().showAndSelectProgram(jobTemplate.program());

  if (static_cast<DialogCode>(dlg.exec()) != Accepted)
    return false;

  jobTemplate = dlg.widget().configuredJob();
  return true;
}

MoleQueueWidget& MoleQueueDialog::widget()
{
  return *m_ui->widget;
}

const MoleQueueWidget& MoleQueueDialog::widget() const
{
  return *m_ui->widget;
}

bool MoleQueueDialog::waitForSignal(const QList<MetaMethod>& signalList,
                                    int msTimeout) const
{
  QEventLoop waiter;

  foreach (const MetaMethod& sig, signalList)
    connect(sig.first, sig.second, &waiter, SLOT(quit()));

  QTimer limiter;
  if (msTimeout >= 0) {
    limiter.setSingleShot(true);
    connect(&limiter, SIGNAL(timeout()), &waiter, SLOT(quit()));
    limiter.start(msTimeout);
  }

  waiter.exec();

  return limiter.isActive();
}

void MoleQueueDialog::done(int r)
{
  if (r == QDialog::Accepted && !widget().programSelected()) {
    QMessageBox::information(parentWidget(), tr("No program selected."),
                             tr("Please select the target program from the "
                                "\"Queue and Program\" list."));
  } else {
    QDialog::done(r);
  }
}

} // namespace MoleQueue
} // namespace Avogadro
