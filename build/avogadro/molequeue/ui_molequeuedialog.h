/********************************************************************************
** Form generated from reading UI file 'molequeuedialog.ui'
**
** Created by: Qt User Interface Compiler version 5.15.17
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_MOLEQUEUEDIALOG_H
#define UI_MOLEQUEUEDIALOG_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QDialog>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QVBoxLayout>
#include <avogadro/molequeue/molequeuewidget.h>

namespace Avogadro {
namespace MoleQueue {

class Ui_MoleQueueDialog
{
public:
    QVBoxLayout *verticalLayout;
    Avogadro::MoleQueue::MoleQueueWidget *widget;
    QDialogButtonBox *buttonBox;

    void setupUi(QDialog *Avogadro__MoleQueue__MoleQueueDialog)
    {
        if (Avogadro__MoleQueue__MoleQueueDialog->objectName().isEmpty())
            Avogadro__MoleQueue__MoleQueueDialog->setObjectName(QString::fromUtf8("Avogadro__MoleQueue__MoleQueueDialog"));
        Avogadro__MoleQueue__MoleQueueDialog->resize(400, 300);
        verticalLayout = new QVBoxLayout(Avogadro__MoleQueue__MoleQueueDialog);
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        widget = new Avogadro::MoleQueue::MoleQueueWidget(Avogadro__MoleQueue__MoleQueueDialog);
        widget->setObjectName(QString::fromUtf8("widget"));

        verticalLayout->addWidget(widget);

        buttonBox = new QDialogButtonBox(Avogadro__MoleQueue__MoleQueueDialog);
        buttonBox->setObjectName(QString::fromUtf8("buttonBox"));
        buttonBox->setOrientation(Qt::Horizontal);
        buttonBox->setStandardButtons(QDialogButtonBox::Cancel|QDialogButtonBox::Ok);

        verticalLayout->addWidget(buttonBox);


        retranslateUi(Avogadro__MoleQueue__MoleQueueDialog);
        QObject::connect(buttonBox, SIGNAL(accepted()), Avogadro__MoleQueue__MoleQueueDialog, SLOT(accept()));
        QObject::connect(buttonBox, SIGNAL(rejected()), Avogadro__MoleQueue__MoleQueueDialog, SLOT(reject()));

        QMetaObject::connectSlotsByName(Avogadro__MoleQueue__MoleQueueDialog);
    } // setupUi

    void retranslateUi(QDialog *Avogadro__MoleQueue__MoleQueueDialog)
    {
        Avogadro__MoleQueue__MoleQueueDialog->setWindowTitle(QCoreApplication::translate("Avogadro::MoleQueue::MoleQueueDialog", "Dialog", nullptr));
    } // retranslateUi

};

} // namespace MoleQueue
} // namespace Avogadro

namespace Avogadro {
namespace MoleQueue {
namespace Ui {
    class MoleQueueDialog: public Ui_MoleQueueDialog {};
} // namespace Ui
} // namespace MoleQueue
} // namespace Avogadro

#endif // UI_MOLEQUEUEDIALOG_H
