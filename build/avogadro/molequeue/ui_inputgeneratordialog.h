/********************************************************************************
** Form generated from reading UI file 'inputgeneratordialog.ui'
**
** Created by: Qt User Interface Compiler version 5.15.17
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_INPUTGENERATORDIALOG_H
#define UI_INPUTGENERATORDIALOG_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QDialog>
#include <QtWidgets/QVBoxLayout>
#include <avogadro/molequeue/inputgeneratorwidget.h>

namespace Avogadro {
namespace MoleQueue {

class Ui_InputGeneratorDialog
{
public:
    QVBoxLayout *verticalLayout;
    Avogadro::MoleQueue::InputGeneratorWidget *widget;

    void setupUi(QDialog *Avogadro__MoleQueue__InputGeneratorDialog)
    {
        if (Avogadro__MoleQueue__InputGeneratorDialog->objectName().isEmpty())
            Avogadro__MoleQueue__InputGeneratorDialog->setObjectName(QString::fromUtf8("Avogadro__MoleQueue__InputGeneratorDialog"));
        Avogadro__MoleQueue__InputGeneratorDialog->resize(750, 650);
        verticalLayout = new QVBoxLayout(Avogadro__MoleQueue__InputGeneratorDialog);
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        widget = new Avogadro::MoleQueue::InputGeneratorWidget(Avogadro__MoleQueue__InputGeneratorDialog);
        widget->setObjectName(QString::fromUtf8("widget"));

        verticalLayout->addWidget(widget);


        retranslateUi(Avogadro__MoleQueue__InputGeneratorDialog);

        QMetaObject::connectSlotsByName(Avogadro__MoleQueue__InputGeneratorDialog);
    } // setupUi

    void retranslateUi(QDialog *Avogadro__MoleQueue__InputGeneratorDialog)
    {
        Avogadro__MoleQueue__InputGeneratorDialog->setWindowTitle(QCoreApplication::translate("Avogadro::MoleQueue::InputGeneratorDialog", "Dialog", nullptr));
    } // retranslateUi

};

} // namespace MoleQueue
} // namespace Avogadro

namespace Avogadro {
namespace MoleQueue {
namespace Ui {
    class InputGeneratorDialog: public Ui_InputGeneratorDialog {};
} // namespace Ui
} // namespace MoleQueue
} // namespace Avogadro

#endif // UI_INPUTGENERATORDIALOG_H
