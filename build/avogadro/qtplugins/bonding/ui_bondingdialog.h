/********************************************************************************
** Form generated from reading UI file 'bondingdialog.ui'
**
** Created by: Qt User Interface Compiler version 5.15.17
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_BONDINGDIALOG_H
#define UI_BONDINGDIALOG_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QDialog>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QDoubleSpinBox>
#include <QtWidgets/QFormLayout>
#include <QtWidgets/QLabel>

QT_BEGIN_NAMESPACE

class Ui_BondingDialog
{
public:
    QFormLayout *formLayout;
    QLabel *label;
    QLabel *label_2;
    QDialogButtonBox *buttonBox;
    QDoubleSpinBox *toleranceSpinBox;
    QDoubleSpinBox *minimumSpinBox;

    void setupUi(QDialog *BondingDialog)
    {
        if (BondingDialog->objectName().isEmpty())
            BondingDialog->setObjectName(QString::fromUtf8("BondingDialog"));
        BondingDialog->resize(305, 122);
        formLayout = new QFormLayout(BondingDialog);
        formLayout->setObjectName(QString::fromUtf8("formLayout"));
        label = new QLabel(BondingDialog);
        label->setObjectName(QString::fromUtf8("label"));

        formLayout->setWidget(0, QFormLayout::LabelRole, label);

        label_2 = new QLabel(BondingDialog);
        label_2->setObjectName(QString::fromUtf8("label_2"));

        formLayout->setWidget(1, QFormLayout::LabelRole, label_2);

        buttonBox = new QDialogButtonBox(BondingDialog);
        buttonBox->setObjectName(QString::fromUtf8("buttonBox"));
        buttonBox->setStandardButtons(QDialogButtonBox::Cancel|QDialogButtonBox::Ok);

        formLayout->setWidget(2, QFormLayout::FieldRole, buttonBox);

        toleranceSpinBox = new QDoubleSpinBox(BondingDialog);
        toleranceSpinBox->setObjectName(QString::fromUtf8("toleranceSpinBox"));
        toleranceSpinBox->setDecimals(3);
        toleranceSpinBox->setMaximum(2.000000000000000);
        toleranceSpinBox->setSingleStep(0.050000000000000);
        toleranceSpinBox->setValue(0.450000000000000);

        formLayout->setWidget(0, QFormLayout::FieldRole, toleranceSpinBox);

        minimumSpinBox = new QDoubleSpinBox(BondingDialog);
        minimumSpinBox->setObjectName(QString::fromUtf8("minimumSpinBox"));
        minimumSpinBox->setDecimals(3);
        minimumSpinBox->setMaximum(1.000000000000000);
        minimumSpinBox->setSingleStep(0.100000000000000);
        minimumSpinBox->setValue(0.100000000000000);

        formLayout->setWidget(1, QFormLayout::FieldRole, minimumSpinBox);


        retranslateUi(BondingDialog);

        QMetaObject::connectSlotsByName(BondingDialog);
    } // setupUi

    void retranslateUi(QDialog *BondingDialog)
    {
        BondingDialog->setWindowTitle(QCoreApplication::translate("BondingDialog", "Form", nullptr));
        label->setText(QCoreApplication::translate("BondingDialog", "Distance Tolerance:", nullptr));
        label_2->setText(QCoreApplication::translate("BondingDialog", "Minimum Distance:", nullptr));
        toleranceSpinBox->setSuffix(QCoreApplication::translate("BondingDialog", " \303\205", nullptr));
        minimumSpinBox->setSuffix(QCoreApplication::translate("BondingDialog", " \303\205", nullptr));
    } // retranslateUi

};

namespace Ui {
    class BondingDialog: public Ui_BondingDialog {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_BONDINGDIALOG_H
