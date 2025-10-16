/********************************************************************************
** Form generated from reading UI file 'chargedialog.ui'
**
** Created by: Qt User Interface Compiler version 5.15.17
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_CHARGEDIALOG_H
#define UI_CHARGEDIALOG_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QDialog>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QFormLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QSpacerItem>

QT_BEGIN_NAMESPACE

class Ui_ChargeDialog
{
public:
    QFormLayout *formLayout;
    QLabel *colormapLabel;
    QDialogButtonBox *buttonBox;
    QComboBox *colorMapCombo;
    QComboBox *modelCombo;
    QLabel *chargeModelLabel;
    QSpacerItem *verticalSpacer;

    void setupUi(QDialog *ChargeDialog)
    {
        if (ChargeDialog->objectName().isEmpty())
            ChargeDialog->setObjectName(QString::fromUtf8("ChargeDialog"));
        ChargeDialog->resize(293, 126);
        formLayout = new QFormLayout(ChargeDialog);
        formLayout->setObjectName(QString::fromUtf8("formLayout"));
        colormapLabel = new QLabel(ChargeDialog);
        colormapLabel->setObjectName(QString::fromUtf8("colormapLabel"));

        formLayout->setWidget(1, QFormLayout::LabelRole, colormapLabel);

        buttonBox = new QDialogButtonBox(ChargeDialog);
        buttonBox->setObjectName(QString::fromUtf8("buttonBox"));
        buttonBox->setStandardButtons(QDialogButtonBox::Cancel|QDialogButtonBox::Ok);

        formLayout->setWidget(2, QFormLayout::FieldRole, buttonBox);

        colorMapCombo = new QComboBox(ChargeDialog);
        colorMapCombo->addItem(QString());
        colorMapCombo->addItem(QString());
        colorMapCombo->addItem(QString());
        colorMapCombo->addItem(QString());
        colorMapCombo->addItem(QString());
        colorMapCombo->setObjectName(QString::fromUtf8("colorMapCombo"));

        formLayout->setWidget(1, QFormLayout::FieldRole, colorMapCombo);

        modelCombo = new QComboBox(ChargeDialog);
        modelCombo->setObjectName(QString::fromUtf8("modelCombo"));

        formLayout->setWidget(0, QFormLayout::FieldRole, modelCombo);

        chargeModelLabel = new QLabel(ChargeDialog);
        chargeModelLabel->setObjectName(QString::fromUtf8("chargeModelLabel"));

        formLayout->setWidget(0, QFormLayout::LabelRole, chargeModelLabel);

        verticalSpacer = new QSpacerItem(20, 40, QSizePolicy::Minimum, QSizePolicy::Expanding);

        formLayout->setItem(2, QFormLayout::LabelRole, verticalSpacer);

        QWidget::setTabOrder(modelCombo, colorMapCombo);

        retranslateUi(ChargeDialog);
        QObject::connect(buttonBox, SIGNAL(rejected()), ChargeDialog, SLOT(reject()));
        QObject::connect(buttonBox, SIGNAL(accepted()), ChargeDialog, SLOT(accept()));

        QMetaObject::connectSlotsByName(ChargeDialog);
    } // setupUi

    void retranslateUi(QDialog *ChargeDialog)
    {
        ChargeDialog->setWindowTitle(QCoreApplication::translate("ChargeDialog", "Partial Charges", nullptr));
        colormapLabel->setText(QCoreApplication::translate("ChargeDialog", "Colormap:", nullptr));
        colorMapCombo->setItemText(0, QCoreApplication::translate("ChargeDialog", "Balance", "colormap"));
        colorMapCombo->setItemText(1, QCoreApplication::translate("ChargeDialog", "Blue-DarkRed", "colormap"));
        colorMapCombo->setItemText(2, QCoreApplication::translate("ChargeDialog", "Coolwarm", "colormap"));
        colorMapCombo->setItemText(3, QCoreApplication::translate("ChargeDialog", "Spectral", "colormap"));
        colorMapCombo->setItemText(4, QCoreApplication::translate("ChargeDialog", "Turbo", "colormap"));

        chargeModelLabel->setText(QCoreApplication::translate("ChargeDialog", "Charge Model:", nullptr));
    } // retranslateUi

};

namespace Ui {
    class ChargeDialog: public Ui_ChargeDialog {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_CHARGEDIALOG_H
