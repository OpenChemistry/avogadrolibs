/********************************************************************************
** Form generated from reading UI file 'apbsoutputdialog.ui'
**
** Created by: Qt User Interface Compiler version 5.15.17
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_APBSOUTPUTDIALOG_H
#define UI_APBSOUTPUTDIALOG_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QDialog>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QLabel>
#include <QtWidgets/QVBoxLayout>

QT_BEGIN_NAMESPACE

class Ui_ApbsOutputDialog
{
public:
    QVBoxLayout *verticalLayout;
    QLabel *label;
    QCheckBox *loadStructureCheckBox;
    QCheckBox *loadCubeCheckBox;
    QDialogButtonBox *buttonBox;

    void setupUi(QDialog *ApbsOutputDialog)
    {
        if (ApbsOutputDialog->objectName().isEmpty())
            ApbsOutputDialog->setObjectName(QString::fromUtf8("ApbsOutputDialog"));
        ApbsOutputDialog->resize(325, 99);
        verticalLayout = new QVBoxLayout(ApbsOutputDialog);
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        label = new QLabel(ApbsOutputDialog);
        label->setObjectName(QString::fromUtf8("label"));

        verticalLayout->addWidget(label);

        loadStructureCheckBox = new QCheckBox(ApbsOutputDialog);
        loadStructureCheckBox->setObjectName(QString::fromUtf8("loadStructureCheckBox"));
        loadStructureCheckBox->setChecked(true);

        verticalLayout->addWidget(loadStructureCheckBox);

        loadCubeCheckBox = new QCheckBox(ApbsOutputDialog);
        loadCubeCheckBox->setObjectName(QString::fromUtf8("loadCubeCheckBox"));
        loadCubeCheckBox->setChecked(true);

        verticalLayout->addWidget(loadCubeCheckBox);

        buttonBox = new QDialogButtonBox(ApbsOutputDialog);
        buttonBox->setObjectName(QString::fromUtf8("buttonBox"));
        buttonBox->setOrientation(Qt::Horizontal);
        buttonBox->setStandardButtons(QDialogButtonBox::Cancel|QDialogButtonBox::Ok);

        verticalLayout->addWidget(buttonBox);


        retranslateUi(ApbsOutputDialog);
        QObject::connect(buttonBox, SIGNAL(accepted()), ApbsOutputDialog, SLOT(accept()));
        QObject::connect(buttonBox, SIGNAL(rejected()), ApbsOutputDialog, SLOT(reject()));

        QMetaObject::connectSlotsByName(ApbsOutputDialog);
    } // setupUi

    void retranslateUi(QDialog *ApbsOutputDialog)
    {
        ApbsOutputDialog->setWindowTitle(QCoreApplication::translate("ApbsOutputDialog", "Success", nullptr));
        label->setText(QCoreApplication::translate("ApbsOutputDialog", "Success!", nullptr));
        loadStructureCheckBox->setText(QCoreApplication::translate("ApbsOutputDialog", "Load Structure File", nullptr));
        loadCubeCheckBox->setText(QCoreApplication::translate("ApbsOutputDialog", "Load Cube File", nullptr));
    } // retranslateUi

};

namespace Ui {
    class ApbsOutputDialog: public Ui_ApbsOutputDialog {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_APBSOUTPUTDIALOG_H
