/********************************************************************************
** Form generated from reading UI file 'apbsdialog.ui'
**
** Created by: Qt User Interface Compiler version 5.15.17
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_APBSDIALOG_H
#define UI_APBSDIALOG_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QDialog>
#include <QtWidgets/QGroupBox>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QRadioButton>
#include <QtWidgets/QTextEdit>
#include <QtWidgets/QVBoxLayout>

QT_BEGIN_NAMESPACE

class Ui_ApbsDialog
{
public:
    QVBoxLayout *verticalLayout_2;
    QGroupBox *groupBox;
    QVBoxLayout *verticalLayout_3;
    QVBoxLayout *verticalLayout;
    QRadioButton *generateFromPdbButton;
    QHBoxLayout *horizontalLayout;
    QLabel *pdbFileLabel;
    QLineEdit *pdbFileLineEdit;
    QPushButton *openPdbFileButton;
    QHBoxLayout *horizontalLayout_4;
    QLabel *label;
    QComboBox *forceFieldComboBox;
    QPushButton *runPdb2PqrButton;
    QRadioButton *loadFromPqrButton;
    QHBoxLayout *horizontalLayout_2;
    QLabel *pqrFileLabel;
    QLineEdit *pqrFileLineEdit;
    QPushButton *openPqrFileButton;
    QGroupBox *groupBox_2;
    QVBoxLayout *verticalLayout_4;
    QTextEdit *textEdit;
    QHBoxLayout *horizontalLayout_3;
    QPushButton *saveInputFileButton;
    QPushButton *runApbsButton;
    QPushButton *closeButton;

    void setupUi(QDialog *ApbsDialog)
    {
        if (ApbsDialog->objectName().isEmpty())
            ApbsDialog->setObjectName(QString::fromUtf8("ApbsDialog"));
        ApbsDialog->resize(794, 644);
        verticalLayout_2 = new QVBoxLayout(ApbsDialog);
        verticalLayout_2->setObjectName(QString::fromUtf8("verticalLayout_2"));
        groupBox = new QGroupBox(ApbsDialog);
        groupBox->setObjectName(QString::fromUtf8("groupBox"));
        verticalLayout_3 = new QVBoxLayout(groupBox);
        verticalLayout_3->setObjectName(QString::fromUtf8("verticalLayout_3"));
        verticalLayout = new QVBoxLayout();
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        generateFromPdbButton = new QRadioButton(groupBox);
        generateFromPdbButton->setObjectName(QString::fromUtf8("generateFromPdbButton"));
        generateFromPdbButton->setChecked(true);

        verticalLayout->addWidget(generateFromPdbButton);

        horizontalLayout = new QHBoxLayout();
        horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));
        pdbFileLabel = new QLabel(groupBox);
        pdbFileLabel->setObjectName(QString::fromUtf8("pdbFileLabel"));

        horizontalLayout->addWidget(pdbFileLabel);

        pdbFileLineEdit = new QLineEdit(groupBox);
        pdbFileLineEdit->setObjectName(QString::fromUtf8("pdbFileLineEdit"));

        horizontalLayout->addWidget(pdbFileLineEdit);

        openPdbFileButton = new QPushButton(groupBox);
        openPdbFileButton->setObjectName(QString::fromUtf8("openPdbFileButton"));

        horizontalLayout->addWidget(openPdbFileButton);


        verticalLayout->addLayout(horizontalLayout);

        horizontalLayout_4 = new QHBoxLayout();
        horizontalLayout_4->setObjectName(QString::fromUtf8("horizontalLayout_4"));
        label = new QLabel(groupBox);
        label->setObjectName(QString::fromUtf8("label"));
        QSizePolicy sizePolicy(QSizePolicy::Maximum, QSizePolicy::Preferred);
        sizePolicy.setHorizontalStretch(0);
        sizePolicy.setVerticalStretch(0);
        sizePolicy.setHeightForWidth(label->sizePolicy().hasHeightForWidth());
        label->setSizePolicy(sizePolicy);

        horizontalLayout_4->addWidget(label);

        forceFieldComboBox = new QComboBox(groupBox);
        forceFieldComboBox->addItem(QString());
        forceFieldComboBox->addItem(QString());
        forceFieldComboBox->addItem(QString());
        forceFieldComboBox->addItem(QString());
        forceFieldComboBox->addItem(QString());
        forceFieldComboBox->addItem(QString());
        forceFieldComboBox->setObjectName(QString::fromUtf8("forceFieldComboBox"));

        horizontalLayout_4->addWidget(forceFieldComboBox);

        runPdb2PqrButton = new QPushButton(groupBox);
        runPdb2PqrButton->setObjectName(QString::fromUtf8("runPdb2PqrButton"));
        QSizePolicy sizePolicy1(QSizePolicy::Maximum, QSizePolicy::Fixed);
        sizePolicy1.setHorizontalStretch(0);
        sizePolicy1.setVerticalStretch(0);
        sizePolicy1.setHeightForWidth(runPdb2PqrButton->sizePolicy().hasHeightForWidth());
        runPdb2PqrButton->setSizePolicy(sizePolicy1);

        horizontalLayout_4->addWidget(runPdb2PqrButton);


        verticalLayout->addLayout(horizontalLayout_4);

        loadFromPqrButton = new QRadioButton(groupBox);
        loadFromPqrButton->setObjectName(QString::fromUtf8("loadFromPqrButton"));

        verticalLayout->addWidget(loadFromPqrButton);

        horizontalLayout_2 = new QHBoxLayout();
        horizontalLayout_2->setObjectName(QString::fromUtf8("horizontalLayout_2"));
        pqrFileLabel = new QLabel(groupBox);
        pqrFileLabel->setObjectName(QString::fromUtf8("pqrFileLabel"));

        horizontalLayout_2->addWidget(pqrFileLabel);

        pqrFileLineEdit = new QLineEdit(groupBox);
        pqrFileLineEdit->setObjectName(QString::fromUtf8("pqrFileLineEdit"));

        horizontalLayout_2->addWidget(pqrFileLineEdit);

        openPqrFileButton = new QPushButton(groupBox);
        openPqrFileButton->setObjectName(QString::fromUtf8("openPqrFileButton"));

        horizontalLayout_2->addWidget(openPqrFileButton);


        verticalLayout->addLayout(horizontalLayout_2);


        verticalLayout_3->addLayout(verticalLayout);


        verticalLayout_2->addWidget(groupBox);

        groupBox_2 = new QGroupBox(ApbsDialog);
        groupBox_2->setObjectName(QString::fromUtf8("groupBox_2"));
        verticalLayout_4 = new QVBoxLayout(groupBox_2);
        verticalLayout_4->setObjectName(QString::fromUtf8("verticalLayout_4"));
        textEdit = new QTextEdit(groupBox_2);
        textEdit->setObjectName(QString::fromUtf8("textEdit"));

        verticalLayout_4->addWidget(textEdit);


        verticalLayout_2->addWidget(groupBox_2);

        horizontalLayout_3 = new QHBoxLayout();
        horizontalLayout_3->setObjectName(QString::fromUtf8("horizontalLayout_3"));
        saveInputFileButton = new QPushButton(ApbsDialog);
        saveInputFileButton->setObjectName(QString::fromUtf8("saveInputFileButton"));

        horizontalLayout_3->addWidget(saveInputFileButton);

        runApbsButton = new QPushButton(ApbsDialog);
        runApbsButton->setObjectName(QString::fromUtf8("runApbsButton"));

        horizontalLayout_3->addWidget(runApbsButton);

        closeButton = new QPushButton(ApbsDialog);
        closeButton->setObjectName(QString::fromUtf8("closeButton"));

        horizontalLayout_3->addWidget(closeButton);


        verticalLayout_2->addLayout(horizontalLayout_3);


        retranslateUi(ApbsDialog);

        QMetaObject::connectSlotsByName(ApbsDialog);
    } // setupUi

    void retranslateUi(QDialog *ApbsDialog)
    {
        ApbsDialog->setWindowTitle(QCoreApplication::translate("ApbsDialog", "APBS", nullptr));
        groupBox->setTitle(QCoreApplication::translate("ApbsDialog", "Structure Input File", nullptr));
        generateFromPdbButton->setText(QCoreApplication::translate("ApbsDialog", "Generate Input From PDB", nullptr));
        pdbFileLabel->setText(QCoreApplication::translate("ApbsDialog", "PDB File:", nullptr));
        openPdbFileButton->setText(QCoreApplication::translate("ApbsDialog", "\342\200\246", nullptr));
        label->setText(QCoreApplication::translate("ApbsDialog", "Force Field:", nullptr));
        forceFieldComboBox->setItemText(0, QCoreApplication::translate("ApbsDialog", "AMBER", nullptr));
        forceFieldComboBox->setItemText(1, QCoreApplication::translate("ApbsDialog", "CHARMM", nullptr));
        forceFieldComboBox->setItemText(2, QCoreApplication::translate("ApbsDialog", "PARSE", nullptr));
        forceFieldComboBox->setItemText(3, QCoreApplication::translate("ApbsDialog", "TYL06", nullptr));
        forceFieldComboBox->setItemText(4, QCoreApplication::translate("ApbsDialog", "PEOEPB", nullptr));
        forceFieldComboBox->setItemText(5, QCoreApplication::translate("ApbsDialog", "SWANSON", nullptr));

        runPdb2PqrButton->setText(QCoreApplication::translate("ApbsDialog", "Run PDB2PQR", nullptr));
        loadFromPqrButton->setText(QCoreApplication::translate("ApbsDialog", "Load Existing PQR File", nullptr));
        pqrFileLabel->setText(QCoreApplication::translate("ApbsDialog", "PQR File:", nullptr));
        openPqrFileButton->setText(QCoreApplication::translate("ApbsDialog", "\342\200\246", nullptr));
        groupBox_2->setTitle(QCoreApplication::translate("ApbsDialog", "APBS Input File", nullptr));
        saveInputFileButton->setText(QCoreApplication::translate("ApbsDialog", "Save Input File", nullptr));
        runApbsButton->setText(QCoreApplication::translate("ApbsDialog", "Run APBS", nullptr));
        closeButton->setText(QCoreApplication::translate("ApbsDialog", "Close", nullptr));
    } // retranslateUi

};

namespace Ui {
    class ApbsDialog: public Ui_ApbsDialog {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_APBSDIALOG_H
