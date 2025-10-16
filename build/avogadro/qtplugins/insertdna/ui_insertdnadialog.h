/********************************************************************************
** Form generated from reading UI file 'insertdnadialog.ui'
**
** Created by: Qt User Interface Compiler version 5.15.17
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_INSERTDNADIALOG_H
#define UI_INSERTDNADIALOG_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QDialog>
#include <QtWidgets/QDoubleSpinBox>
#include <QtWidgets/QGridLayout>
#include <QtWidgets/QGroupBox>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QPlainTextEdit>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QRadioButton>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QToolButton>
#include <QtWidgets/QVBoxLayout>

QT_BEGIN_NAMESPACE

class Ui_InsertDNADialog
{
public:
    QVBoxLayout *verticalLayout;
    QGroupBox *groupBox;
    QVBoxLayout *verticalLayout_2;
    QComboBox *typeComboBox;
    QLabel *label_6;
    QHBoxLayout *horizontalLayout;
    QToolButton *toolButton_A;
    QToolButton *toolButton_C;
    QToolButton *toolButton_G;
    QToolButton *toolButton_TU;
    QSpacerItem *horizontalSpacer;
    QLabel *label;
    QPlainTextEdit *sequenceText;
    QGridLayout *gridLayout_3;
    QComboBox *bpCombo;
    QDoubleSpinBox *bpTurnsSpin;
    QLabel *label_3;
    QHBoxLayout *horizontalLayout_3;
    QLabel *label_2;
    QRadioButton *singleStrandRadio;
    QRadioButton *doubleStrandRadio;
    QHBoxLayout *horizontalLayout_2;
    QSpacerItem *horizontalSpacer_3;
    QPushButton *insertButton;
    QSpacerItem *horizontalSpacer_2;
    QSpacerItem *verticalSpacer;

    void setupUi(QDialog *InsertDNADialog)
    {
        if (InsertDNADialog->objectName().isEmpty())
            InsertDNADialog->setObjectName(QString::fromUtf8("InsertDNADialog"));
        InsertDNADialog->resize(365, 384);
        verticalLayout = new QVBoxLayout(InsertDNADialog);
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        groupBox = new QGroupBox(InsertDNADialog);
        groupBox->setObjectName(QString::fromUtf8("groupBox"));
        verticalLayout_2 = new QVBoxLayout(groupBox);
        verticalLayout_2->setObjectName(QString::fromUtf8("verticalLayout_2"));
        typeComboBox = new QComboBox(groupBox);
        typeComboBox->addItem(QString());
        typeComboBox->addItem(QString());
        typeComboBox->setObjectName(QString::fromUtf8("typeComboBox"));

        verticalLayout_2->addWidget(typeComboBox);

        label_6 = new QLabel(groupBox);
        label_6->setObjectName(QString::fromUtf8("label_6"));

        verticalLayout_2->addWidget(label_6);

        horizontalLayout = new QHBoxLayout();
        horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));
        toolButton_A = new QToolButton(groupBox);
        toolButton_A->setObjectName(QString::fromUtf8("toolButton_A"));

        horizontalLayout->addWidget(toolButton_A);

        toolButton_C = new QToolButton(groupBox);
        toolButton_C->setObjectName(QString::fromUtf8("toolButton_C"));

        horizontalLayout->addWidget(toolButton_C);

        toolButton_G = new QToolButton(groupBox);
        toolButton_G->setObjectName(QString::fromUtf8("toolButton_G"));

        horizontalLayout->addWidget(toolButton_G);

        toolButton_TU = new QToolButton(groupBox);
        toolButton_TU->setObjectName(QString::fromUtf8("toolButton_TU"));

        horizontalLayout->addWidget(toolButton_TU);

        horizontalSpacer = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout->addItem(horizontalSpacer);


        verticalLayout_2->addLayout(horizontalLayout);

        label = new QLabel(groupBox);
        label->setObjectName(QString::fromUtf8("label"));

        verticalLayout_2->addWidget(label);

        sequenceText = new QPlainTextEdit(groupBox);
        sequenceText->setObjectName(QString::fromUtf8("sequenceText"));
        sequenceText->setFocusPolicy(Qt::StrongFocus);

        verticalLayout_2->addWidget(sequenceText);

        gridLayout_3 = new QGridLayout();
        gridLayout_3->setObjectName(QString::fromUtf8("gridLayout_3"));
        bpCombo = new QComboBox(groupBox);
        bpCombo->addItem(QString());
        bpCombo->addItem(QString());
        bpCombo->addItem(QString());
        bpCombo->addItem(QString());
        bpCombo->setObjectName(QString::fromUtf8("bpCombo"));

        gridLayout_3->addWidget(bpCombo, 0, 1, 1, 1);

        bpTurnsSpin = new QDoubleSpinBox(groupBox);
        bpTurnsSpin->setObjectName(QString::fromUtf8("bpTurnsSpin"));
        bpTurnsSpin->setDecimals(1);
        bpTurnsSpin->setMinimum(0.000000000000000);
        bpTurnsSpin->setMaximum(15.000000000000000);
        bpTurnsSpin->setValue(10.500000000000000);

        gridLayout_3->addWidget(bpTurnsSpin, 0, 2, 1, 1);

        label_3 = new QLabel(groupBox);
        label_3->setObjectName(QString::fromUtf8("label_3"));

        gridLayout_3->addWidget(label_3, 0, 0, 1, 1);


        verticalLayout_2->addLayout(gridLayout_3);

        horizontalLayout_3 = new QHBoxLayout();
        horizontalLayout_3->setObjectName(QString::fromUtf8("horizontalLayout_3"));
        label_2 = new QLabel(groupBox);
        label_2->setObjectName(QString::fromUtf8("label_2"));

        horizontalLayout_3->addWidget(label_2);

        singleStrandRadio = new QRadioButton(groupBox);
        singleStrandRadio->setObjectName(QString::fromUtf8("singleStrandRadio"));

        horizontalLayout_3->addWidget(singleStrandRadio);

        doubleStrandRadio = new QRadioButton(groupBox);
        doubleStrandRadio->setObjectName(QString::fromUtf8("doubleStrandRadio"));
        doubleStrandRadio->setChecked(true);

        horizontalLayout_3->addWidget(doubleStrandRadio);


        verticalLayout_2->addLayout(horizontalLayout_3);


        verticalLayout->addWidget(groupBox);

        horizontalLayout_2 = new QHBoxLayout();
        horizontalLayout_2->setObjectName(QString::fromUtf8("horizontalLayout_2"));
        horizontalSpacer_3 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_2->addItem(horizontalSpacer_3);

        insertButton = new QPushButton(InsertDNADialog);
        insertButton->setObjectName(QString::fromUtf8("insertButton"));

        horizontalLayout_2->addWidget(insertButton);

        horizontalSpacer_2 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_2->addItem(horizontalSpacer_2);


        verticalLayout->addLayout(horizontalLayout_2);

        verticalSpacer = new QSpacerItem(20, 0, QSizePolicy::Minimum, QSizePolicy::Expanding);

        verticalLayout->addItem(verticalSpacer);


        retranslateUi(InsertDNADialog);

        bpCombo->setCurrentIndex(1);
        insertButton->setDefault(true);


        QMetaObject::connectSlotsByName(InsertDNADialog);
    } // setupUi

    void retranslateUi(QDialog *InsertDNADialog)
    {
        InsertDNADialog->setWindowTitle(QCoreApplication::translate("InsertDNADialog", "Insert Nucleic Acids", nullptr));
        groupBox->setTitle(QCoreApplication::translate("InsertDNADialog", "DNA/RNA Builder", nullptr));
        typeComboBox->setItemText(0, QCoreApplication::translate("InsertDNADialog", "DNA", nullptr));
        typeComboBox->setItemText(1, QCoreApplication::translate("InsertDNADialog", "RNA", nullptr));

        label_6->setText(QCoreApplication::translate("InsertDNADialog", "Nucleic Acids:", nullptr));
#if QT_CONFIG(tooltip)
        toolButton_A->setToolTip(QCoreApplication::translate("InsertDNADialog", "Adenine", nullptr));
#endif // QT_CONFIG(tooltip)
        toolButton_A->setText(QCoreApplication::translate("InsertDNADialog", "A", nullptr));
#if QT_CONFIG(tooltip)
        toolButton_C->setToolTip(QCoreApplication::translate("InsertDNADialog", "Cytosine", nullptr));
#endif // QT_CONFIG(tooltip)
        toolButton_C->setText(QCoreApplication::translate("InsertDNADialog", "C", nullptr));
#if QT_CONFIG(tooltip)
        toolButton_G->setToolTip(QCoreApplication::translate("InsertDNADialog", "Guanine", nullptr));
#endif // QT_CONFIG(tooltip)
        toolButton_G->setText(QCoreApplication::translate("InsertDNADialog", "G", nullptr));
#if QT_CONFIG(tooltip)
        toolButton_TU->setToolTip(QCoreApplication::translate("InsertDNADialog", "Thymine", nullptr));
#endif // QT_CONFIG(tooltip)
        toolButton_TU->setText(QCoreApplication::translate("InsertDNADialog", "T", nullptr));
        label->setText(QCoreApplication::translate("InsertDNADialog", "Sequence:", nullptr));
        bpCombo->setItemText(0, QCoreApplication::translate("InsertDNADialog", "A", nullptr));
        bpCombo->setItemText(1, QCoreApplication::translate("InsertDNADialog", "B", nullptr));
        bpCombo->setItemText(2, QCoreApplication::translate("InsertDNADialog", "Z", nullptr));
        bpCombo->setItemText(3, QCoreApplication::translate("InsertDNADialog", "Other", nullptr));

#if QT_CONFIG(tooltip)
        bpCombo->setToolTip(QCoreApplication::translate("InsertDNADialog", "the number of base pairs per helix turn", nullptr));
#endif // QT_CONFIG(tooltip)
#if QT_CONFIG(tooltip)
        bpTurnsSpin->setToolTip(QCoreApplication::translate("InsertDNADialog", "the number of base pairs per helix turn", nullptr));
#endif // QT_CONFIG(tooltip)
        bpTurnsSpin->setSuffix(QString());
        label_3->setText(QCoreApplication::translate("InsertDNADialog", "Bases Per Turn:", nullptr));
        label_2->setText(QCoreApplication::translate("InsertDNADialog", "Strands:", nullptr));
        singleStrandRadio->setText(QCoreApplication::translate("InsertDNADialog", "Single", nullptr));
        doubleStrandRadio->setText(QCoreApplication::translate("InsertDNADialog", "Double", nullptr));
        insertButton->setText(QCoreApplication::translate("InsertDNADialog", "Insert", nullptr));
    } // retranslateUi

};

namespace Ui {
    class InsertDNADialog: public Ui_InsertDNADialog {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_INSERTDNADIALOG_H
