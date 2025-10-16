/********************************************************************************
** Form generated from reading UI file 'conformersearchdialog.ui'
**
** Created by: Qt User Interface Compiler version 5.15.17
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_CONFORMERSEARCHDIALOG_H
#define UI_CONFORMERSEARCHDIALOG_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QDialog>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QFormLayout>
#include <QtWidgets/QGroupBox>
#include <QtWidgets/QLabel>
#include <QtWidgets/QRadioButton>
#include <QtWidgets/QSpinBox>
#include <QtWidgets/QVBoxLayout>

QT_BEGIN_NAMESPACE

class Ui_ConformerSearchDialog
{
public:
    QVBoxLayout *vboxLayout;
    QGroupBox *systematicOptionsGroupBox;
    QFormLayout *formLayout;
    QLabel *label;
    QSpinBox *numSpin;
    QRadioButton *systematicRadio;
    QRadioButton *randomRadio;
    QRadioButton *weightedRadio;
    QRadioButton *geneticRadio;
    QLabel *optimizationStepsLabel;
    QSpinBox *optimizationStepsSpinBox;
    QGroupBox *geneticGroupBox;
    QVBoxLayout *verticalLayout;
    QFormLayout *formLayout_2;
    QLabel *label_2;
    QSpinBox *childrenSpinBox;
    QLabel *label_3;
    QSpinBox *mutabilitySpinBox;
    QLabel *label_4;
    QSpinBox *convergenceSpinBox;
    QLabel *label_5;
    QComboBox *scoringComboBox;
    QDialogButtonBox *buttonBox;

    void setupUi(QDialog *ConformerSearchDialog)
    {
        if (ConformerSearchDialog->objectName().isEmpty())
            ConformerSearchDialog->setObjectName(QString::fromUtf8("ConformerSearchDialog"));
        ConformerSearchDialog->resize(338, 400);
        vboxLayout = new QVBoxLayout(ConformerSearchDialog);
        vboxLayout->setObjectName(QString::fromUtf8("vboxLayout"));
        systematicOptionsGroupBox = new QGroupBox(ConformerSearchDialog);
        systematicOptionsGroupBox->setObjectName(QString::fromUtf8("systematicOptionsGroupBox"));
        formLayout = new QFormLayout(systematicOptionsGroupBox);
        formLayout->setObjectName(QString::fromUtf8("formLayout"));
        label = new QLabel(systematicOptionsGroupBox);
        label->setObjectName(QString::fromUtf8("label"));

        formLayout->setWidget(0, QFormLayout::LabelRole, label);

        numSpin = new QSpinBox(systematicOptionsGroupBox);
        numSpin->setObjectName(QString::fromUtf8("numSpin"));
        numSpin->setMaximum(10000);

        formLayout->setWidget(0, QFormLayout::FieldRole, numSpin);

        systematicRadio = new QRadioButton(systematicOptionsGroupBox);
        systematicRadio->setObjectName(QString::fromUtf8("systematicRadio"));

        formLayout->setWidget(2, QFormLayout::SpanningRole, systematicRadio);

        randomRadio = new QRadioButton(systematicOptionsGroupBox);
        randomRadio->setObjectName(QString::fromUtf8("randomRadio"));

        formLayout->setWidget(3, QFormLayout::SpanningRole, randomRadio);

        weightedRadio = new QRadioButton(systematicOptionsGroupBox);
        weightedRadio->setObjectName(QString::fromUtf8("weightedRadio"));

        formLayout->setWidget(4, QFormLayout::SpanningRole, weightedRadio);

        geneticRadio = new QRadioButton(systematicOptionsGroupBox);
        geneticRadio->setObjectName(QString::fromUtf8("geneticRadio"));

        formLayout->setWidget(5, QFormLayout::SpanningRole, geneticRadio);

        optimizationStepsLabel = new QLabel(systematicOptionsGroupBox);
        optimizationStepsLabel->setObjectName(QString::fromUtf8("optimizationStepsLabel"));

        formLayout->setWidget(1, QFormLayout::LabelRole, optimizationStepsLabel);

        optimizationStepsSpinBox = new QSpinBox(systematicOptionsGroupBox);
        optimizationStepsSpinBox->setObjectName(QString::fromUtf8("optimizationStepsSpinBox"));
        optimizationStepsSpinBox->setMinimum(5);
        optimizationStepsSpinBox->setMaximum(250);
        optimizationStepsSpinBox->setValue(25);

        formLayout->setWidget(1, QFormLayout::FieldRole, optimizationStepsSpinBox);


        vboxLayout->addWidget(systematicOptionsGroupBox);

        geneticGroupBox = new QGroupBox(ConformerSearchDialog);
        geneticGroupBox->setObjectName(QString::fromUtf8("geneticGroupBox"));
        verticalLayout = new QVBoxLayout(geneticGroupBox);
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        formLayout_2 = new QFormLayout();
        formLayout_2->setObjectName(QString::fromUtf8("formLayout_2"));
        label_2 = new QLabel(geneticGroupBox);
        label_2->setObjectName(QString::fromUtf8("label_2"));

        formLayout_2->setWidget(0, QFormLayout::LabelRole, label_2);

        childrenSpinBox = new QSpinBox(geneticGroupBox);
        childrenSpinBox->setObjectName(QString::fromUtf8("childrenSpinBox"));
        childrenSpinBox->setMinimum(1);
        childrenSpinBox->setMaximum(9999);
        childrenSpinBox->setValue(5);

        formLayout_2->setWidget(0, QFormLayout::FieldRole, childrenSpinBox);

        label_3 = new QLabel(geneticGroupBox);
        label_3->setObjectName(QString::fromUtf8("label_3"));

        formLayout_2->setWidget(1, QFormLayout::LabelRole, label_3);

        mutabilitySpinBox = new QSpinBox(geneticGroupBox);
        mutabilitySpinBox->setObjectName(QString::fromUtf8("mutabilitySpinBox"));
        mutabilitySpinBox->setMinimum(1);
        mutabilitySpinBox->setMaximum(9999);
        mutabilitySpinBox->setValue(5);

        formLayout_2->setWidget(1, QFormLayout::FieldRole, mutabilitySpinBox);

        label_4 = new QLabel(geneticGroupBox);
        label_4->setObjectName(QString::fromUtf8("label_4"));

        formLayout_2->setWidget(2, QFormLayout::LabelRole, label_4);

        convergenceSpinBox = new QSpinBox(geneticGroupBox);
        convergenceSpinBox->setObjectName(QString::fromUtf8("convergenceSpinBox"));
        convergenceSpinBox->setMinimum(2);
        convergenceSpinBox->setMaximum(999);
        convergenceSpinBox->setValue(25);

        formLayout_2->setWidget(2, QFormLayout::FieldRole, convergenceSpinBox);

        label_5 = new QLabel(geneticGroupBox);
        label_5->setObjectName(QString::fromUtf8("label_5"));

        formLayout_2->setWidget(3, QFormLayout::LabelRole, label_5);

        scoringComboBox = new QComboBox(geneticGroupBox);
        scoringComboBox->addItem(QString());
        scoringComboBox->addItem(QString());
        scoringComboBox->setObjectName(QString::fromUtf8("scoringComboBox"));

        formLayout_2->setWidget(3, QFormLayout::FieldRole, scoringComboBox);


        verticalLayout->addLayout(formLayout_2);


        vboxLayout->addWidget(geneticGroupBox);

        buttonBox = new QDialogButtonBox(ConformerSearchDialog);
        buttonBox->setObjectName(QString::fromUtf8("buttonBox"));
        buttonBox->setOrientation(Qt::Horizontal);
        buttonBox->setStandardButtons(QDialogButtonBox::Cancel|QDialogButtonBox::Ok);

        vboxLayout->addWidget(buttonBox);


        retranslateUi(ConformerSearchDialog);
        QObject::connect(buttonBox, SIGNAL(accepted()), ConformerSearchDialog, SLOT(accept()));
        QObject::connect(buttonBox, SIGNAL(rejected()), ConformerSearchDialog, SLOT(reject()));

        QMetaObject::connectSlotsByName(ConformerSearchDialog);
    } // setupUi

    void retranslateUi(QDialog *ConformerSearchDialog)
    {
        ConformerSearchDialog->setWindowTitle(QCoreApplication::translate("ConformerSearchDialog", "Conformer Search", nullptr));
        systematicOptionsGroupBox->setTitle(QCoreApplication::translate("ConformerSearchDialog", "Method", nullptr));
        label->setText(QCoreApplication::translate("ConformerSearchDialog", "Number of conformers:", nullptr));
        systematicRadio->setText(QCoreApplication::translate("ConformerSearchDialog", "Systematic rotor search", nullptr));
        randomRadio->setText(QCoreApplication::translate("ConformerSearchDialog", "Random rotor search", nullptr));
        weightedRadio->setText(QCoreApplication::translate("ConformerSearchDialog", "Weighted rotor search", nullptr));
        geneticRadio->setText(QCoreApplication::translate("ConformerSearchDialog", "Genetic algorithm search", nullptr));
        optimizationStepsLabel->setText(QCoreApplication::translate("ConformerSearchDialog", "Optimization per conformer:", nullptr));
        optimizationStepsSpinBox->setSuffix(QCoreApplication::translate("ConformerSearchDialog", " steps", nullptr));
        geneticGroupBox->setTitle(QCoreApplication::translate("ConformerSearchDialog", "Genetic Algorithm Options", nullptr));
#if QT_CONFIG(tooltip)
        label_2->setToolTip(QCoreApplication::translate("ConformerSearchDialog", "number of children for each parent geometry", nullptr));
#endif // QT_CONFIG(tooltip)
        label_2->setText(QCoreApplication::translate("ConformerSearchDialog", "Children:", nullptr));
#if QT_CONFIG(tooltip)
        childrenSpinBox->setToolTip(QCoreApplication::translate("ConformerSearchDialog", "number of children for each parent geometry", nullptr));
#endif // QT_CONFIG(tooltip)
#if QT_CONFIG(tooltip)
        label_3->setToolTip(QCoreApplication::translate("ConformerSearchDialog", "mutation frequency (lower = more frequent mutations)", nullptr));
#endif // QT_CONFIG(tooltip)
        label_3->setText(QCoreApplication::translate("ConformerSearchDialog", "Mutability:", nullptr));
#if QT_CONFIG(tooltip)
        mutabilitySpinBox->setToolTip(QCoreApplication::translate("ConformerSearchDialog", "mutation frequency (lower = more frequent mutations)", nullptr));
#endif // QT_CONFIG(tooltip)
#if QT_CONFIG(tooltip)
        label_4->setToolTip(QCoreApplication::translate("ConformerSearchDialog", "number of identical generations before convergence is reached", nullptr));
#endif // QT_CONFIG(tooltip)
        label_4->setText(QCoreApplication::translate("ConformerSearchDialog", "Convergence:", nullptr));
#if QT_CONFIG(tooltip)
        convergenceSpinBox->setToolTip(QCoreApplication::translate("ConformerSearchDialog", "number of identical generations before convergence is reached", nullptr));
#endif // QT_CONFIG(tooltip)
        label_5->setText(QCoreApplication::translate("ConformerSearchDialog", "Scoring method:", nullptr));
        scoringComboBox->setItemText(0, QCoreApplication::translate("ConformerSearchDialog", "RMSD", nullptr));
        scoringComboBox->setItemText(1, QCoreApplication::translate("ConformerSearchDialog", "Energy", nullptr));

#if QT_CONFIG(tooltip)
        scoringComboBox->setToolTip(QCoreApplication::translate("ConformerSearchDialog", "scoring method for the genetic algorithm (RMSD = geometric distance, energy = lowest energies)", nullptr));
#endif // QT_CONFIG(tooltip)
    } // retranslateUi

};

namespace Ui {
    class ConformerSearchDialog: public Ui_ConformerSearchDialog {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_CONFORMERSEARCHDIALOG_H
