/********************************************************************************
** Form generated from reading UI file 'obforcefielddialog.ui'
**
** Created by: Qt User Interface Compiler version 5.15.17
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_OBFORCEFIELDDIALOG_H
#define UI_OBFORCEFIELDDIALOG_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QDialog>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QDoubleSpinBox>
#include <QtWidgets/QFormLayout>
#include <QtWidgets/QFrame>
#include <QtWidgets/QGridLayout>
#include <QtWidgets/QGroupBox>
#include <QtWidgets/QLabel>
#include <QtWidgets/QSpinBox>

namespace Avogadro {
namespace QtPlugins {

class Ui_OBForceFieldDialog
{
public:
    QGridLayout *gridLayout;
    QDialogButtonBox *buttonBox;
    QGroupBox *groupBox_2;
    QFormLayout *formLayout;
    QLabel *label;
    QLabel *label_3;
    QLabel *label_4;
    QComboBox *algorithm;
    QComboBox *lineSearch;
    QComboBox *forceField;
    QCheckBox *useRecommended;
    QFrame *line;
    QGroupBox *enableCutoffs;
    QFormLayout *formLayout_2;
    QLabel *label_7;
    QLabel *label_6;
    QLabel *label_8;
    QDoubleSpinBox *vdwCutoff;
    QDoubleSpinBox *eleCutoff;
    QSpinBox *pairFreq;
    QGroupBox *groupBox_3;
    QFormLayout *formLayout_3;
    QLabel *label_2;
    QLabel *label_5;
    QSpinBox *energyConv;
    QSpinBox *stepLimit;

    void setupUi(QDialog *Avogadro__QtPlugins__OBForceFieldDialog)
    {
        if (Avogadro__QtPlugins__OBForceFieldDialog->objectName().isEmpty())
            Avogadro__QtPlugins__OBForceFieldDialog->setObjectName(QString::fromUtf8("Avogadro__QtPlugins__OBForceFieldDialog"));
        Avogadro__QtPlugins__OBForceFieldDialog->resize(327, 388);
        QSizePolicy sizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
        sizePolicy.setHorizontalStretch(0);
        sizePolicy.setVerticalStretch(0);
        sizePolicy.setHeightForWidth(Avogadro__QtPlugins__OBForceFieldDialog->sizePolicy().hasHeightForWidth());
        Avogadro__QtPlugins__OBForceFieldDialog->setSizePolicy(sizePolicy);
        gridLayout = new QGridLayout(Avogadro__QtPlugins__OBForceFieldDialog);
        gridLayout->setObjectName(QString::fromUtf8("gridLayout"));
        gridLayout->setSizeConstraint(QLayout::SetFixedSize);
        buttonBox = new QDialogButtonBox(Avogadro__QtPlugins__OBForceFieldDialog);
        buttonBox->setObjectName(QString::fromUtf8("buttonBox"));
        buttonBox->setOrientation(Qt::Horizontal);
        buttonBox->setStandardButtons(QDialogButtonBox::Cancel|QDialogButtonBox::Ok);

        gridLayout->addWidget(buttonBox, 3, 0, 1, 1);

        groupBox_2 = new QGroupBox(Avogadro__QtPlugins__OBForceFieldDialog);
        groupBox_2->setObjectName(QString::fromUtf8("groupBox_2"));
        formLayout = new QFormLayout(groupBox_2);
        formLayout->setObjectName(QString::fromUtf8("formLayout"));
        label = new QLabel(groupBox_2);
        label->setObjectName(QString::fromUtf8("label"));

        formLayout->setWidget(0, QFormLayout::LabelRole, label);

        label_3 = new QLabel(groupBox_2);
        label_3->setObjectName(QString::fromUtf8("label_3"));

        formLayout->setWidget(3, QFormLayout::LabelRole, label_3);

        label_4 = new QLabel(groupBox_2);
        label_4->setObjectName(QString::fromUtf8("label_4"));

        formLayout->setWidget(4, QFormLayout::LabelRole, label_4);

        algorithm = new QComboBox(groupBox_2);
        algorithm->addItem(QString());
        algorithm->addItem(QString());
        algorithm->setObjectName(QString::fromUtf8("algorithm"));

        formLayout->setWidget(3, QFormLayout::FieldRole, algorithm);

        lineSearch = new QComboBox(groupBox_2);
        lineSearch->addItem(QString());
        lineSearch->addItem(QString());
        lineSearch->setObjectName(QString::fromUtf8("lineSearch"));

        formLayout->setWidget(4, QFormLayout::FieldRole, lineSearch);

        forceField = new QComboBox(groupBox_2);
        forceField->setObjectName(QString::fromUtf8("forceField"));

        formLayout->setWidget(0, QFormLayout::FieldRole, forceField);

        useRecommended = new QCheckBox(groupBox_2);
        useRecommended->setObjectName(QString::fromUtf8("useRecommended"));

        formLayout->setWidget(1, QFormLayout::FieldRole, useRecommended);

        line = new QFrame(groupBox_2);
        line->setObjectName(QString::fromUtf8("line"));
        line->setFrameShape(QFrame::HLine);
        line->setFrameShadow(QFrame::Sunken);

        formLayout->setWidget(2, QFormLayout::SpanningRole, line);


        gridLayout->addWidget(groupBox_2, 0, 0, 1, 1);

        enableCutoffs = new QGroupBox(Avogadro__QtPlugins__OBForceFieldDialog);
        enableCutoffs->setObjectName(QString::fromUtf8("enableCutoffs"));
        enableCutoffs->setCheckable(true);
        enableCutoffs->setChecked(false);
        formLayout_2 = new QFormLayout(enableCutoffs);
        formLayout_2->setObjectName(QString::fromUtf8("formLayout_2"));
        label_7 = new QLabel(enableCutoffs);
        label_7->setObjectName(QString::fromUtf8("label_7"));

        formLayout_2->setWidget(0, QFormLayout::LabelRole, label_7);

        label_6 = new QLabel(enableCutoffs);
        label_6->setObjectName(QString::fromUtf8("label_6"));

        formLayout_2->setWidget(3, QFormLayout::LabelRole, label_6);

        label_8 = new QLabel(enableCutoffs);
        label_8->setObjectName(QString::fromUtf8("label_8"));

        formLayout_2->setWidget(2, QFormLayout::LabelRole, label_8);

        vdwCutoff = new QDoubleSpinBox(enableCutoffs);
        vdwCutoff->setObjectName(QString::fromUtf8("vdwCutoff"));
        vdwCutoff->setMinimum(0.250000000000000);
        vdwCutoff->setMaximum(100.000000000000000);
        vdwCutoff->setSingleStep(0.250000000000000);
        vdwCutoff->setValue(10.000000000000000);

        formLayout_2->setWidget(0, QFormLayout::FieldRole, vdwCutoff);

        eleCutoff = new QDoubleSpinBox(enableCutoffs);
        eleCutoff->setObjectName(QString::fromUtf8("eleCutoff"));
        eleCutoff->setMinimum(0.250000000000000);
        eleCutoff->setMaximum(100.000000000000000);
        eleCutoff->setSingleStep(0.250000000000000);
        eleCutoff->setValue(10.000000000000000);

        formLayout_2->setWidget(2, QFormLayout::FieldRole, eleCutoff);

        pairFreq = new QSpinBox(enableCutoffs);
        pairFreq->setObjectName(QString::fromUtf8("pairFreq"));
        pairFreq->setMinimum(1);
        pairFreq->setMaximum(100);
        pairFreq->setSingleStep(1);
        pairFreq->setValue(10);

        formLayout_2->setWidget(3, QFormLayout::FieldRole, pairFreq);


        gridLayout->addWidget(enableCutoffs, 2, 0, 1, 1);

        groupBox_3 = new QGroupBox(Avogadro__QtPlugins__OBForceFieldDialog);
        groupBox_3->setObjectName(QString::fromUtf8("groupBox_3"));
        formLayout_3 = new QFormLayout(groupBox_3);
        formLayout_3->setObjectName(QString::fromUtf8("formLayout_3"));
        label_2 = new QLabel(groupBox_3);
        label_2->setObjectName(QString::fromUtf8("label_2"));

        formLayout_3->setWidget(0, QFormLayout::LabelRole, label_2);

        label_5 = new QLabel(groupBox_3);
        label_5->setObjectName(QString::fromUtf8("label_5"));

        formLayout_3->setWidget(1, QFormLayout::LabelRole, label_5);

        energyConv = new QSpinBox(groupBox_3);
        energyConv->setObjectName(QString::fromUtf8("energyConv"));
        energyConv->setMinimum(-10);
        energyConv->setMaximum(9);
        energyConv->setValue(-6);

        formLayout_3->setWidget(0, QFormLayout::FieldRole, energyConv);

        stepLimit = new QSpinBox(groupBox_3);
        stepLimit->setObjectName(QString::fromUtf8("stepLimit"));
        stepLimit->setMinimum(0);
        stepLimit->setMaximum(100000);
        stepLimit->setSingleStep(250);
        stepLimit->setValue(2500);

        formLayout_3->setWidget(1, QFormLayout::FieldRole, stepLimit);


        gridLayout->addWidget(groupBox_3, 1, 0, 1, 1);

        QWidget::setTabOrder(forceField, useRecommended);
        QWidget::setTabOrder(useRecommended, algorithm);
        QWidget::setTabOrder(algorithm, lineSearch);
        QWidget::setTabOrder(lineSearch, energyConv);
        QWidget::setTabOrder(energyConv, stepLimit);
        QWidget::setTabOrder(stepLimit, enableCutoffs);
        QWidget::setTabOrder(enableCutoffs, vdwCutoff);
        QWidget::setTabOrder(vdwCutoff, eleCutoff);
        QWidget::setTabOrder(eleCutoff, pairFreq);
        QWidget::setTabOrder(pairFreq, buttonBox);

        retranslateUi(Avogadro__QtPlugins__OBForceFieldDialog);
        QObject::connect(buttonBox, SIGNAL(accepted()), Avogadro__QtPlugins__OBForceFieldDialog, SLOT(accept()));
        QObject::connect(buttonBox, SIGNAL(rejected()), Avogadro__QtPlugins__OBForceFieldDialog, SLOT(reject()));

        QMetaObject::connectSlotsByName(Avogadro__QtPlugins__OBForceFieldDialog);
    } // setupUi

    void retranslateUi(QDialog *Avogadro__QtPlugins__OBForceFieldDialog)
    {
        Avogadro__QtPlugins__OBForceFieldDialog->setWindowTitle(QCoreApplication::translate("Avogadro::QtPlugins::OBForceFieldDialog", "Geometry Optimization Parameters", nullptr));
        groupBox_2->setTitle(QCoreApplication::translate("Avogadro::QtPlugins::OBForceFieldDialog", "Optimization Method", nullptr));
        label->setText(QCoreApplication::translate("Avogadro::QtPlugins::OBForceFieldDialog", "Force field:", nullptr));
        label_3->setText(QCoreApplication::translate("Avogadro::QtPlugins::OBForceFieldDialog", "Optimization algorithm:", nullptr));
        label_4->setText(QCoreApplication::translate("Avogadro::QtPlugins::OBForceFieldDialog", "Line search technique:", nullptr));
        algorithm->setItemText(0, QCoreApplication::translate("Avogadro::QtPlugins::OBForceFieldDialog", "Steepest Descent", nullptr));
        algorithm->setItemText(1, QCoreApplication::translate("Avogadro::QtPlugins::OBForceFieldDialog", "Conjugate Gradient", nullptr));

        lineSearch->setItemText(0, QCoreApplication::translate("Avogadro::QtPlugins::OBForceFieldDialog", "Simple", nullptr));
        lineSearch->setItemText(1, QCoreApplication::translate("Avogadro::QtPlugins::OBForceFieldDialog", "Newton's Method", nullptr));

        useRecommended->setText(QCoreApplication::translate("Avogadro::QtPlugins::OBForceFieldDialog", "Autodetect", nullptr));
        enableCutoffs->setTitle(QCoreApplication::translate("Avogadro::QtPlugins::OBForceFieldDialog", "Limit Non-Bonded Interactions", nullptr));
        label_7->setText(QCoreApplication::translate("Avogadro::QtPlugins::OBForceFieldDialog", "Van der Waals cutoff distance:", nullptr));
        label_6->setText(QCoreApplication::translate("Avogadro::QtPlugins::OBForceFieldDialog", "Pair update frequency:", nullptr));
        label_8->setText(QCoreApplication::translate("Avogadro::QtPlugins::OBForceFieldDialog", "electrostatic cutoff distance:", nullptr));
        vdwCutoff->setSuffix(QCoreApplication::translate("Avogadro::QtPlugins::OBForceFieldDialog", "\303\205", nullptr));
        eleCutoff->setSuffix(QCoreApplication::translate("Avogadro::QtPlugins::OBForceFieldDialog", "\303\205", nullptr));
        pairFreq->setSuffix(QCoreApplication::translate("Avogadro::QtPlugins::OBForceFieldDialog", " steps", nullptr));
        groupBox_3->setTitle(QCoreApplication::translate("Avogadro::QtPlugins::OBForceFieldDialog", "Convergence Criteria", nullptr));
        label_2->setText(QCoreApplication::translate("Avogadro::QtPlugins::OBForceFieldDialog", "\"Energy\" convergence:", nullptr));
        label_5->setText(QCoreApplication::translate("Avogadro::QtPlugins::OBForceFieldDialog", "Step limit:", nullptr));
        energyConv->setSuffix(QCoreApplication::translate("Avogadro::QtPlugins::OBForceFieldDialog", " units", nullptr));
        energyConv->setPrefix(QCoreApplication::translate("Avogadro::QtPlugins::OBForceFieldDialog", "10^", nullptr));
        stepLimit->setSuffix(QCoreApplication::translate("Avogadro::QtPlugins::OBForceFieldDialog", " steps", nullptr));
    } // retranslateUi

};

} // namespace QtPlugins
} // namespace Avogadro

namespace Avogadro {
namespace QtPlugins {
namespace Ui {
    class OBForceFieldDialog: public Ui_OBForceFieldDialog {};
} // namespace Ui
} // namespace QtPlugins
} // namespace Avogadro

#endif // UI_OBFORCEFIELDDIALOG_H
