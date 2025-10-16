/********************************************************************************
** Form generated from reading UI file 'lammpsinputdialog.ui'
**
** Created by: Qt User Interface Compiler version 5.15.17
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_LAMMPSINPUTDIALOG_H
#define UI_LAMMPSINPUTDIALOG_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QDialog>
#include <QtWidgets/QDoubleSpinBox>
#include <QtWidgets/QFrame>
#include <QtWidgets/QGridLayout>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QSpinBox>
#include <QtWidgets/QTabWidget>
#include <QtWidgets/QVBoxLayout>

QT_BEGIN_NAMESPACE

class Ui_LammpsInputDialog
{
public:
    QVBoxLayout *verticalLayout;
    QGridLayout *gridLayout;
    QLabel *label_7;
    QLineEdit *titleLine;
    QLabel *label_12;
    QLineEdit *baseNameEdit;
    QLabel *label_units;
    QComboBox *unitsCombo;
    QLabel *label_waterPotential;
    QComboBox *waterPotentialCombo;
    QFrame *line_2;
    QLabel *label_atomstyle;
    QComboBox *atomStyleCombo;
    QLabel *label_readdata;
    QLineEdit *readDataLine;
    QLabel *label_therm;
    QComboBox *ensembleCombo;
    QLabel *label_temp;
    QDoubleSpinBox *tempSpin;
    QLabel *label;
    QSpinBox *nhChainSpin;
    QSpacerItem *horizontalSpacer_3;
    QFrame *line_3;
    QLabel *label_2;
    QDoubleSpinBox *stepSpin;
    QLabel *label_4;
    QFrame *line_4;
    QLabel *label_dimension;
    QComboBox *zBoundaryCombo;
    QComboBox *yBoundaryCombo;
    QComboBox *xBoundaryCombo;
    QLabel *label_boundary;
    QSpacerItem *horizontalSpacer_4;
    QLabel *label_5;
    QSpacerItem *horizontalSpacer_5;
    QSpinBox *xReplicateSpin;
    QSpinBox *yReplicateSpin;
    QSpinBox *zReplicateSpin;
    QLineEdit *dumpXYZEdit;
    QLabel *label_3;
    QSpinBox *runSpin;
    QSpacerItem *horizontalSpacer_6;
    QLabel *label_6;
    QSpinBox *dumpStepSpin;
    QSpacerItem *horizontalSpacer_7;
    QLabel *label_8;
    QComboBox *velocityDistCombo;
    QLabel *label_9;
    QDoubleSpinBox *velocityTempSpin;
    QCheckBox *zeroMOMCheck;
    QCheckBox *zeroLCheck;
    QSpacerItem *horizontalSpacer_8;
    QLabel *label_10;
    QLabel *label_11;
    QSpinBox *thermoSpin;
    QSpacerItem *horizontalSpacer_9;
    QComboBox *dimensionCombo;
    QComboBox *thermoStyleCombo;
    QHBoxLayout *horizontalLayout_10;
    QSpacerItem *horizontalSpacer_2;
    QTabWidget *tabWidget;
    QHBoxLayout *horizontalLayout_3;
    QPushButton *resetButton;
    QPushButton *enableFormButton;
    QSpacerItem *horizontalSpacer;
    QPushButton *generateButton;
    QPushButton *closeButton;

    void setupUi(QDialog *LammpsInputDialog)
    {
        if (LammpsInputDialog->objectName().isEmpty())
            LammpsInputDialog->setObjectName(QString::fromUtf8("LammpsInputDialog"));
        LammpsInputDialog->resize(774, 697);
        QSizePolicy sizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
        sizePolicy.setHorizontalStretch(0);
        sizePolicy.setVerticalStretch(0);
        sizePolicy.setHeightForWidth(LammpsInputDialog->sizePolicy().hasHeightForWidth());
        LammpsInputDialog->setSizePolicy(sizePolicy);
        LammpsInputDialog->setSizeGripEnabled(true);
        verticalLayout = new QVBoxLayout(LammpsInputDialog);
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        verticalLayout->setSizeConstraint(QLayout::SetNoConstraint);
        gridLayout = new QGridLayout();
        gridLayout->setObjectName(QString::fromUtf8("gridLayout"));
        gridLayout->setSizeConstraint(QLayout::SetDefaultConstraint);
        label_7 = new QLabel(LammpsInputDialog);
        label_7->setObjectName(QString::fromUtf8("label_7"));

        gridLayout->addWidget(label_7, 0, 0, 1, 1);

        titleLine = new QLineEdit(LammpsInputDialog);
        titleLine->setObjectName(QString::fromUtf8("titleLine"));

        gridLayout->addWidget(titleLine, 0, 1, 1, 7);

        label_12 = new QLabel(LammpsInputDialog);
        label_12->setObjectName(QString::fromUtf8("label_12"));

        gridLayout->addWidget(label_12, 1, 0, 1, 1);

        baseNameEdit = new QLineEdit(LammpsInputDialog);
        baseNameEdit->setObjectName(QString::fromUtf8("baseNameEdit"));

        gridLayout->addWidget(baseNameEdit, 1, 1, 1, 1);

        label_units = new QLabel(LammpsInputDialog);
        label_units->setObjectName(QString::fromUtf8("label_units"));

        gridLayout->addWidget(label_units, 2, 0, 1, 1);

        unitsCombo = new QComboBox(LammpsInputDialog);
        unitsCombo->addItem(QString());
        unitsCombo->addItem(QString());
        unitsCombo->addItem(QString());
        unitsCombo->addItem(QString());
        unitsCombo->addItem(QString());
        unitsCombo->addItem(QString());
        unitsCombo->setObjectName(QString::fromUtf8("unitsCombo"));

        gridLayout->addWidget(unitsCombo, 2, 1, 1, 1);

        label_waterPotential = new QLabel(LammpsInputDialog);
        label_waterPotential->setObjectName(QString::fromUtf8("label_waterPotential"));

        gridLayout->addWidget(label_waterPotential, 5, 0, 1, 1);

        waterPotentialCombo = new QComboBox(LammpsInputDialog);
        waterPotentialCombo->addItem(QString());
        waterPotentialCombo->addItem(QString());
        waterPotentialCombo->addItem(QString());
        waterPotentialCombo->setObjectName(QString::fromUtf8("waterPotentialCombo"));

        gridLayout->addWidget(waterPotentialCombo, 5, 1, 1, 1);

        line_2 = new QFrame(LammpsInputDialog);
        line_2->setObjectName(QString::fromUtf8("line_2"));
        line_2->setFrameShape(QFrame::HLine);
        line_2->setFrameShadow(QFrame::Sunken);

        gridLayout->addWidget(line_2, 4, 0, 1, 8);

        label_atomstyle = new QLabel(LammpsInputDialog);
        label_atomstyle->setObjectName(QString::fromUtf8("label_atomstyle"));

        gridLayout->addWidget(label_atomstyle, 6, 0, 1, 1);

        atomStyleCombo = new QComboBox(LammpsInputDialog);
        atomStyleCombo->addItem(QString());
        atomStyleCombo->addItem(QString());
        atomStyleCombo->addItem(QString());
        atomStyleCombo->addItem(QString());
        atomStyleCombo->addItem(QString());
        atomStyleCombo->addItem(QString());
        atomStyleCombo->addItem(QString());
        atomStyleCombo->addItem(QString());
        atomStyleCombo->addItem(QString());
        atomStyleCombo->addItem(QString());
        atomStyleCombo->addItem(QString());
        atomStyleCombo->addItem(QString());
        atomStyleCombo->addItem(QString());
        atomStyleCombo->addItem(QString());
        atomStyleCombo->addItem(QString());
        atomStyleCombo->setObjectName(QString::fromUtf8("atomStyleCombo"));

        gridLayout->addWidget(atomStyleCombo, 6, 1, 1, 1);

        label_readdata = new QLabel(LammpsInputDialog);
        label_readdata->setObjectName(QString::fromUtf8("label_readdata"));

        gridLayout->addWidget(label_readdata, 6, 2, 1, 2);

        readDataLine = new QLineEdit(LammpsInputDialog);
        readDataLine->setObjectName(QString::fromUtf8("readDataLine"));

        gridLayout->addWidget(readDataLine, 6, 4, 1, 4);

        label_therm = new QLabel(LammpsInputDialog);
        label_therm->setObjectName(QString::fromUtf8("label_therm"));

        gridLayout->addWidget(label_therm, 8, 0, 1, 1);

        ensembleCombo = new QComboBox(LammpsInputDialog);
        ensembleCombo->addItem(QString());
        ensembleCombo->addItem(QString());
        ensembleCombo->setObjectName(QString::fromUtf8("ensembleCombo"));

        gridLayout->addWidget(ensembleCombo, 8, 1, 1, 1);

        label_temp = new QLabel(LammpsInputDialog);
        label_temp->setObjectName(QString::fromUtf8("label_temp"));

        gridLayout->addWidget(label_temp, 8, 2, 1, 1);

        tempSpin = new QDoubleSpinBox(LammpsInputDialog);
        tempSpin->setObjectName(QString::fromUtf8("tempSpin"));
        tempSpin->setDecimals(2);
        tempSpin->setMaximum(20000.000000000000000);
        tempSpin->setValue(298.149999999999977);

        gridLayout->addWidget(tempSpin, 8, 3, 1, 1);

        label = new QLabel(LammpsInputDialog);
        label->setObjectName(QString::fromUtf8("label"));

        gridLayout->addWidget(label, 8, 4, 1, 1);

        nhChainSpin = new QSpinBox(LammpsInputDialog);
        nhChainSpin->setObjectName(QString::fromUtf8("nhChainSpin"));
        nhChainSpin->setMinimum(0);
        nhChainSpin->setValue(1);

        gridLayout->addWidget(nhChainSpin, 8, 5, 1, 1);

        horizontalSpacer_3 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        gridLayout->addItem(horizontalSpacer_3, 5, 2, 1, 6);

        line_3 = new QFrame(LammpsInputDialog);
        line_3->setObjectName(QString::fromUtf8("line_3"));
        line_3->setLineWidth(1);
        line_3->setFrameShape(QFrame::HLine);
        line_3->setFrameShadow(QFrame::Sunken);

        gridLayout->addWidget(line_3, 7, 0, 1, 8);

        label_2 = new QLabel(LammpsInputDialog);
        label_2->setObjectName(QString::fromUtf8("label_2"));

        gridLayout->addWidget(label_2, 10, 0, 1, 1);

        stepSpin = new QDoubleSpinBox(LammpsInputDialog);
        stepSpin->setObjectName(QString::fromUtf8("stepSpin"));
        stepSpin->setSingleStep(0.500000000000000);
        stepSpin->setValue(2.000000000000000);

        gridLayout->addWidget(stepSpin, 10, 1, 1, 1);

        label_4 = new QLabel(LammpsInputDialog);
        label_4->setObjectName(QString::fromUtf8("label_4"));

        gridLayout->addWidget(label_4, 13, 0, 1, 1);

        line_4 = new QFrame(LammpsInputDialog);
        line_4->setObjectName(QString::fromUtf8("line_4"));
        line_4->setFrameShape(QFrame::HLine);
        line_4->setFrameShadow(QFrame::Sunken);

        gridLayout->addWidget(line_4, 11, 0, 1, 8);

        label_dimension = new QLabel(LammpsInputDialog);
        label_dimension->setObjectName(QString::fromUtf8("label_dimension"));

        gridLayout->addWidget(label_dimension, 3, 0, 1, 1);

        zBoundaryCombo = new QComboBox(LammpsInputDialog);
        zBoundaryCombo->addItem(QString());
        zBoundaryCombo->addItem(QString());
        zBoundaryCombo->addItem(QString());
        zBoundaryCombo->addItem(QString());
        zBoundaryCombo->addItem(QString());
        zBoundaryCombo->addItem(QString());
        zBoundaryCombo->setObjectName(QString::fromUtf8("zBoundaryCombo"));

        gridLayout->addWidget(zBoundaryCombo, 3, 7, 1, 1);

        yBoundaryCombo = new QComboBox(LammpsInputDialog);
        yBoundaryCombo->addItem(QString());
        yBoundaryCombo->addItem(QString());
        yBoundaryCombo->addItem(QString());
        yBoundaryCombo->addItem(QString());
        yBoundaryCombo->addItem(QString());
        yBoundaryCombo->addItem(QString());
        yBoundaryCombo->setObjectName(QString::fromUtf8("yBoundaryCombo"));

        gridLayout->addWidget(yBoundaryCombo, 3, 6, 1, 1);

        xBoundaryCombo = new QComboBox(LammpsInputDialog);
        xBoundaryCombo->addItem(QString());
        xBoundaryCombo->addItem(QString());
        xBoundaryCombo->addItem(QString());
        xBoundaryCombo->addItem(QString());
        xBoundaryCombo->addItem(QString());
        xBoundaryCombo->addItem(QString());
        xBoundaryCombo->setObjectName(QString::fromUtf8("xBoundaryCombo"));

        gridLayout->addWidget(xBoundaryCombo, 3, 5, 1, 1);

        label_boundary = new QLabel(LammpsInputDialog);
        label_boundary->setObjectName(QString::fromUtf8("label_boundary"));

        gridLayout->addWidget(label_boundary, 3, 4, 1, 1);

        horizontalSpacer_4 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        gridLayout->addItem(horizontalSpacer_4, 3, 2, 1, 2);

        label_5 = new QLabel(LammpsInputDialog);
        label_5->setObjectName(QString::fromUtf8("label_5"));

        gridLayout->addWidget(label_5, 2, 4, 1, 1);

        horizontalSpacer_5 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        gridLayout->addItem(horizontalSpacer_5, 2, 2, 1, 2);

        xReplicateSpin = new QSpinBox(LammpsInputDialog);
        xReplicateSpin->setObjectName(QString::fromUtf8("xReplicateSpin"));
        xReplicateSpin->setMinimum(1);

        gridLayout->addWidget(xReplicateSpin, 2, 5, 1, 1);

        yReplicateSpin = new QSpinBox(LammpsInputDialog);
        yReplicateSpin->setObjectName(QString::fromUtf8("yReplicateSpin"));
        yReplicateSpin->setMinimum(1);

        gridLayout->addWidget(yReplicateSpin, 2, 6, 1, 1);

        zReplicateSpin = new QSpinBox(LammpsInputDialog);
        zReplicateSpin->setObjectName(QString::fromUtf8("zReplicateSpin"));
        zReplicateSpin->setMinimum(1);

        gridLayout->addWidget(zReplicateSpin, 2, 7, 1, 1);

        dumpXYZEdit = new QLineEdit(LammpsInputDialog);
        dumpXYZEdit->setObjectName(QString::fromUtf8("dumpXYZEdit"));

        gridLayout->addWidget(dumpXYZEdit, 13, 1, 1, 3);

        label_3 = new QLabel(LammpsInputDialog);
        label_3->setObjectName(QString::fromUtf8("label_3"));

        gridLayout->addWidget(label_3, 10, 2, 1, 1);

        runSpin = new QSpinBox(LammpsInputDialog);
        runSpin->setObjectName(QString::fromUtf8("runSpin"));
        runSpin->setMaximum(1000000000);
        runSpin->setValue(50);

        gridLayout->addWidget(runSpin, 10, 3, 1, 1);

        horizontalSpacer_6 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        gridLayout->addItem(horizontalSpacer_6, 10, 4, 1, 4);

        label_6 = new QLabel(LammpsInputDialog);
        label_6->setObjectName(QString::fromUtf8("label_6"));

        gridLayout->addWidget(label_6, 13, 4, 1, 1);

        dumpStepSpin = new QSpinBox(LammpsInputDialog);
        dumpStepSpin->setObjectName(QString::fromUtf8("dumpStepSpin"));
        dumpStepSpin->setMaximum(10000);
        dumpStepSpin->setValue(1);

        gridLayout->addWidget(dumpStepSpin, 13, 5, 1, 1);

        horizontalSpacer_7 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        gridLayout->addItem(horizontalSpacer_7, 13, 6, 1, 2);

        label_8 = new QLabel(LammpsInputDialog);
        label_8->setObjectName(QString::fromUtf8("label_8"));

        gridLayout->addWidget(label_8, 9, 0, 1, 1);

        velocityDistCombo = new QComboBox(LammpsInputDialog);
        velocityDistCombo->addItem(QString());
        velocityDistCombo->addItem(QString());
        velocityDistCombo->setObjectName(QString::fromUtf8("velocityDistCombo"));

        gridLayout->addWidget(velocityDistCombo, 9, 1, 1, 1);

        label_9 = new QLabel(LammpsInputDialog);
        label_9->setObjectName(QString::fromUtf8("label_9"));

        gridLayout->addWidget(label_9, 9, 2, 1, 1);

        velocityTempSpin = new QDoubleSpinBox(LammpsInputDialog);
        velocityTempSpin->setObjectName(QString::fromUtf8("velocityTempSpin"));
        velocityTempSpin->setMaximum(20000.000000000000000);
        velocityTempSpin->setSingleStep(0.500000000000000);
        velocityTempSpin->setValue(298.149999999999977);

        gridLayout->addWidget(velocityTempSpin, 9, 3, 1, 1);

        zeroMOMCheck = new QCheckBox(LammpsInputDialog);
        zeroMOMCheck->setObjectName(QString::fromUtf8("zeroMOMCheck"));
        zeroMOMCheck->setChecked(true);

        gridLayout->addWidget(zeroMOMCheck, 9, 4, 1, 2);

        zeroLCheck = new QCheckBox(LammpsInputDialog);
        zeroLCheck->setObjectName(QString::fromUtf8("zeroLCheck"));
        zeroLCheck->setChecked(true);

        gridLayout->addWidget(zeroLCheck, 9, 6, 1, 2);

        horizontalSpacer_8 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        gridLayout->addItem(horizontalSpacer_8, 8, 6, 1, 2);

        label_10 = new QLabel(LammpsInputDialog);
        label_10->setObjectName(QString::fromUtf8("label_10"));

        gridLayout->addWidget(label_10, 12, 0, 1, 1);

        label_11 = new QLabel(LammpsInputDialog);
        label_11->setObjectName(QString::fromUtf8("label_11"));

        gridLayout->addWidget(label_11, 12, 2, 1, 1);

        thermoSpin = new QSpinBox(LammpsInputDialog);
        thermoSpin->setObjectName(QString::fromUtf8("thermoSpin"));
        thermoSpin->setMaximum(10000);
        thermoSpin->setValue(50);

        gridLayout->addWidget(thermoSpin, 12, 3, 1, 1);

        horizontalSpacer_9 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        gridLayout->addItem(horizontalSpacer_9, 12, 4, 1, 4);

        dimensionCombo = new QComboBox(LammpsInputDialog);
        dimensionCombo->addItem(QString());
        dimensionCombo->addItem(QString());
        dimensionCombo->setObjectName(QString::fromUtf8("dimensionCombo"));

        gridLayout->addWidget(dimensionCombo, 3, 1, 1, 1);

        thermoStyleCombo = new QComboBox(LammpsInputDialog);
        thermoStyleCombo->addItem(QString());
        thermoStyleCombo->addItem(QString());
        thermoStyleCombo->setObjectName(QString::fromUtf8("thermoStyleCombo"));

        gridLayout->addWidget(thermoStyleCombo, 12, 1, 1, 1);


        verticalLayout->addLayout(gridLayout);

        horizontalLayout_10 = new QHBoxLayout();
        horizontalLayout_10->setObjectName(QString::fromUtf8("horizontalLayout_10"));
        horizontalSpacer_2 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_10->addItem(horizontalSpacer_2);


        verticalLayout->addLayout(horizontalLayout_10);

        tabWidget = new QTabWidget(LammpsInputDialog);
        tabWidget->setObjectName(QString::fromUtf8("tabWidget"));
        sizePolicy.setHeightForWidth(tabWidget->sizePolicy().hasHeightForWidth());
        tabWidget->setSizePolicy(sizePolicy);

        verticalLayout->addWidget(tabWidget);

        horizontalLayout_3 = new QHBoxLayout();
        horizontalLayout_3->setObjectName(QString::fromUtf8("horizontalLayout_3"));
        horizontalLayout_3->setSizeConstraint(QLayout::SetFixedSize);
        resetButton = new QPushButton(LammpsInputDialog);
        resetButton->setObjectName(QString::fromUtf8("resetButton"));

        horizontalLayout_3->addWidget(resetButton);

        enableFormButton = new QPushButton(LammpsInputDialog);
        enableFormButton->setObjectName(QString::fromUtf8("enableFormButton"));
        enableFormButton->setEnabled(false);

        horizontalLayout_3->addWidget(enableFormButton);

        horizontalSpacer = new QSpacerItem(48, 26, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_3->addItem(horizontalSpacer);

        generateButton = new QPushButton(LammpsInputDialog);
        generateButton->setObjectName(QString::fromUtf8("generateButton"));

        horizontalLayout_3->addWidget(generateButton);

        closeButton = new QPushButton(LammpsInputDialog);
        closeButton->setObjectName(QString::fromUtf8("closeButton"));

        horizontalLayout_3->addWidget(closeButton);


        verticalLayout->addLayout(horizontalLayout_3);

#if QT_CONFIG(shortcut)
        label_7->setBuddy(titleLine);
        label_units->setBuddy(unitsCombo);
        label_atomstyle->setBuddy(atomStyleCombo);
        label_dimension->setBuddy(dimensionCombo);
#endif // QT_CONFIG(shortcut)
        QWidget::setTabOrder(titleLine, generateButton);
        QWidget::setTabOrder(generateButton, closeButton);
        QWidget::setTabOrder(closeButton, resetButton);
        QWidget::setTabOrder(resetButton, enableFormButton);

        retranslateUi(LammpsInputDialog);
        QObject::connect(closeButton, SIGNAL(clicked()), LammpsInputDialog, SLOT(close()));

        unitsCombo->setCurrentIndex(1);
        atomStyleCombo->setCurrentIndex(7);
        zBoundaryCombo->setCurrentIndex(0);
        yBoundaryCombo->setCurrentIndex(0);
        xBoundaryCombo->setCurrentIndex(0);
        dimensionCombo->setCurrentIndex(1);


        QMetaObject::connectSlotsByName(LammpsInputDialog);
    } // setupUi

    void retranslateUi(QDialog *LammpsInputDialog)
    {
        LammpsInputDialog->setWindowTitle(QCoreApplication::translate("LammpsInputDialog", "LAMMPS Input", nullptr));
#if QT_CONFIG(tooltip)
        label_7->setToolTip(QCoreApplication::translate("LammpsInputDialog", "Input file comments", nullptr));
#endif // QT_CONFIG(tooltip)
        label_7->setText(QCoreApplication::translate("LammpsInputDialog", "Title:", nullptr));
#if QT_CONFIG(tooltip)
        titleLine->setToolTip(QCoreApplication::translate("LammpsInputDialog", "Input file comments", nullptr));
#endif // QT_CONFIG(tooltip)
        titleLine->setText(QCoreApplication::translate("LammpsInputDialog", "Title", nullptr));
        label_12->setText(QCoreApplication::translate("LammpsInputDialog", "Filename Base:", nullptr));
        baseNameEdit->setText(QString());
        baseNameEdit->setPlaceholderText(QCoreApplication::translate("LammpsInputDialog", "job", nullptr));
#if QT_CONFIG(tooltip)
        label_units->setToolTip(QCoreApplication::translate("LammpsInputDialog", "Select the unit style to be used during the simulation.", nullptr));
#endif // QT_CONFIG(tooltip)
#if QT_CONFIG(whatsthis)
        label_units->setWhatsThis(QCoreApplication::translate("LammpsInputDialog", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
"<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
"p, li { white-space: pre-wrap; }\n"
"</style></head><body style=\" font-family:'Sans Serif'; font-size:10pt; font-weight:400; font-style:normal;\">\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><a href=\"http://lammps.sandia.gov/doc/units.html\"><span style=\" text-decoration: underline; color:#0057ae;\">http://lammps.sandia.gov/doc/units.html</span></a></p></body></html>", nullptr));
#endif // QT_CONFIG(whatsthis)
        label_units->setText(QCoreApplication::translate("LammpsInputDialog", "Units", nullptr));
        unitsCombo->setItemText(0, QCoreApplication::translate("LammpsInputDialog", "lj", nullptr));
        unitsCombo->setItemText(1, QCoreApplication::translate("LammpsInputDialog", "real", nullptr));
        unitsCombo->setItemText(2, QCoreApplication::translate("LammpsInputDialog", "metal", nullptr));
        unitsCombo->setItemText(3, QCoreApplication::translate("LammpsInputDialog", "si", nullptr));
        unitsCombo->setItemText(4, QCoreApplication::translate("LammpsInputDialog", "cgs", nullptr));
        unitsCombo->setItemText(5, QCoreApplication::translate("LammpsInputDialog", "electron", nullptr));

#if QT_CONFIG(tooltip)
        unitsCombo->setToolTip(QCoreApplication::translate("LammpsInputDialog", "Select the unit style to be used during the simulation.", nullptr));
#endif // QT_CONFIG(tooltip)
#if QT_CONFIG(whatsthis)
        unitsCombo->setWhatsThis(QCoreApplication::translate("LammpsInputDialog", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
"<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
"p, li { white-space: pre-wrap; }\n"
"</style></head><body style=\" font-family:'Sans Serif'; font-size:10pt; font-weight:400; font-style:normal;\">\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><a href=\"http://lammps.sandia.gov/doc/units.html\"><span style=\" text-decoration: underline; color:#0057ae;\">http://lammps.sandia.gov/doc/units.html</span></a></p></body></html>", nullptr));
#endif // QT_CONFIG(whatsthis)
        label_waterPotential->setText(QCoreApplication::translate("LammpsInputDialog", "Water Potential", nullptr));
        waterPotentialCombo->setItemText(0, QCoreApplication::translate("LammpsInputDialog", "NONE", nullptr));
        waterPotentialCombo->setItemText(1, QCoreApplication::translate("LammpsInputDialog", "SPC", nullptr));
        waterPotentialCombo->setItemText(2, QCoreApplication::translate("LammpsInputDialog", "SPC/E", nullptr));

#if QT_CONFIG(tooltip)
        label_atomstyle->setToolTip(QCoreApplication::translate("LammpsInputDialog", "Select atom_style used by the data file.", nullptr));
#endif // QT_CONFIG(tooltip)
#if QT_CONFIG(whatsthis)
        label_atomstyle->setWhatsThis(QCoreApplication::translate("LammpsInputDialog", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
"<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
"p, li { white-space: pre-wrap; }\n"
"</style></head><body style=\" font-family:'Sans Serif'; font-size:10pt; font-weight:400; font-style:normal;\">\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><a href=\"http://lammps.sandia.gov/doc/atom_style.html\"><span style=\" text-decoration: underline; color:#0057ae;\">http://lammps.sandia.gov/doc/atom_style.html</span></a></p></body></html>", nullptr));
#endif // QT_CONFIG(whatsthis)
        label_atomstyle->setText(QCoreApplication::translate("LammpsInputDialog", "Atom Style", nullptr));
        atomStyleCombo->setItemText(0, QCoreApplication::translate("LammpsInputDialog", "angle", nullptr));
        atomStyleCombo->setItemText(1, QCoreApplication::translate("LammpsInputDialog", "atomic", nullptr));
        atomStyleCombo->setItemText(2, QCoreApplication::translate("LammpsInputDialog", "bond", nullptr));
        atomStyleCombo->setItemText(3, QCoreApplication::translate("LammpsInputDialog", "charge", nullptr));
        atomStyleCombo->setItemText(4, QCoreApplication::translate("LammpsInputDialog", "dipole", nullptr));
        atomStyleCombo->setItemText(5, QCoreApplication::translate("LammpsInputDialog", "electron", nullptr));
        atomStyleCombo->setItemText(6, QCoreApplication::translate("LammpsInputDialog", "ellipsoid", nullptr));
        atomStyleCombo->setItemText(7, QCoreApplication::translate("LammpsInputDialog", "full", nullptr));
        atomStyleCombo->setItemText(8, QCoreApplication::translate("LammpsInputDialog", "line", nullptr));
        atomStyleCombo->setItemText(9, QCoreApplication::translate("LammpsInputDialog", "meso", nullptr));
        atomStyleCombo->setItemText(10, QCoreApplication::translate("LammpsInputDialog", "molecular", nullptr));
        atomStyleCombo->setItemText(11, QCoreApplication::translate("LammpsInputDialog", "peri", nullptr));
        atomStyleCombo->setItemText(12, QCoreApplication::translate("LammpsInputDialog", "sphere", nullptr));
        atomStyleCombo->setItemText(13, QCoreApplication::translate("LammpsInputDialog", "tri", nullptr));
        atomStyleCombo->setItemText(14, QCoreApplication::translate("LammpsInputDialog", "wavepacket", nullptr));

#if QT_CONFIG(tooltip)
        atomStyleCombo->setToolTip(QCoreApplication::translate("LammpsInputDialog", "Select atom_style used by the data file.", nullptr));
#endif // QT_CONFIG(tooltip)
#if QT_CONFIG(whatsthis)
        atomStyleCombo->setWhatsThis(QCoreApplication::translate("LammpsInputDialog", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
"<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
"p, li { white-space: pre-wrap; }\n"
"</style></head><body style=\" font-family:'Sans Serif'; font-size:10pt; font-weight:400; font-style:normal;\">\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><a href=\"http://lammps.sandia.gov/doc/atom_style.html\"><span style=\" text-decoration: underline; color:#0057ae;\">http://lammps.sandia.gov/doc/atom_style.html</span></a></p></body></html>", nullptr));
#endif // QT_CONFIG(whatsthis)
#if QT_CONFIG(tooltip)
        label_readdata->setToolTip(QCoreApplication::translate("LammpsInputDialog", "Specify the name to be used for the coordinate file.", nullptr));
#endif // QT_CONFIG(tooltip)
        label_readdata->setText(QCoreApplication::translate("LammpsInputDialog", "Coordinate Data File", nullptr));
#if QT_CONFIG(tooltip)
        readDataLine->setToolTip(QCoreApplication::translate("LammpsInputDialog", "Specify the name to be used for the coordinate file.", nullptr));
#endif // QT_CONFIG(tooltip)
        label_therm->setText(QCoreApplication::translate("LammpsInputDialog", "Ensemble", nullptr));
        ensembleCombo->setItemText(0, QCoreApplication::translate("LammpsInputDialog", "NVT", nullptr));
        ensembleCombo->setItemText(1, QCoreApplication::translate("LammpsInputDialog", "NVE", nullptr));

        label_temp->setText(QCoreApplication::translate("LammpsInputDialog", "Temperature", nullptr));
#if QT_CONFIG(tooltip)
        label->setToolTip(QCoreApplication::translate("LammpsInputDialog", "Select the number of Nos\303\251-Hoover chains in the NVT ensemble.", nullptr));
#endif // QT_CONFIG(tooltip)
        label->setText(QCoreApplication::translate("LammpsInputDialog", "NH Chains", nullptr));
#if QT_CONFIG(tooltip)
        nhChainSpin->setToolTip(QCoreApplication::translate("LammpsInputDialog", "Select the number of Nos\303\251-Hoover chains in the NVT ensemble.", nullptr));
#endif // QT_CONFIG(tooltip)
#if QT_CONFIG(tooltip)
        label_2->setToolTip(QCoreApplication::translate("LammpsInputDialog", "Time step for the simulation in units according to \"Units\" specification.", nullptr));
#endif // QT_CONFIG(tooltip)
        label_2->setText(QCoreApplication::translate("LammpsInputDialog", "Time Step", nullptr));
#if QT_CONFIG(tooltip)
        stepSpin->setToolTip(QCoreApplication::translate("LammpsInputDialog", "Time step for the simulation in units according to \"Units\" specification.", nullptr));
#endif // QT_CONFIG(tooltip)
#if QT_CONFIG(tooltip)
        label_4->setToolTip(QCoreApplication::translate("LammpsInputDialog", "Filename of the XYZ file to write during the simulation.", nullptr));
#endif // QT_CONFIG(tooltip)
        label_4->setText(QCoreApplication::translate("LammpsInputDialog", "Dump XYZ", nullptr));
#if QT_CONFIG(tooltip)
        label_dimension->setToolTip(QCoreApplication::translate("LammpsInputDialog", "Number of dimensions in the system.", nullptr));
#endif // QT_CONFIG(tooltip)
        label_dimension->setText(QCoreApplication::translate("LammpsInputDialog", "Dimensions", nullptr));
        zBoundaryCombo->setItemText(0, QCoreApplication::translate("LammpsInputDialog", "p", nullptr));
        zBoundaryCombo->setItemText(1, QCoreApplication::translate("LammpsInputDialog", "s", nullptr));
        zBoundaryCombo->setItemText(2, QCoreApplication::translate("LammpsInputDialog", "f", nullptr));
        zBoundaryCombo->setItemText(3, QCoreApplication::translate("LammpsInputDialog", "m", nullptr));
        zBoundaryCombo->setItemText(4, QCoreApplication::translate("LammpsInputDialog", "fs", nullptr));
        zBoundaryCombo->setItemText(5, QCoreApplication::translate("LammpsInputDialog", "fm", nullptr));

#if QT_CONFIG(tooltip)
        zBoundaryCombo->setToolTip(QCoreApplication::translate("LammpsInputDialog", "Change Z boundary style.", nullptr));
#endif // QT_CONFIG(tooltip)
        yBoundaryCombo->setItemText(0, QCoreApplication::translate("LammpsInputDialog", "p", nullptr));
        yBoundaryCombo->setItemText(1, QCoreApplication::translate("LammpsInputDialog", "s", nullptr));
        yBoundaryCombo->setItemText(2, QCoreApplication::translate("LammpsInputDialog", "f", nullptr));
        yBoundaryCombo->setItemText(3, QCoreApplication::translate("LammpsInputDialog", "m", nullptr));
        yBoundaryCombo->setItemText(4, QCoreApplication::translate("LammpsInputDialog", "fs", nullptr));
        yBoundaryCombo->setItemText(5, QCoreApplication::translate("LammpsInputDialog", "fm", nullptr));

#if QT_CONFIG(tooltip)
        yBoundaryCombo->setToolTip(QCoreApplication::translate("LammpsInputDialog", "Change Y boundary style.", nullptr));
#endif // QT_CONFIG(tooltip)
        xBoundaryCombo->setItemText(0, QCoreApplication::translate("LammpsInputDialog", "p", nullptr));
        xBoundaryCombo->setItemText(1, QCoreApplication::translate("LammpsInputDialog", "s", nullptr));
        xBoundaryCombo->setItemText(2, QCoreApplication::translate("LammpsInputDialog", "f", nullptr));
        xBoundaryCombo->setItemText(3, QCoreApplication::translate("LammpsInputDialog", "m", nullptr));
        xBoundaryCombo->setItemText(4, QCoreApplication::translate("LammpsInputDialog", "fs", nullptr));
        xBoundaryCombo->setItemText(5, QCoreApplication::translate("LammpsInputDialog", "fm", nullptr));

#if QT_CONFIG(tooltip)
        xBoundaryCombo->setToolTip(QCoreApplication::translate("LammpsInputDialog", "Change X boundary style.", nullptr));
#endif // QT_CONFIG(tooltip)
#if QT_CONFIG(tooltip)
        label_boundary->setToolTip(QCoreApplication::translate("LammpsInputDialog", "Select boundary Styles in X, Y and Z directions.", nullptr));
#endif // QT_CONFIG(tooltip)
        label_boundary->setText(QCoreApplication::translate("LammpsInputDialog", "Boundary", nullptr));
#if QT_CONFIG(tooltip)
        label_5->setToolTip(QCoreApplication::translate("LammpsInputDialog", "Number of replicants in X, Y and Z directions.", nullptr));
#endif // QT_CONFIG(tooltip)
        label_5->setText(QCoreApplication::translate("LammpsInputDialog", "Replicate", nullptr));
#if QT_CONFIG(tooltip)
        xReplicateSpin->setToolTip(QCoreApplication::translate("LammpsInputDialog", "Replicate the X direction.", nullptr));
#endif // QT_CONFIG(tooltip)
#if QT_CONFIG(tooltip)
        yReplicateSpin->setToolTip(QCoreApplication::translate("LammpsInputDialog", "Replicate the Y direction.", nullptr));
#endif // QT_CONFIG(tooltip)
#if QT_CONFIG(tooltip)
        zReplicateSpin->setToolTip(QCoreApplication::translate("LammpsInputDialog", "Replicate the Z direction.", nullptr));
#endif // QT_CONFIG(tooltip)
#if QT_CONFIG(tooltip)
        dumpXYZEdit->setToolTip(QCoreApplication::translate("LammpsInputDialog", "Filename of the XYZ file to write during the simulation.", nullptr));
#endif // QT_CONFIG(tooltip)
#if QT_CONFIG(tooltip)
        label_3->setToolTip(QCoreApplication::translate("LammpsInputDialog", "Total number of timesteps to run the simulation.", nullptr));
#endif // QT_CONFIG(tooltip)
        label_3->setText(QCoreApplication::translate("LammpsInputDialog", "Total Steps", nullptr));
#if QT_CONFIG(tooltip)
        runSpin->setToolTip(QCoreApplication::translate("LammpsInputDialog", "Total number of timesteps to run the simulation.", nullptr));
#endif // QT_CONFIG(tooltip)
        label_6->setText(QCoreApplication::translate("LammpsInputDialog", "Dump Interval", nullptr));
#if QT_CONFIG(tooltip)
        label_8->setToolTip(QCoreApplication::translate("LammpsInputDialog", "Set the initial atom velocities for the simulation.", nullptr));
#endif // QT_CONFIG(tooltip)
        label_8->setText(QCoreApplication::translate("LammpsInputDialog", "Initial Velocities", nullptr));
        velocityDistCombo->setItemText(0, QCoreApplication::translate("LammpsInputDialog", "gaussian", nullptr));
        velocityDistCombo->setItemText(1, QCoreApplication::translate("LammpsInputDialog", "uniform", nullptr));

#if QT_CONFIG(tooltip)
        velocityDistCombo->setToolTip(QCoreApplication::translate("LammpsInputDialog", "Select the distribution of initial atom velocities.", nullptr));
#endif // QT_CONFIG(tooltip)
#if QT_CONFIG(tooltip)
        label_9->setToolTip(QCoreApplication::translate("LammpsInputDialog", "Set the initial atom velocities to match this temperature.", nullptr));
#endif // QT_CONFIG(tooltip)
        label_9->setText(QCoreApplication::translate("LammpsInputDialog", "Temperature", nullptr));
#if QT_CONFIG(tooltip)
        velocityTempSpin->setToolTip(QCoreApplication::translate("LammpsInputDialog", "Set the initial atom velocities to match this temperature.", nullptr));
#endif // QT_CONFIG(tooltip)
#if QT_CONFIG(tooltip)
        zeroMOMCheck->setToolTip(QCoreApplication::translate("LammpsInputDialog", "Remove system linear momentum from initial velocities.", nullptr));
#endif // QT_CONFIG(tooltip)
        zeroMOMCheck->setText(QCoreApplication::translate("LammpsInputDialog", "Zero Linear Momentum", nullptr));
#if QT_CONFIG(tooltip)
        zeroLCheck->setToolTip(QCoreApplication::translate("LammpsInputDialog", "Remove system angular momentum from initial velocities.", nullptr));
#endif // QT_CONFIG(tooltip)
        zeroLCheck->setText(QCoreApplication::translate("LammpsInputDialog", "Zero Angular Momentum", nullptr));
#if QT_CONFIG(tooltip)
        label_10->setToolTip(QCoreApplication::translate("LammpsInputDialog", "Control the thermodynamic output during the simulation.", nullptr));
#endif // QT_CONFIG(tooltip)
        label_10->setText(QCoreApplication::translate("LammpsInputDialog", "Output", nullptr));
        label_11->setText(QCoreApplication::translate("LammpsInputDialog", "Output Interval", nullptr));
        dimensionCombo->setItemText(0, QCoreApplication::translate("LammpsInputDialog", "2d", nullptr));
        dimensionCombo->setItemText(1, QCoreApplication::translate("LammpsInputDialog", "3d", nullptr));

#if QT_CONFIG(tooltip)
        dimensionCombo->setToolTip(QCoreApplication::translate("LammpsInputDialog", "Number of dimensions in the system.", nullptr));
#endif // QT_CONFIG(tooltip)
        thermoStyleCombo->setItemText(0, QCoreApplication::translate("LammpsInputDialog", "One Line", nullptr));
        thermoStyleCombo->setItemText(1, QCoreApplication::translate("LammpsInputDialog", "Multi Line", nullptr));

#if QT_CONFIG(tooltip)
        thermoStyleCombo->setToolTip(QCoreApplication::translate("LammpsInputDialog", "Thermodynamic output style.", nullptr));
#endif // QT_CONFIG(tooltip)
        resetButton->setText(QCoreApplication::translate("LammpsInputDialog", "Reset", nullptr));
        enableFormButton->setText(QCoreApplication::translate("LammpsInputDialog", "Use Form", nullptr));
        generateButton->setText(QCoreApplication::translate("LammpsInputDialog", "Generate\342\200\246", nullptr));
        closeButton->setText(QCoreApplication::translate("LammpsInputDialog", "Close", nullptr));
    } // retranslateUi

};

namespace Ui {
    class LammpsInputDialog: public Ui_LammpsInputDialog {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_LAMMPSINPUTDIALOG_H
