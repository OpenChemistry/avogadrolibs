/********************************************************************************
** Form generated from reading UI file 'openmminputdialog.ui'
**
** Created by: Qt User Interface Compiler version 5.15.17
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_OPENMMINPUTDIALOG_H
#define UI_OPENMMINPUTDIALOG_H

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

class Ui_OpenMMInputDialog
{
public:
    QVBoxLayout *verticalLayout;
    QGridLayout *gridLayout;
    QLabel *label_jobScript;
    QLineEdit *jobScriptEdit;
    QLabel *label_1;
    QLineEdit *inputCoordEdit;
    QLabel *label_2;
    QLineEdit *inputTopEdit;
    QLabel *label_forceField;
    QComboBox *forceFieldCombo;
    QLabel *label_waterModel;
    QComboBox *waterModelCombo;
    QLabel *label_platform;
    QComboBox *platformCombo;
    QLabel *label_precision;
    QComboBox *precisionCombo;
    QLabel *label_deviceIndex;
    QSpinBox *deviceIndexSpin;
    QLabel *label_openCLIndex;
    QSpinBox *openCLIndexSpin;
    QFrame *line_2;
    QLabel *label_nonbondedMethod;
    QComboBox *nonBondedMethodCombo;
    QLabel *label_ewaldTolerance;
    QDoubleSpinBox *ewaldToleranceSpin;
    QLabel *label_constraints;
    QComboBox *constraintsCombo;
    QLabel *label_constraintTolerance;
    QDoubleSpinBox *constraintToleranceSpin;
    QLabel *label_rigidWater;
    QComboBox *rigidWaterCombo;
    QLabel *label_nonBondedCutoff;
    QDoubleSpinBox *nonBondedCutoffSpin;
    QLabel *label_randomInitVel;
    QComboBox *initVelCombo;
    QLabel *label_generationTemp;
    QDoubleSpinBox *generationTemperatureSpin;
    QFrame *line_3;
    QLabel *label_integrator;
    QComboBox *integratorCombo;
    QLabel *label_timestep;
    QDoubleSpinBox *stepSpin;
    QLabel *label_errorTol;
    QDoubleSpinBox *errorTolSpin;
    QLabel *label_collisionRate;
    QDoubleSpinBox *collisionRateSpin;
    QLabel *label_temperature;
    QDoubleSpinBox *temperatureSpin;
    QLabel *label_barostat;
    QComboBox *barostatCombo;
    QLabel *label_pressure;
    QDoubleSpinBox *pressureSpin;
    QLabel *label_barostatInterval;
    QSpinBox *barostatIntervalSpin;
    QFrame *line_4;
    QLabel *label_reporters;
    QCheckBox *stateDataCheck;
    QCheckBox *dcdCheck;
    QCheckBox *pdbCheck;
    QLabel *label_reportInterval;
    QSpinBox *reportIntervalSpin;
    QLabel *label_equilibriationSteps;
    QSpinBox *equilibriationStepsSpin;
    QLabel *label_productionSteps;
    QSpinBox *productionStepsSpin;
    QLabel *label_minimize;
    QComboBox *minimizeCombo;
    QLabel *label_minimizeSteps;
    QSpinBox *minimizeStepsSpin;
    QLabel *label_stateDataOptions;
    QCheckBox *stepIndexCheck;
    QCheckBox *timeCheck;
    QCheckBox *speedCheck;
    QCheckBox *progressCheck;
    QCheckBox *potentialEnergyCheck;
    QCheckBox *kineticEnergyCheck;
    QCheckBox *totalEnergyCheck;
    QCheckBox *temperatureCheck;
    QCheckBox *volumeCheck;
    QCheckBox *densityCheck;
    QHBoxLayout *horizontalLayout_10;
    QSpacerItem *horizontalSpacer_2;
    QTabWidget *tabWidget;
    QHBoxLayout *horizontalLayout_3;
    QPushButton *resetButton;
    QPushButton *enableFormButton;
    QSpacerItem *horizontalSpacer;
    QPushButton *generateButton;
    QPushButton *closeButton;

    void setupUi(QDialog *OpenMMInputDialog)
    {
        if (OpenMMInputDialog->objectName().isEmpty())
            OpenMMInputDialog->setObjectName(QString::fromUtf8("OpenMMInputDialog"));
        OpenMMInputDialog->resize(1074, 697);
        QSizePolicy sizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
        sizePolicy.setHorizontalStretch(0);
        sizePolicy.setVerticalStretch(0);
        sizePolicy.setHeightForWidth(OpenMMInputDialog->sizePolicy().hasHeightForWidth());
        OpenMMInputDialog->setSizePolicy(sizePolicy);
        OpenMMInputDialog->setSizeGripEnabled(true);
        verticalLayout = new QVBoxLayout(OpenMMInputDialog);
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        verticalLayout->setSizeConstraint(QLayout::SetNoConstraint);
        gridLayout = new QGridLayout();
        gridLayout->setObjectName(QString::fromUtf8("gridLayout"));
        gridLayout->setSizeConstraint(QLayout::SetDefaultConstraint);
        label_jobScript = new QLabel(OpenMMInputDialog);
        label_jobScript->setObjectName(QString::fromUtf8("label_jobScript"));

        gridLayout->addWidget(label_jobScript, 0, 0, 1, 1);

        jobScriptEdit = new QLineEdit(OpenMMInputDialog);
        jobScriptEdit->setObjectName(QString::fromUtf8("jobScriptEdit"));

        gridLayout->addWidget(jobScriptEdit, 0, 1, 1, 1);

        label_1 = new QLabel(OpenMMInputDialog);
        label_1->setObjectName(QString::fromUtf8("label_1"));

        gridLayout->addWidget(label_1, 0, 2, 1, 1);

        inputCoordEdit = new QLineEdit(OpenMMInputDialog);
        inputCoordEdit->setObjectName(QString::fromUtf8("inputCoordEdit"));

        gridLayout->addWidget(inputCoordEdit, 0, 3, 1, 1);

        label_2 = new QLabel(OpenMMInputDialog);
        label_2->setObjectName(QString::fromUtf8("label_2"));

        gridLayout->addWidget(label_2, 0, 4, 1, 1);

        inputTopEdit = new QLineEdit(OpenMMInputDialog);
        inputTopEdit->setObjectName(QString::fromUtf8("inputTopEdit"));
        inputTopEdit->setEnabled(false);

        gridLayout->addWidget(inputTopEdit, 0, 5, 1, 1);

        label_forceField = new QLabel(OpenMMInputDialog);
        label_forceField->setObjectName(QString::fromUtf8("label_forceField"));

        gridLayout->addWidget(label_forceField, 1, 0, 1, 1);

        forceFieldCombo = new QComboBox(OpenMMInputDialog);
        forceFieldCombo->addItem(QString());
        forceFieldCombo->addItem(QString());
        forceFieldCombo->addItem(QString());
        forceFieldCombo->addItem(QString());
        forceFieldCombo->addItem(QString());
        forceFieldCombo->addItem(QString());
        forceFieldCombo->setObjectName(QString::fromUtf8("forceFieldCombo"));

        gridLayout->addWidget(forceFieldCombo, 1, 1, 1, 1);

        label_waterModel = new QLabel(OpenMMInputDialog);
        label_waterModel->setObjectName(QString::fromUtf8("label_waterModel"));

        gridLayout->addWidget(label_waterModel, 1, 2, 1, 1);

        waterModelCombo = new QComboBox(OpenMMInputDialog);
        waterModelCombo->addItem(QString());
        waterModelCombo->addItem(QString());
        waterModelCombo->addItem(QString());
        waterModelCombo->addItem(QString());
        waterModelCombo->addItem(QString());
        waterModelCombo->setObjectName(QString::fromUtf8("waterModelCombo"));

        gridLayout->addWidget(waterModelCombo, 1, 3, 1, 1);

        label_platform = new QLabel(OpenMMInputDialog);
        label_platform->setObjectName(QString::fromUtf8("label_platform"));

        gridLayout->addWidget(label_platform, 2, 0, 1, 1);

        platformCombo = new QComboBox(OpenMMInputDialog);
        platformCombo->addItem(QString());
        platformCombo->addItem(QString());
        platformCombo->addItem(QString());
        platformCombo->addItem(QString());
        platformCombo->setObjectName(QString::fromUtf8("platformCombo"));

        gridLayout->addWidget(platformCombo, 2, 1, 1, 1);

        label_precision = new QLabel(OpenMMInputDialog);
        label_precision->setObjectName(QString::fromUtf8("label_precision"));

        gridLayout->addWidget(label_precision, 2, 2, 1, 1);

        precisionCombo = new QComboBox(OpenMMInputDialog);
        precisionCombo->addItem(QString());
        precisionCombo->addItem(QString());
        precisionCombo->addItem(QString());
        precisionCombo->setObjectName(QString::fromUtf8("precisionCombo"));

        gridLayout->addWidget(precisionCombo, 2, 3, 1, 1);

        label_deviceIndex = new QLabel(OpenMMInputDialog);
        label_deviceIndex->setObjectName(QString::fromUtf8("label_deviceIndex"));

        gridLayout->addWidget(label_deviceIndex, 2, 4, 1, 1);

        deviceIndexSpin = new QSpinBox(OpenMMInputDialog);
        deviceIndexSpin->setObjectName(QString::fromUtf8("deviceIndexSpin"));
        deviceIndexSpin->setMaximum(10000);
        deviceIndexSpin->setMinimum(1);
        deviceIndexSpin->setValue(1);

        gridLayout->addWidget(deviceIndexSpin, 2, 5, 1, 1);

        label_openCLIndex = new QLabel(OpenMMInputDialog);
        label_openCLIndex->setObjectName(QString::fromUtf8("label_openCLIndex"));

        gridLayout->addWidget(label_openCLIndex, 2, 6, 1, 1);

        openCLIndexSpin = new QSpinBox(OpenMMInputDialog);
        openCLIndexSpin->setObjectName(QString::fromUtf8("openCLIndexSpin"));
        openCLIndexSpin->setMaximum(10000);
        openCLIndexSpin->setMinimum(1);
        openCLIndexSpin->setValue(1);

        gridLayout->addWidget(openCLIndexSpin, 2, 7, 1, 1);

        line_2 = new QFrame(OpenMMInputDialog);
        line_2->setObjectName(QString::fromUtf8("line_2"));
        line_2->setLineWidth(1);
        line_2->setFrameShape(QFrame::HLine);
        line_2->setFrameShadow(QFrame::Sunken);

        gridLayout->addWidget(line_2, 3, 0, 1, 8);

        label_nonbondedMethod = new QLabel(OpenMMInputDialog);
        label_nonbondedMethod->setObjectName(QString::fromUtf8("label_nonbondedMethod"));

        gridLayout->addWidget(label_nonbondedMethod, 4, 0, 1, 1);

        nonBondedMethodCombo = new QComboBox(OpenMMInputDialog);
        nonBondedMethodCombo->addItem(QString());
        nonBondedMethodCombo->addItem(QString());
        nonBondedMethodCombo->addItem(QString());
        nonBondedMethodCombo->addItem(QString());
        nonBondedMethodCombo->addItem(QString());
        nonBondedMethodCombo->setObjectName(QString::fromUtf8("nonBondedMethodCombo"));

        gridLayout->addWidget(nonBondedMethodCombo, 4, 1, 1, 1);

        label_ewaldTolerance = new QLabel(OpenMMInputDialog);
        label_ewaldTolerance->setObjectName(QString::fromUtf8("label_ewaldTolerance"));

        gridLayout->addWidget(label_ewaldTolerance, 4, 2, 1, 1);

        ewaldToleranceSpin = new QDoubleSpinBox(OpenMMInputDialog);
        ewaldToleranceSpin->setObjectName(QString::fromUtf8("ewaldToleranceSpin"));
        ewaldToleranceSpin->setDecimals(5);
        ewaldToleranceSpin->setSingleStep(0.000010000000000);
        ewaldToleranceSpin->setValue(0.000500000000000);
        ewaldToleranceSpin->setMinimum(0.000010000000000);
        ewaldToleranceSpin->setMaximum(10000.000000000000000);

        gridLayout->addWidget(ewaldToleranceSpin, 4, 3, 1, 1);

        label_constraints = new QLabel(OpenMMInputDialog);
        label_constraints->setObjectName(QString::fromUtf8("label_constraints"));

        gridLayout->addWidget(label_constraints, 4, 4, 1, 1);

        constraintsCombo = new QComboBox(OpenMMInputDialog);
        constraintsCombo->addItem(QString());
        constraintsCombo->addItem(QString());
        constraintsCombo->addItem(QString());
        constraintsCombo->addItem(QString());
        constraintsCombo->setObjectName(QString::fromUtf8("constraintsCombo"));

        gridLayout->addWidget(constraintsCombo, 4, 5, 1, 1);

        label_constraintTolerance = new QLabel(OpenMMInputDialog);
        label_constraintTolerance->setObjectName(QString::fromUtf8("label_constraintTolerance"));

        gridLayout->addWidget(label_constraintTolerance, 4, 6, 1, 1);

        constraintToleranceSpin = new QDoubleSpinBox(OpenMMInputDialog);
        constraintToleranceSpin->setObjectName(QString::fromUtf8("constraintToleranceSpin"));
        constraintToleranceSpin->setDecimals(5);
        constraintToleranceSpin->setSingleStep(0.000010000000000);
        constraintToleranceSpin->setValue(1.000000000000000);
        constraintToleranceSpin->setMinimum(0.000010000000000);
        constraintToleranceSpin->setMaximum(10000.000000000000000);

        gridLayout->addWidget(constraintToleranceSpin, 4, 7, 1, 1);

        label_rigidWater = new QLabel(OpenMMInputDialog);
        label_rigidWater->setObjectName(QString::fromUtf8("label_rigidWater"));

        gridLayout->addWidget(label_rigidWater, 5, 0, 1, 1);

        rigidWaterCombo = new QComboBox(OpenMMInputDialog);
        rigidWaterCombo->addItem(QString());
        rigidWaterCombo->addItem(QString());
        rigidWaterCombo->setObjectName(QString::fromUtf8("rigidWaterCombo"));

        gridLayout->addWidget(rigidWaterCombo, 5, 1, 1, 1);

        label_nonBondedCutoff = new QLabel(OpenMMInputDialog);
        label_nonBondedCutoff->setObjectName(QString::fromUtf8("label_nonBondedCutoff"));

        gridLayout->addWidget(label_nonBondedCutoff, 5, 2, 1, 1);

        nonBondedCutoffSpin = new QDoubleSpinBox(OpenMMInputDialog);
        nonBondedCutoffSpin->setObjectName(QString::fromUtf8("nonBondedCutoffSpin"));
        nonBondedCutoffSpin->setDecimals(4);
        nonBondedCutoffSpin->setSingleStep(0.000100000000000);
        nonBondedCutoffSpin->setValue(1.000000000000000);
        nonBondedCutoffSpin->setMinimum(0.000100000000000);
        nonBondedCutoffSpin->setMaximum(10000.000000000000000);

        gridLayout->addWidget(nonBondedCutoffSpin, 5, 3, 1, 1);

        label_randomInitVel = new QLabel(OpenMMInputDialog);
        label_randomInitVel->setObjectName(QString::fromUtf8("label_randomInitVel"));

        gridLayout->addWidget(label_randomInitVel, 5, 4, 1, 1);

        initVelCombo = new QComboBox(OpenMMInputDialog);
        initVelCombo->addItem(QString());
        initVelCombo->addItem(QString());
        initVelCombo->setObjectName(QString::fromUtf8("initVelCombo"));

        gridLayout->addWidget(initVelCombo, 5, 5, 1, 1);

        label_generationTemp = new QLabel(OpenMMInputDialog);
        label_generationTemp->setObjectName(QString::fromUtf8("label_generationTemp"));

        gridLayout->addWidget(label_generationTemp, 5, 6, 1, 1);

        generationTemperatureSpin = new QDoubleSpinBox(OpenMMInputDialog);
        generationTemperatureSpin->setObjectName(QString::fromUtf8("generationTemperatureSpin"));
        generationTemperatureSpin->setDecimals(2);
        generationTemperatureSpin->setMaximum(20000.000000000000000);
        generationTemperatureSpin->setValue(298.149999999999977);

        gridLayout->addWidget(generationTemperatureSpin, 5, 7, 1, 1);

        line_3 = new QFrame(OpenMMInputDialog);
        line_3->setObjectName(QString::fromUtf8("line_3"));
        line_3->setLineWidth(1);
        line_3->setFrameShape(QFrame::HLine);
        line_3->setFrameShadow(QFrame::Sunken);

        gridLayout->addWidget(line_3, 6, 0, 1, 8);

        label_integrator = new QLabel(OpenMMInputDialog);
        label_integrator->setObjectName(QString::fromUtf8("label_integrator"));

        gridLayout->addWidget(label_integrator, 7, 0, 1, 1);

        integratorCombo = new QComboBox(OpenMMInputDialog);
        integratorCombo->addItem(QString());
        integratorCombo->addItem(QString());
        integratorCombo->addItem(QString());
        integratorCombo->addItem(QString());
        integratorCombo->addItem(QString());
        integratorCombo->setObjectName(QString::fromUtf8("integratorCombo"));

        gridLayout->addWidget(integratorCombo, 7, 1, 1, 1);

        label_timestep = new QLabel(OpenMMInputDialog);
        label_timestep->setObjectName(QString::fromUtf8("label_timestep"));

        gridLayout->addWidget(label_timestep, 8, 0, 1, 1);

        stepSpin = new QDoubleSpinBox(OpenMMInputDialog);
        stepSpin->setObjectName(QString::fromUtf8("stepSpin"));
        stepSpin->setSingleStep(0.500000000000000);
        stepSpin->setValue(2.000000000000000);

        gridLayout->addWidget(stepSpin, 8, 1, 1, 1);

        label_errorTol = new QLabel(OpenMMInputDialog);
        label_errorTol->setObjectName(QString::fromUtf8("label_errorTol"));

        gridLayout->addWidget(label_errorTol, 8, 2, 1, 1);

        errorTolSpin = new QDoubleSpinBox(OpenMMInputDialog);
        errorTolSpin->setObjectName(QString::fromUtf8("errorTolSpin"));
        errorTolSpin->setDecimals(4);
        errorTolSpin->setSingleStep(0.000100000000000);
        errorTolSpin->setValue(0.000100000000000);
        errorTolSpin->setMinimum(0.000100000000000);
        errorTolSpin->setMaximum(10000.000000000000000);

        gridLayout->addWidget(errorTolSpin, 8, 3, 1, 1);

        label_collisionRate = new QLabel(OpenMMInputDialog);
        label_collisionRate->setObjectName(QString::fromUtf8("label_collisionRate"));

        gridLayout->addWidget(label_collisionRate, 8, 4, 1, 1);

        collisionRateSpin = new QDoubleSpinBox(OpenMMInputDialog);
        collisionRateSpin->setObjectName(QString::fromUtf8("collisionRateSpin"));
        collisionRateSpin->setDecimals(2);
        collisionRateSpin->setMaximum(20000.000000000000000);
        collisionRateSpin->setValue(1.500000000000000);

        gridLayout->addWidget(collisionRateSpin, 8, 5, 1, 1);

        label_temperature = new QLabel(OpenMMInputDialog);
        label_temperature->setObjectName(QString::fromUtf8("label_temperature"));

        gridLayout->addWidget(label_temperature, 8, 6, 1, 1);

        temperatureSpin = new QDoubleSpinBox(OpenMMInputDialog);
        temperatureSpin->setObjectName(QString::fromUtf8("temperatureSpin"));
        temperatureSpin->setDecimals(2);
        temperatureSpin->setMaximum(20000.000000000000000);
        temperatureSpin->setValue(298.149999999999977);

        gridLayout->addWidget(temperatureSpin, 8, 7, 1, 1);

        label_barostat = new QLabel(OpenMMInputDialog);
        label_barostat->setObjectName(QString::fromUtf8("label_barostat"));

        gridLayout->addWidget(label_barostat, 9, 0, 1, 1);

        barostatCombo = new QComboBox(OpenMMInputDialog);
        barostatCombo->addItem(QString());
        barostatCombo->addItem(QString());
        barostatCombo->setObjectName(QString::fromUtf8("barostatCombo"));

        gridLayout->addWidget(barostatCombo, 9, 1, 1, 1);

        label_pressure = new QLabel(OpenMMInputDialog);
        label_pressure->setObjectName(QString::fromUtf8("label_pressure"));

        gridLayout->addWidget(label_pressure, 9, 2, 1, 1);

        pressureSpin = new QDoubleSpinBox(OpenMMInputDialog);
        pressureSpin->setObjectName(QString::fromUtf8("pressureSpin"));
        pressureSpin->setDecimals(2);
        pressureSpin->setMaximum(20000.000000000000000);
        pressureSpin->setValue(1.000000000000000);

        gridLayout->addWidget(pressureSpin, 9, 3, 1, 1);

        label_barostatInterval = new QLabel(OpenMMInputDialog);
        label_barostatInterval->setObjectName(QString::fromUtf8("label_barostatInterval"));

        gridLayout->addWidget(label_barostatInterval, 9, 4, 1, 1);

        barostatIntervalSpin = new QSpinBox(OpenMMInputDialog);
        barostatIntervalSpin->setObjectName(QString::fromUtf8("barostatIntervalSpin"));
        barostatIntervalSpin->setMaximum(10000);
        barostatIntervalSpin->setMinimum(1);
        barostatIntervalSpin->setValue(25);

        gridLayout->addWidget(barostatIntervalSpin, 9, 5, 1, 1);

        line_4 = new QFrame(OpenMMInputDialog);
        line_4->setObjectName(QString::fromUtf8("line_4"));
        line_4->setFrameShape(QFrame::HLine);
        line_4->setFrameShadow(QFrame::Sunken);

        gridLayout->addWidget(line_4, 10, 0, 1, 8);

        label_reporters = new QLabel(OpenMMInputDialog);
        label_reporters->setObjectName(QString::fromUtf8("label_reporters"));

        gridLayout->addWidget(label_reporters, 11, 0, 1, 1);

        stateDataCheck = new QCheckBox(OpenMMInputDialog);
        stateDataCheck->setObjectName(QString::fromUtf8("stateDataCheck"));
        stateDataCheck->setChecked(true);

        gridLayout->addWidget(stateDataCheck, 11, 1, 1, 1);

        dcdCheck = new QCheckBox(OpenMMInputDialog);
        dcdCheck->setObjectName(QString::fromUtf8("dcdCheck"));
        dcdCheck->setChecked(true);

        gridLayout->addWidget(dcdCheck, 11, 2, 1, 1);

        pdbCheck = new QCheckBox(OpenMMInputDialog);
        pdbCheck->setObjectName(QString::fromUtf8("pdbCheck"));
        pdbCheck->setChecked(false);

        gridLayout->addWidget(pdbCheck, 11, 3, 1, 1);

        label_reportInterval = new QLabel(OpenMMInputDialog);
        label_reportInterval->setObjectName(QString::fromUtf8("label_reportInterval"));

        gridLayout->addWidget(label_reportInterval, 11, 4, 1, 1);

        reportIntervalSpin = new QSpinBox(OpenMMInputDialog);
        reportIntervalSpin->setObjectName(QString::fromUtf8("reportIntervalSpin"));
        reportIntervalSpin->setMinimum(1);
        reportIntervalSpin->setMaximum(9999999);
        reportIntervalSpin->setValue(1000);

        gridLayout->addWidget(reportIntervalSpin, 11, 5, 1, 1);

        label_equilibriationSteps = new QLabel(OpenMMInputDialog);
        label_equilibriationSteps->setObjectName(QString::fromUtf8("label_equilibriationSteps"));

        gridLayout->addWidget(label_equilibriationSteps, 11, 6, 1, 1);

        equilibriationStepsSpin = new QSpinBox(OpenMMInputDialog);
        equilibriationStepsSpin->setObjectName(QString::fromUtf8("equilibriationStepsSpin"));
        equilibriationStepsSpin->setMinimum(1);
        equilibriationStepsSpin->setMaximum(9999999);
        equilibriationStepsSpin->setValue(100);

        gridLayout->addWidget(equilibriationStepsSpin, 11, 7, 1, 1);

        label_productionSteps = new QLabel(OpenMMInputDialog);
        label_productionSteps->setObjectName(QString::fromUtf8("label_productionSteps"));

        gridLayout->addWidget(label_productionSteps, 12, 0, 1, 1);

        productionStepsSpin = new QSpinBox(OpenMMInputDialog);
        productionStepsSpin->setObjectName(QString::fromUtf8("productionStepsSpin"));
        productionStepsSpin->setMinimum(1);
        productionStepsSpin->setMaximum(9999999);
        productionStepsSpin->setValue(1000);

        gridLayout->addWidget(productionStepsSpin, 12, 1, 1, 1);

        label_minimize = new QLabel(OpenMMInputDialog);
        label_minimize->setObjectName(QString::fromUtf8("label_minimize"));

        gridLayout->addWidget(label_minimize, 12, 2, 1, 1);

        minimizeCombo = new QComboBox(OpenMMInputDialog);
        minimizeCombo->addItem(QString());
        minimizeCombo->addItem(QString());
        minimizeCombo->setObjectName(QString::fromUtf8("minimizeCombo"));

        gridLayout->addWidget(minimizeCombo, 12, 3, 1, 1);

        label_minimizeSteps = new QLabel(OpenMMInputDialog);
        label_minimizeSteps->setObjectName(QString::fromUtf8("label_minimizeSteps"));

        gridLayout->addWidget(label_minimizeSteps, 12, 4, 1, 1);

        minimizeStepsSpin = new QSpinBox(OpenMMInputDialog);
        minimizeStepsSpin->setObjectName(QString::fromUtf8("minimizeStepsSpin"));
        minimizeStepsSpin->setMinimum(1);
        minimizeStepsSpin->setMaximum(9999999);
        minimizeStepsSpin->setValue(1000);

        gridLayout->addWidget(minimizeStepsSpin, 12, 5, 1, 1);

        label_stateDataOptions = new QLabel(OpenMMInputDialog);
        label_stateDataOptions->setObjectName(QString::fromUtf8("label_stateDataOptions"));

        gridLayout->addWidget(label_stateDataOptions, 13, 0, 1, 1);

        stepIndexCheck = new QCheckBox(OpenMMInputDialog);
        stepIndexCheck->setObjectName(QString::fromUtf8("stepIndexCheck"));
        stepIndexCheck->setChecked(true);

        gridLayout->addWidget(stepIndexCheck, 13, 1, 1, 1);

        timeCheck = new QCheckBox(OpenMMInputDialog);
        timeCheck->setObjectName(QString::fromUtf8("timeCheck"));
        timeCheck->setChecked(false);

        gridLayout->addWidget(timeCheck, 13, 2, 1, 1);

        speedCheck = new QCheckBox(OpenMMInputDialog);
        speedCheck->setObjectName(QString::fromUtf8("speedCheck"));
        speedCheck->setChecked(true);

        gridLayout->addWidget(speedCheck, 13, 3, 1, 1);

        progressCheck = new QCheckBox(OpenMMInputDialog);
        progressCheck->setObjectName(QString::fromUtf8("progressCheck"));
        progressCheck->setChecked(true);

        gridLayout->addWidget(progressCheck, 13, 4, 1, 1);

        potentialEnergyCheck = new QCheckBox(OpenMMInputDialog);
        potentialEnergyCheck->setObjectName(QString::fromUtf8("potentialEnergyCheck"));
        potentialEnergyCheck->setChecked(true);

        gridLayout->addWidget(potentialEnergyCheck, 13, 5, 1, 1);

        kineticEnergyCheck = new QCheckBox(OpenMMInputDialog);
        kineticEnergyCheck->setObjectName(QString::fromUtf8("kineticEnergyCheck"));
        kineticEnergyCheck->setChecked(false);

        gridLayout->addWidget(kineticEnergyCheck, 13, 6, 1, 1);

        totalEnergyCheck = new QCheckBox(OpenMMInputDialog);
        totalEnergyCheck->setObjectName(QString::fromUtf8("totalEnergyCheck"));
        totalEnergyCheck->setChecked(false);

        gridLayout->addWidget(totalEnergyCheck, 13, 7, 1, 1);

        temperatureCheck = new QCheckBox(OpenMMInputDialog);
        temperatureCheck->setObjectName(QString::fromUtf8("temperatureCheck"));
        temperatureCheck->setChecked(true);

        gridLayout->addWidget(temperatureCheck, 14, 1, 1, 1);

        volumeCheck = new QCheckBox(OpenMMInputDialog);
        volumeCheck->setObjectName(QString::fromUtf8("volumeCheck"));
        volumeCheck->setChecked(false);

        gridLayout->addWidget(volumeCheck, 14, 2, 1, 1);

        densityCheck = new QCheckBox(OpenMMInputDialog);
        densityCheck->setObjectName(QString::fromUtf8("densityCheck"));
        densityCheck->setChecked(false);

        gridLayout->addWidget(densityCheck, 14, 3, 1, 1);


        verticalLayout->addLayout(gridLayout);

        horizontalLayout_10 = new QHBoxLayout();
        horizontalLayout_10->setObjectName(QString::fromUtf8("horizontalLayout_10"));
        horizontalSpacer_2 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_10->addItem(horizontalSpacer_2);


        verticalLayout->addLayout(horizontalLayout_10);

        tabWidget = new QTabWidget(OpenMMInputDialog);
        tabWidget->setObjectName(QString::fromUtf8("tabWidget"));
        sizePolicy.setHeightForWidth(tabWidget->sizePolicy().hasHeightForWidth());
        tabWidget->setSizePolicy(sizePolicy);

        verticalLayout->addWidget(tabWidget);

        horizontalLayout_3 = new QHBoxLayout();
        horizontalLayout_3->setObjectName(QString::fromUtf8("horizontalLayout_3"));
        horizontalLayout_3->setSizeConstraint(QLayout::SetFixedSize);
        resetButton = new QPushButton(OpenMMInputDialog);
        resetButton->setObjectName(QString::fromUtf8("resetButton"));

        horizontalLayout_3->addWidget(resetButton);

        enableFormButton = new QPushButton(OpenMMInputDialog);
        enableFormButton->setObjectName(QString::fromUtf8("enableFormButton"));
        enableFormButton->setEnabled(false);

        horizontalLayout_3->addWidget(enableFormButton);

        horizontalSpacer = new QSpacerItem(48, 26, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_3->addItem(horizontalSpacer);

        generateButton = new QPushButton(OpenMMInputDialog);
        generateButton->setObjectName(QString::fromUtf8("generateButton"));

        horizontalLayout_3->addWidget(generateButton);

        closeButton = new QPushButton(OpenMMInputDialog);
        closeButton->setObjectName(QString::fromUtf8("closeButton"));

        horizontalLayout_3->addWidget(closeButton);


        verticalLayout->addLayout(horizontalLayout_3);

        QWidget::setTabOrder(generateButton, closeButton);
        QWidget::setTabOrder(closeButton, resetButton);
        QWidget::setTabOrder(resetButton, enableFormButton);

        retranslateUi(OpenMMInputDialog);
        QObject::connect(closeButton, SIGNAL(clicked()), OpenMMInputDialog, SLOT(close()));

        QMetaObject::connectSlotsByName(OpenMMInputDialog);
    } // setupUi

    void retranslateUi(QDialog *OpenMMInputDialog)
    {
        OpenMMInputDialog->setWindowTitle(QCoreApplication::translate("OpenMMInputDialog", "OpenMM Script Builder", nullptr));
        label_jobScript->setText(QCoreApplication::translate("OpenMMInputDialog", "Job script:", nullptr));
        jobScriptEdit->setText(QString());
        jobScriptEdit->setPlaceholderText(QCoreApplication::translate("OpenMMInputDialog", "script", nullptr));
        label_1->setText(QCoreApplication::translate("OpenMMInputDialog", "Input Coords:", nullptr));
        inputCoordEdit->setText(QString());
        inputCoordEdit->setPlaceholderText(QCoreApplication::translate("OpenMMInputDialog", "input.pdb", nullptr));
        label_2->setText(QCoreApplication::translate("OpenMMInputDialog", "Input Topology:", nullptr));
        inputTopEdit->setText(QString());
        inputTopEdit->setPlaceholderText(QCoreApplication::translate("OpenMMInputDialog", "input.prmtop", nullptr));
        label_forceField->setText(QCoreApplication::translate("OpenMMInputDialog", "Forcefield:", nullptr));
        forceFieldCombo->setItemText(0, QCoreApplication::translate("OpenMMInputDialog", "AMBER96", nullptr));
        forceFieldCombo->setItemText(1, QCoreApplication::translate("OpenMMInputDialog", "AMBER99sb", nullptr));
        forceFieldCombo->setItemText(2, QCoreApplication::translate("OpenMMInputDialog", "AMBER99sb-ildn", nullptr));
        forceFieldCombo->setItemText(3, QCoreApplication::translate("OpenMMInputDialog", "AMBER99sb-nmr", nullptr));
        forceFieldCombo->setItemText(4, QCoreApplication::translate("OpenMMInputDialog", "AMBER03", nullptr));
        forceFieldCombo->setItemText(5, QCoreApplication::translate("OpenMMInputDialog", "AMBER10", nullptr));

        label_waterModel->setText(QCoreApplication::translate("OpenMMInputDialog", "Water Model:", nullptr));
        waterModelCombo->setItemText(0, QCoreApplication::translate("OpenMMInputDialog", "SPC/E", nullptr));
        waterModelCombo->setItemText(1, QCoreApplication::translate("OpenMMInputDialog", "TIP3P", nullptr));
        waterModelCombo->setItemText(2, QCoreApplication::translate("OpenMMInputDialog", "TIP4P-Ew", nullptr));
        waterModelCombo->setItemText(3, QCoreApplication::translate("OpenMMInputDialog", "TIP5P", nullptr));
        waterModelCombo->setItemText(4, QCoreApplication::translate("OpenMMInputDialog", "Implicit Solvent (OBC)", nullptr));

        label_platform->setText(QCoreApplication::translate("OpenMMInputDialog", "Platform:", nullptr));
        platformCombo->setItemText(0, QCoreApplication::translate("OpenMMInputDialog", "Reference", nullptr));
        platformCombo->setItemText(1, QCoreApplication::translate("OpenMMInputDialog", "OpenCL", nullptr));
        platformCombo->setItemText(2, QCoreApplication::translate("OpenMMInputDialog", "CPU", nullptr));
        platformCombo->setItemText(3, QCoreApplication::translate("OpenMMInputDialog", "CUDA", nullptr));

        label_precision->setText(QCoreApplication::translate("OpenMMInputDialog", "Precision:", nullptr));
        precisionCombo->setItemText(0, QCoreApplication::translate("OpenMMInputDialog", "single", nullptr));
        precisionCombo->setItemText(1, QCoreApplication::translate("OpenMMInputDialog", "mixed", nullptr));
        precisionCombo->setItemText(2, QCoreApplication::translate("OpenMMInputDialog", "double", nullptr));

        label_deviceIndex->setText(QCoreApplication::translate("OpenMMInputDialog", "Device Index:", nullptr));
        label_openCLIndex->setText(QCoreApplication::translate("OpenMMInputDialog", "OpenCL Platform Index:", nullptr));
        label_nonbondedMethod->setText(QCoreApplication::translate("OpenMMInputDialog", "Nonbonded method:", nullptr));
        nonBondedMethodCombo->setItemText(0, QCoreApplication::translate("OpenMMInputDialog", "NoCutoff", nullptr));
        nonBondedMethodCombo->setItemText(1, QCoreApplication::translate("OpenMMInputDialog", "CutoffNonPeriodic", nullptr));
        nonBondedMethodCombo->setItemText(2, QCoreApplication::translate("OpenMMInputDialog", "CutoffPeriodic", nullptr));
        nonBondedMethodCombo->setItemText(3, QCoreApplication::translate("OpenMMInputDialog", "Ewald", nullptr));
        nonBondedMethodCombo->setItemText(4, QCoreApplication::translate("OpenMMInputDialog", "PME", nullptr));

        label_ewaldTolerance->setText(QCoreApplication::translate("OpenMMInputDialog", "Ewald Tolerance:", nullptr));
        label_constraints->setText(QCoreApplication::translate("OpenMMInputDialog", "Constraints:", nullptr));
        constraintsCombo->setItemText(0, QCoreApplication::translate("OpenMMInputDialog", "None", nullptr));
        constraintsCombo->setItemText(1, QCoreApplication::translate("OpenMMInputDialog", "HBonds", nullptr));
        constraintsCombo->setItemText(2, QCoreApplication::translate("OpenMMInputDialog", "AllBonds", nullptr));
        constraintsCombo->setItemText(3, QCoreApplication::translate("OpenMMInputDialog", "HAngles", nullptr));

        label_constraintTolerance->setText(QCoreApplication::translate("OpenMMInputDialog", "Constraint Tolerance:", nullptr));
        label_rigidWater->setText(QCoreApplication::translate("OpenMMInputDialog", "Rigid water?", nullptr));
        rigidWaterCombo->setItemText(0, QCoreApplication::translate("OpenMMInputDialog", "True", nullptr));
        rigidWaterCombo->setItemText(1, QCoreApplication::translate("OpenMMInputDialog", "False", nullptr));

        label_nonBondedCutoff->setText(QCoreApplication::translate("OpenMMInputDialog", "Nonbonded cutoff:", nullptr));
        nonBondedCutoffSpin->setSuffix(QCoreApplication::translate("OpenMMInputDialog", " nm", nullptr));
        label_randomInitVel->setText(QCoreApplication::translate("OpenMMInputDialog", "Random initial velocity:", nullptr));
        initVelCombo->setItemText(0, QCoreApplication::translate("OpenMMInputDialog", "True", nullptr));
        initVelCombo->setItemText(1, QCoreApplication::translate("OpenMMInputDialog", "False", nullptr));

        label_generationTemp->setText(QCoreApplication::translate("OpenMMInputDialog", "Generation Temp:", nullptr));
        generationTemperatureSpin->setSuffix(QCoreApplication::translate("OpenMMInputDialog", " K", nullptr));
        label_integrator->setText(QCoreApplication::translate("OpenMMInputDialog", "Integrator:", nullptr));
        integratorCombo->setItemText(0, QCoreApplication::translate("OpenMMInputDialog", "Langevin", nullptr));
        integratorCombo->setItemText(1, QCoreApplication::translate("OpenMMInputDialog", "Verlet", nullptr));
        integratorCombo->setItemText(2, QCoreApplication::translate("OpenMMInputDialog", "Brownian", nullptr));
        integratorCombo->setItemText(3, QCoreApplication::translate("OpenMMInputDialog", "VariableLangevin", nullptr));
        integratorCombo->setItemText(4, QCoreApplication::translate("OpenMMInputDialog", "VariableVerlet", nullptr));

#if QT_CONFIG(tooltip)
        label_timestep->setToolTip(QCoreApplication::translate("OpenMMInputDialog", "Time step for the simulation in units according to \"Units\" specification.", nullptr));
#endif // QT_CONFIG(tooltip)
        label_timestep->setText(QCoreApplication::translate("OpenMMInputDialog", "Timestep:", nullptr));
#if QT_CONFIG(tooltip)
        stepSpin->setToolTip(QCoreApplication::translate("OpenMMInputDialog", "Time step for the simulation in units according to \"Units\" specification.", nullptr));
#endif // QT_CONFIG(tooltip)
        stepSpin->setSuffix(QCoreApplication::translate("OpenMMInputDialog", " fs", nullptr));
        label_errorTol->setText(QCoreApplication::translate("OpenMMInputDialog", "Error tolerance:", nullptr));
        label_collisionRate->setText(QCoreApplication::translate("OpenMMInputDialog", "Collision rate:", nullptr));
        collisionRateSpin->setSuffix(QCoreApplication::translate("OpenMMInputDialog", "/ps", nullptr));
        label_temperature->setText(QCoreApplication::translate("OpenMMInputDialog", "Temperature:", nullptr));
        temperatureSpin->setSuffix(QCoreApplication::translate("OpenMMInputDialog", " K", nullptr));
        label_barostat->setText(QCoreApplication::translate("OpenMMInputDialog", "Barostat:", nullptr));
        barostatCombo->setItemText(0, QCoreApplication::translate("OpenMMInputDialog", "None", nullptr));
        barostatCombo->setItemText(1, QCoreApplication::translate("OpenMMInputDialog", "Monte Carlo", nullptr));

        label_pressure->setText(QCoreApplication::translate("OpenMMInputDialog", "Pressure:", nullptr));
        pressureSpin->setSuffix(QCoreApplication::translate("OpenMMInputDialog", " atm", nullptr));
        label_barostatInterval->setText(QCoreApplication::translate("OpenMMInputDialog", "Barostat Interval", nullptr));
        label_reporters->setText(QCoreApplication::translate("OpenMMInputDialog", "Reporters:", nullptr));
        stateDataCheck->setText(QCoreApplication::translate("OpenMMInputDialog", "StateData", nullptr));
        dcdCheck->setText(QCoreApplication::translate("OpenMMInputDialog", "DCD", nullptr));
        pdbCheck->setText(QCoreApplication::translate("OpenMMInputDialog", "PDB", nullptr));
        label_reportInterval->setText(QCoreApplication::translate("OpenMMInputDialog", "Report Interval:", nullptr));
        label_equilibriationSteps->setText(QCoreApplication::translate("OpenMMInputDialog", "Equilibration Steps:", nullptr));
        label_productionSteps->setText(QCoreApplication::translate("OpenMMInputDialog", "Production Steps:", nullptr));
        label_minimize->setText(QCoreApplication::translate("OpenMMInputDialog", "Minimize?", nullptr));
        minimizeCombo->setItemText(0, QCoreApplication::translate("OpenMMInputDialog", "True", nullptr));
        minimizeCombo->setItemText(1, QCoreApplication::translate("OpenMMInputDialog", "False", nullptr));

        label_minimizeSteps->setText(QCoreApplication::translate("OpenMMInputDialog", "Max. Minimize Steps:", nullptr));
        label_stateDataOptions->setText(QCoreApplication::translate("OpenMMInputDialog", "StateData options:", nullptr));
        stepIndexCheck->setText(QCoreApplication::translate("OpenMMInputDialog", "Step Index", nullptr));
        timeCheck->setText(QCoreApplication::translate("OpenMMInputDialog", "Time", nullptr));
        speedCheck->setText(QCoreApplication::translate("OpenMMInputDialog", "Speed", nullptr));
        progressCheck->setText(QCoreApplication::translate("OpenMMInputDialog", "Progress", nullptr));
        potentialEnergyCheck->setText(QCoreApplication::translate("OpenMMInputDialog", "Potential Energy", nullptr));
        kineticEnergyCheck->setText(QCoreApplication::translate("OpenMMInputDialog", "Kinetic Energy", nullptr));
        totalEnergyCheck->setText(QCoreApplication::translate("OpenMMInputDialog", "Total Energy", nullptr));
        temperatureCheck->setText(QCoreApplication::translate("OpenMMInputDialog", "Temperature", nullptr));
        volumeCheck->setText(QCoreApplication::translate("OpenMMInputDialog", "Volume", nullptr));
        densityCheck->setText(QCoreApplication::translate("OpenMMInputDialog", "Density", nullptr));
        resetButton->setText(QCoreApplication::translate("OpenMMInputDialog", "Reset", nullptr));
        enableFormButton->setText(QCoreApplication::translate("OpenMMInputDialog", "Use Form", nullptr));
        generateButton->setText(QCoreApplication::translate("OpenMMInputDialog", "Generate\342\200\246", nullptr));
        closeButton->setText(QCoreApplication::translate("OpenMMInputDialog", "Close", nullptr));
    } // retranslateUi

};

namespace Ui {
    class OpenMMInputDialog: public Ui_OpenMMInputDialog {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_OPENMMINPUTDIALOG_H
