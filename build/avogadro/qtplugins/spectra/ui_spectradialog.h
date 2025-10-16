/********************************************************************************
** Form generated from reading UI file 'spectradialog.ui'
**
** Created by: Qt User Interface Compiler version 5.15.17
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_SPECTRADIALOG_H
#define UI_SPECTRADIALOG_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QDialog>
#include <QtWidgets/QDoubleSpinBox>
#include <QtWidgets/QGridLayout>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLabel>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QTabWidget>
#include <QtWidgets/QTableWidget>
#include <QtWidgets/QWidget>
#include <avogadro/qtgui/chartwidget.h>

QT_BEGIN_NAMESPACE

class Ui_SpectraDialog
{
public:
    QGridLayout *gridLayout;
    QTabWidget *tab_widget;
    QWidget *tab_spectra;
    QGridLayout *gridLayout_2;
    QDoubleSpinBox *yAxisMinimum;
    QLabel *label_11;
    QDoubleSpinBox *xAxisMaximum;
    QLabel *label_7;
    QLabel *label_9;
    QDoubleSpinBox *offsetSpinBox;
    QLabel *label_12;
    QLabel *label_10;
    QDoubleSpinBox *xAxisMinimum;
    QLabel *label_8;
    QDoubleSpinBox *yAxisMaximum;
    QDoubleSpinBox *scaleSpinBox;
    QLabel *label_13;
    QDoubleSpinBox *peakWidth;
    QDoubleSpinBox *peakThreshold;
    QLabel *label_27;
    QLabel *unitsLabel;
    QComboBox *unitsCombo;
    QWidget *tab_appearance;
    QGridLayout *gridLayout_3;
    QCheckBox *cb_import;
    QPushButton *push_import;
    QPushButton *push_colorImported;
    QLabel *label_6;
    QLabel *label_4;
    QCheckBox *cb_calculate;
    QPushButton *push_colorForeground;
    QPushButton *push_export;
    QPushButton *push_colorCalculated;
    QLabel *label_2;
    QLabel *label_3;
    QPushButton *push_colorBackground;
    QLabel *label;
    QComboBox *fontSizeCombo;
    QLabel *label_5;
    QDoubleSpinBox *lineWidthSpinBox;
    QComboBox *combo_spectra;
    QPushButton *push_exportData;
    QPushButton *pushButton;
    QPushButton *push_options;
    QTableWidget *dataTable;
    Avogadro::QtGui::ChartWidget *plot;
    QPushButton *push_loadSpectra;
    QComboBox *elementCombo;

    void setupUi(QDialog *SpectraDialog)
    {
        if (SpectraDialog->objectName().isEmpty())
            SpectraDialog->setObjectName(QString::fromUtf8("SpectraDialog"));
        SpectraDialog->resize(808, 480);
        SpectraDialog->setMinimumSize(QSize(808, 480));
        SpectraDialog->setSizeGripEnabled(true);
        gridLayout = new QGridLayout(SpectraDialog);
        gridLayout->setObjectName(QString::fromUtf8("gridLayout"));
        tab_widget = new QTabWidget(SpectraDialog);
        tab_widget->setObjectName(QString::fromUtf8("tab_widget"));
        QSizePolicy sizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
        sizePolicy.setHorizontalStretch(0);
        sizePolicy.setVerticalStretch(0);
        sizePolicy.setHeightForWidth(tab_widget->sizePolicy().hasHeightForWidth());
        tab_widget->setSizePolicy(sizePolicy);
        tab_spectra = new QWidget();
        tab_spectra->setObjectName(QString::fromUtf8("tab_spectra"));
        gridLayout_2 = new QGridLayout(tab_spectra);
        gridLayout_2->setObjectName(QString::fromUtf8("gridLayout_2"));
        yAxisMinimum = new QDoubleSpinBox(tab_spectra);
        yAxisMinimum->setObjectName(QString::fromUtf8("yAxisMinimum"));
        yAxisMinimum->setAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);
        yAxisMinimum->setMinimum(-4000.000000000000000);
        yAxisMinimum->setMaximum(4000.000000000000000);

        gridLayout_2->addWidget(yAxisMinimum, 4, 1, 1, 1);

        label_11 = new QLabel(tab_spectra);
        label_11->setObjectName(QString::fromUtf8("label_11"));

        gridLayout_2->addWidget(label_11, 1, 0, 1, 1);

        xAxisMaximum = new QDoubleSpinBox(tab_spectra);
        xAxisMaximum->setObjectName(QString::fromUtf8("xAxisMaximum"));
        xAxisMaximum->setAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);
        xAxisMaximum->setMaximum(4000.000000000000000);

        gridLayout_2->addWidget(xAxisMaximum, 3, 3, 1, 1);

        label_7 = new QLabel(tab_spectra);
        label_7->setObjectName(QString::fromUtf8("label_7"));

        gridLayout_2->addWidget(label_7, 3, 0, 1, 1);

        label_9 = new QLabel(tab_spectra);
        label_9->setObjectName(QString::fromUtf8("label_9"));

        gridLayout_2->addWidget(label_9, 3, 2, 1, 1);

        offsetSpinBox = new QDoubleSpinBox(tab_spectra);
        offsetSpinBox->setObjectName(QString::fromUtf8("offsetSpinBox"));
        offsetSpinBox->setAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);
        offsetSpinBox->setDecimals(3);

        gridLayout_2->addWidget(offsetSpinBox, 1, 3, 1, 1);

        label_12 = new QLabel(tab_spectra);
        label_12->setObjectName(QString::fromUtf8("label_12"));

        gridLayout_2->addWidget(label_12, 1, 2, 1, 1);

        label_10 = new QLabel(tab_spectra);
        label_10->setObjectName(QString::fromUtf8("label_10"));

        gridLayout_2->addWidget(label_10, 4, 2, 1, 1);

        xAxisMinimum = new QDoubleSpinBox(tab_spectra);
        xAxisMinimum->setObjectName(QString::fromUtf8("xAxisMinimum"));
        xAxisMinimum->setAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);
        xAxisMinimum->setMaximum(4000.000000000000000);

        gridLayout_2->addWidget(xAxisMinimum, 3, 1, 1, 1);

        label_8 = new QLabel(tab_spectra);
        label_8->setObjectName(QString::fromUtf8("label_8"));

        gridLayout_2->addWidget(label_8, 4, 0, 1, 1);

        yAxisMaximum = new QDoubleSpinBox(tab_spectra);
        yAxisMaximum->setObjectName(QString::fromUtf8("yAxisMaximum"));
        yAxisMaximum->setAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);
        yAxisMaximum->setMaximum(4000.000000000000000);

        gridLayout_2->addWidget(yAxisMaximum, 4, 3, 1, 1);

        scaleSpinBox = new QDoubleSpinBox(tab_spectra);
        scaleSpinBox->setObjectName(QString::fromUtf8("scaleSpinBox"));
        scaleSpinBox->setAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);
        scaleSpinBox->setDecimals(4);
        scaleSpinBox->setSingleStep(0.100000000000000);
        scaleSpinBox->setValue(1.000000000000000);

        gridLayout_2->addWidget(scaleSpinBox, 1, 1, 1, 1);

        label_13 = new QLabel(tab_spectra);
        label_13->setObjectName(QString::fromUtf8("label_13"));

        gridLayout_2->addWidget(label_13, 2, 0, 1, 1);

        peakWidth = new QDoubleSpinBox(tab_spectra);
        peakWidth->setObjectName(QString::fromUtf8("peakWidth"));
        peakWidth->setAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);
        peakWidth->setMinimum(0.010000000000000);

        gridLayout_2->addWidget(peakWidth, 2, 1, 1, 1);

        peakThreshold = new QDoubleSpinBox(tab_spectra);
        peakThreshold->setObjectName(QString::fromUtf8("peakThreshold"));
        peakThreshold->setEnabled(false);
        peakThreshold->setAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);

        gridLayout_2->addWidget(peakThreshold, 2, 3, 1, 1);

        label_27 = new QLabel(tab_spectra);
        label_27->setObjectName(QString::fromUtf8("label_27"));

        gridLayout_2->addWidget(label_27, 2, 2, 1, 1);

        unitsLabel = new QLabel(tab_spectra);
        unitsLabel->setObjectName(QString::fromUtf8("unitsLabel"));

        gridLayout_2->addWidget(unitsLabel, 0, 0, 1, 1);

        unitsCombo = new QComboBox(tab_spectra);
        unitsCombo->setObjectName(QString::fromUtf8("unitsCombo"));
        unitsCombo->setEnabled(false);

        gridLayout_2->addWidget(unitsCombo, 0, 1, 1, 1);

        tab_widget->addTab(tab_spectra, QString());
        tab_appearance = new QWidget();
        tab_appearance->setObjectName(QString::fromUtf8("tab_appearance"));
        gridLayout_3 = new QGridLayout(tab_appearance);
        gridLayout_3->setObjectName(QString::fromUtf8("gridLayout_3"));
        cb_import = new QCheckBox(tab_appearance);
        cb_import->setObjectName(QString::fromUtf8("cb_import"));
        cb_import->setEnabled(false);

        gridLayout_3->addWidget(cb_import, 4, 2, 1, 1);

        push_import = new QPushButton(tab_appearance);
        push_import->setObjectName(QString::fromUtf8("push_import"));
        push_import->setEnabled(false);
        QSizePolicy sizePolicy1(QSizePolicy::Ignored, QSizePolicy::Fixed);
        sizePolicy1.setHorizontalStretch(0);
        sizePolicy1.setVerticalStretch(0);
        sizePolicy1.setHeightForWidth(push_import->sizePolicy().hasHeightForWidth());
        push_import->setSizePolicy(sizePolicy1);

        gridLayout_3->addWidget(push_import, 4, 3, 1, 1);

        push_colorImported = new QPushButton(tab_appearance);
        push_colorImported->setObjectName(QString::fromUtf8("push_colorImported"));
        push_colorImported->setEnabled(false);
        QSizePolicy sizePolicy2(QSizePolicy::Minimum, QSizePolicy::Fixed);
        sizePolicy2.setHorizontalStretch(0);
        sizePolicy2.setVerticalStretch(0);
        sizePolicy2.setHeightForWidth(push_colorImported->sizePolicy().hasHeightForWidth());
        push_colorImported->setSizePolicy(sizePolicy2);

        gridLayout_3->addWidget(push_colorImported, 4, 1, 1, 1);

        label_6 = new QLabel(tab_appearance);
        label_6->setObjectName(QString::fromUtf8("label_6"));
        QSizePolicy sizePolicy3(QSizePolicy::Fixed, QSizePolicy::Preferred);
        sizePolicy3.setHorizontalStretch(0);
        sizePolicy3.setVerticalStretch(0);
        sizePolicy3.setHeightForWidth(label_6->sizePolicy().hasHeightForWidth());
        label_6->setSizePolicy(sizePolicy3);

        gridLayout_3->addWidget(label_6, 2, 2, 1, 1);

        label_4 = new QLabel(tab_appearance);
        label_4->setObjectName(QString::fromUtf8("label_4"));

        gridLayout_3->addWidget(label_4, 4, 0, 1, 1);

        cb_calculate = new QCheckBox(tab_appearance);
        cb_calculate->setObjectName(QString::fromUtf8("cb_calculate"));
        cb_calculate->setEnabled(true);
        QSizePolicy sizePolicy4(QSizePolicy::Fixed, QSizePolicy::Fixed);
        sizePolicy4.setHorizontalStretch(0);
        sizePolicy4.setVerticalStretch(0);
        sizePolicy4.setHeightForWidth(cb_calculate->sizePolicy().hasHeightForWidth());
        cb_calculate->setSizePolicy(sizePolicy4);
        cb_calculate->setChecked(true);

        gridLayout_3->addWidget(cb_calculate, 3, 2, 1, 1);

        push_colorForeground = new QPushButton(tab_appearance);
        push_colorForeground->setObjectName(QString::fromUtf8("push_colorForeground"));
        sizePolicy1.setHeightForWidth(push_colorForeground->sizePolicy().hasHeightForWidth());
        push_colorForeground->setSizePolicy(sizePolicy1);

        gridLayout_3->addWidget(push_colorForeground, 2, 3, 1, 1);

        push_export = new QPushButton(tab_appearance);
        push_export->setObjectName(QString::fromUtf8("push_export"));
        push_export->setEnabled(false);
        sizePolicy1.setHeightForWidth(push_export->sizePolicy().hasHeightForWidth());
        push_export->setSizePolicy(sizePolicy1);

        gridLayout_3->addWidget(push_export, 3, 3, 1, 1);

        push_colorCalculated = new QPushButton(tab_appearance);
        push_colorCalculated->setObjectName(QString::fromUtf8("push_colorCalculated"));
        sizePolicy2.setHeightForWidth(push_colorCalculated->sizePolicy().hasHeightForWidth());
        push_colorCalculated->setSizePolicy(sizePolicy2);

        gridLayout_3->addWidget(push_colorCalculated, 3, 1, 1, 1);

        label_2 = new QLabel(tab_appearance);
        label_2->setObjectName(QString::fromUtf8("label_2"));
        sizePolicy4.setHeightForWidth(label_2->sizePolicy().hasHeightForWidth());
        label_2->setSizePolicy(sizePolicy4);

        gridLayout_3->addWidget(label_2, 2, 0, 1, 1);

        label_3 = new QLabel(tab_appearance);
        label_3->setObjectName(QString::fromUtf8("label_3"));
        sizePolicy4.setHeightForWidth(label_3->sizePolicy().hasHeightForWidth());
        label_3->setSizePolicy(sizePolicy4);

        gridLayout_3->addWidget(label_3, 3, 0, 1, 1);

        push_colorBackground = new QPushButton(tab_appearance);
        push_colorBackground->setObjectName(QString::fromUtf8("push_colorBackground"));
        sizePolicy2.setHeightForWidth(push_colorBackground->sizePolicy().hasHeightForWidth());
        push_colorBackground->setSizePolicy(sizePolicy2);

        gridLayout_3->addWidget(push_colorBackground, 2, 1, 1, 1);

        label = new QLabel(tab_appearance);
        label->setObjectName(QString::fromUtf8("label"));

        gridLayout_3->addWidget(label, 5, 2, 1, 1);

        fontSizeCombo = new QComboBox(tab_appearance);
        fontSizeCombo->addItem(QString());
        fontSizeCombo->addItem(QString());
        fontSizeCombo->addItem(QString());
        fontSizeCombo->addItem(QString());
        fontSizeCombo->addItem(QString());
        fontSizeCombo->setObjectName(QString::fromUtf8("fontSizeCombo"));
        fontSizeCombo->setEditable(true);

        gridLayout_3->addWidget(fontSizeCombo, 5, 3, 1, 1);

        label_5 = new QLabel(tab_appearance);
        label_5->setObjectName(QString::fromUtf8("label_5"));

        gridLayout_3->addWidget(label_5, 5, 0, 1, 1);

        lineWidthSpinBox = new QDoubleSpinBox(tab_appearance);
        lineWidthSpinBox->setObjectName(QString::fromUtf8("lineWidthSpinBox"));
        lineWidthSpinBox->setAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);
        lineWidthSpinBox->setDecimals(1);
        lineWidthSpinBox->setMinimum(1.000000000000000);
        lineWidthSpinBox->setMaximum(10.000000000000000);
        lineWidthSpinBox->setSingleStep(0.500000000000000);

        gridLayout_3->addWidget(lineWidthSpinBox, 5, 1, 1, 1);

        tab_widget->addTab(tab_appearance, QString());

        gridLayout->addWidget(tab_widget, 8, 0, 2, 5);

        combo_spectra = new QComboBox(SpectraDialog);
        combo_spectra->setObjectName(QString::fromUtf8("combo_spectra"));
        QSizePolicy sizePolicy5(QSizePolicy::Preferred, QSizePolicy::Fixed);
        sizePolicy5.setHorizontalStretch(0);
        sizePolicy5.setVerticalStretch(0);
        sizePolicy5.setHeightForWidth(combo_spectra->sizePolicy().hasHeightForWidth());
        combo_spectra->setSizePolicy(sizePolicy5);

        gridLayout->addWidget(combo_spectra, 5, 0, 1, 1);

        push_exportData = new QPushButton(SpectraDialog);
        push_exportData->setObjectName(QString::fromUtf8("push_exportData"));

        gridLayout->addWidget(push_exportData, 9, 8, 1, 1);

        pushButton = new QPushButton(SpectraDialog);
        pushButton->setObjectName(QString::fromUtf8("pushButton"));
        sizePolicy4.setHeightForWidth(pushButton->sizePolicy().hasHeightForWidth());
        pushButton->setSizePolicy(sizePolicy4);

        gridLayout->addWidget(pushButton, 5, 4, 1, 1);

        push_options = new QPushButton(SpectraDialog);
        push_options->setObjectName(QString::fromUtf8("push_options"));
        sizePolicy4.setHeightForWidth(push_options->sizePolicy().hasHeightForWidth());
        push_options->setSizePolicy(sizePolicy4);

        gridLayout->addWidget(push_options, 5, 3, 1, 1);

        dataTable = new QTableWidget(SpectraDialog);
        if (dataTable->columnCount() < 2)
            dataTable->setColumnCount(2);
        QTableWidgetItem *__qtablewidgetitem = new QTableWidgetItem();
        dataTable->setHorizontalHeaderItem(0, __qtablewidgetitem);
        QTableWidgetItem *__qtablewidgetitem1 = new QTableWidgetItem();
        dataTable->setHorizontalHeaderItem(1, __qtablewidgetitem1);
        dataTable->setObjectName(QString::fromUtf8("dataTable"));
        QSizePolicy sizePolicy6(QSizePolicy::Fixed, QSizePolicy::Expanding);
        sizePolicy6.setHorizontalStretch(0);
        sizePolicy6.setVerticalStretch(0);
        sizePolicy6.setHeightForWidth(dataTable->sizePolicy().hasHeightForWidth());
        dataTable->setSizePolicy(sizePolicy6);
        dataTable->setMinimumSize(QSize(160, 0));
        dataTable->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        dataTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
        dataTable->setAlternatingRowColors(true);
        dataTable->setSelectionMode(QAbstractItemView::SingleSelection);
        dataTable->setSelectionBehavior(QAbstractItemView::SelectRows);
        dataTable->setSortingEnabled(true);
        dataTable->horizontalHeader()->setVisible(true);
        dataTable->horizontalHeader()->setCascadingSectionResizes(false);
        dataTable->horizontalHeader()->setHighlightSections(false);
        dataTable->verticalHeader()->setVisible(true);

        gridLayout->addWidget(dataTable, 0, 8, 9, 1);

        plot = new Avogadro::QtGui::ChartWidget(SpectraDialog);
        plot->setObjectName(QString::fromUtf8("plot"));
        QSizePolicy sizePolicy7(QSizePolicy::Preferred, QSizePolicy::Expanding);
        sizePolicy7.setHorizontalStretch(0);
        sizePolicy7.setVerticalStretch(0);
        sizePolicy7.setHeightForWidth(plot->sizePolicy().hasHeightForWidth());
        plot->setSizePolicy(sizePolicy7);
        plot->setMinimumSize(QSize(500, 210));
        plot->setBaseSize(QSize(800, 600));
        plot->setCursor(QCursor(Qt::CrossCursor));

        gridLayout->addWidget(plot, 0, 0, 1, 5);

        push_loadSpectra = new QPushButton(SpectraDialog);
        push_loadSpectra->setObjectName(QString::fromUtf8("push_loadSpectra"));
        push_loadSpectra->setEnabled(false);
        sizePolicy4.setHeightForWidth(push_loadSpectra->sizePolicy().hasHeightForWidth());
        push_loadSpectra->setSizePolicy(sizePolicy4);

        gridLayout->addWidget(push_loadSpectra, 5, 2, 1, 1);

        elementCombo = new QComboBox(SpectraDialog);
        elementCombo->addItem(QString::fromUtf8("\302\271H"));
        elementCombo->addItem(QString::fromUtf8("\302\271\302\263C"));
        elementCombo->setObjectName(QString::fromUtf8("elementCombo"));

        gridLayout->addWidget(elementCombo, 5, 1, 1, 1);

        QWidget::setTabOrder(combo_spectra, push_loadSpectra);
        QWidget::setTabOrder(push_loadSpectra, push_options);
        QWidget::setTabOrder(push_options, scaleSpinBox);
        QWidget::setTabOrder(scaleSpinBox, offsetSpinBox);
        QWidget::setTabOrder(offsetSpinBox, peakWidth);
        QWidget::setTabOrder(peakWidth, peakThreshold);
        QWidget::setTabOrder(peakThreshold, xAxisMinimum);
        QWidget::setTabOrder(xAxisMinimum, xAxisMaximum);
        QWidget::setTabOrder(xAxisMaximum, yAxisMinimum);
        QWidget::setTabOrder(yAxisMinimum, yAxisMaximum);
        QWidget::setTabOrder(yAxisMaximum, push_colorBackground);
        QWidget::setTabOrder(push_colorBackground, push_colorForeground);
        QWidget::setTabOrder(push_colorForeground, push_colorCalculated);
        QWidget::setTabOrder(push_colorCalculated, cb_calculate);
        QWidget::setTabOrder(cb_calculate, push_export);
        QWidget::setTabOrder(push_export, push_colorImported);
        QWidget::setTabOrder(push_colorImported, cb_import);
        QWidget::setTabOrder(cb_import, push_import);
        QWidget::setTabOrder(push_import, lineWidthSpinBox);
        QWidget::setTabOrder(lineWidthSpinBox, fontSizeCombo);
        QWidget::setTabOrder(fontSizeCombo, dataTable);
        QWidget::setTabOrder(dataTable, push_exportData);
        QWidget::setTabOrder(push_exportData, pushButton);
        QWidget::setTabOrder(pushButton, tab_widget);

        retranslateUi(SpectraDialog);
        QObject::connect(pushButton, SIGNAL(clicked()), SpectraDialog, SLOT(accept()));

        tab_widget->setCurrentIndex(0);


        QMetaObject::connectSlotsByName(SpectraDialog);
    } // setupUi

    void retranslateUi(QDialog *SpectraDialog)
    {
        SpectraDialog->setWindowTitle(QCoreApplication::translate("SpectraDialog", "Spectra Visualization", nullptr));
        label_11->setText(QCoreApplication::translate("SpectraDialog", "Scale Factor:", nullptr));
        label_7->setText(QCoreApplication::translate("SpectraDialog", "X-Axis Minimum:", nullptr));
        label_9->setText(QCoreApplication::translate("SpectraDialog", "X-Axis Maximum:", nullptr));
        label_12->setText(QCoreApplication::translate("SpectraDialog", "Offset:", nullptr));
        label_10->setText(QCoreApplication::translate("SpectraDialog", "Y-Axis Maximum:", nullptr));
        label_8->setText(QCoreApplication::translate("SpectraDialog", "Y-Axis Minimum:", nullptr));
        label_13->setText(QCoreApplication::translate("SpectraDialog", "Peak Width:", nullptr));
        label_27->setText(QCoreApplication::translate("SpectraDialog", "Peak Threshold:", nullptr));
        unitsLabel->setText(QCoreApplication::translate("SpectraDialog", "Units:", nullptr));
        tab_widget->setTabText(tab_widget->indexOf(tab_spectra), QCoreApplication::translate("SpectraDialog", "Spectra", nullptr));
        cb_import->setText(QCoreApplication::translate("SpectraDialog", "Show", nullptr));
#if QT_CONFIG(tooltip)
        push_import->setToolTip(QCoreApplication::translate("SpectraDialog", "Imports a tsv of experimental spectra to overlay on the plot.", nullptr));
#endif // QT_CONFIG(tooltip)
        push_import->setText(QCoreApplication::translate("SpectraDialog", "&Import\342\200\246", nullptr));
        push_colorImported->setText(QCoreApplication::translate("SpectraDialog", "Set Color\342\200\246", nullptr));
        label_6->setText(QCoreApplication::translate("SpectraDialog", "Axis:", nullptr));
        label_4->setText(QCoreApplication::translate("SpectraDialog", "Imported Spectra:", nullptr));
        cb_calculate->setText(QCoreApplication::translate("SpectraDialog", "Show", nullptr));
        push_colorForeground->setText(QCoreApplication::translate("SpectraDialog", "Set Color\342\200\246", nullptr));
        push_export->setText(QCoreApplication::translate("SpectraDialog", "&Export\342\200\246", nullptr));
        push_colorCalculated->setText(QCoreApplication::translate("SpectraDialog", "Set Color\342\200\246", nullptr));
        label_2->setText(QCoreApplication::translate("SpectraDialog", "Background:", nullptr));
        label_3->setText(QCoreApplication::translate("SpectraDialog", "Calculated Spectra:", nullptr));
        push_colorBackground->setText(QCoreApplication::translate("SpectraDialog", "Set Color\342\200\246", nullptr));
        label->setText(QCoreApplication::translate("SpectraDialog", "Font Size:", nullptr));
        fontSizeCombo->setItemText(0, QCoreApplication::translate("SpectraDialog", "10", nullptr));
        fontSizeCombo->setItemText(1, QCoreApplication::translate("SpectraDialog", "12", nullptr));
        fontSizeCombo->setItemText(2, QCoreApplication::translate("SpectraDialog", "14", nullptr));
        fontSizeCombo->setItemText(3, QCoreApplication::translate("SpectraDialog", "16", nullptr));
        fontSizeCombo->setItemText(4, QCoreApplication::translate("SpectraDialog", "18", nullptr));

#if QT_CONFIG(tooltip)
        label_5->setToolTip(QString());
#endif // QT_CONFIG(tooltip)
        label_5->setText(QCoreApplication::translate("SpectraDialog", "Line Width:", "Size in pixels of the line drawing the spectra"));
        tab_widget->setTabText(tab_widget->indexOf(tab_appearance), QCoreApplication::translate("SpectraDialog", "&Appearance", nullptr));
        push_exportData->setText(QCoreApplication::translate("SpectraDialog", "Export Data", nullptr));
        pushButton->setText(QCoreApplication::translate("SpectraDialog", "&Close", nullptr));
        push_options->setText(QCoreApplication::translate("SpectraDialog", "&Options\342\200\246", nullptr));
        QTableWidgetItem *___qtablewidgetitem = dataTable->horizontalHeaderItem(0);
        ___qtablewidgetitem->setText(QCoreApplication::translate("SpectraDialog", "x", nullptr));
        QTableWidgetItem *___qtablewidgetitem1 = dataTable->horizontalHeaderItem(1);
        ___qtablewidgetitem1->setText(QCoreApplication::translate("SpectraDialog", "y", nullptr));
#if QT_CONFIG(tooltip)
        plot->setToolTip(QCoreApplication::translate("SpectraDialog", "Controls:\n"
"Double left click: Restore default axis limits\n"
"Right click + drag: Move plot\n"
"Middle click + drag: Zoom to region\n"
"Scroll wheel: Zoom to cursor", nullptr));
#endif // QT_CONFIG(tooltip)
        push_loadSpectra->setText(QCoreApplication::translate("SpectraDialog", "&Load data\342\200\246", nullptr));

    } // retranslateUi

};

namespace Ui {
    class SpectraDialog: public Ui_SpectraDialog {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_SPECTRADIALOG_H
