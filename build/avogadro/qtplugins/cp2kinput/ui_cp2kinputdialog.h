/********************************************************************************
** Form generated from reading UI file 'cp2kinputdialog.ui'
**
** Created by: Qt User Interface Compiler version 5.15.17
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_CP2KINPUTDIALOG_H
#define UI_CP2KINPUTDIALOG_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QDialog>
#include <QtWidgets/QDoubleSpinBox>
#include <QtWidgets/QFormLayout>
#include <QtWidgets/QGridLayout>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QSpinBox>
#include <QtWidgets/QTabWidget>
#include <QtWidgets/QTextEdit>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_Cp2kInputDialog
{
public:
    QGridLayout *gridLayout;
    QHBoxLayout *hboxLayout;
    QPushButton *resetAllButton;
    QPushButton *defaultsButton;
    QSpacerItem *spacerItem;
    QPushButton *computeButton;
    QPushButton *generateButton;
    QPushButton *closeButton;
    QTextEdit *previewText;
    QTabWidget *modeTab;
    QWidget *basicWidget;
    QFormLayout *formLayout_3;
    QLabel *label_8;
    QLineEdit *titleEdit;
    QLabel *label_4;
    QLineEdit *baseNameEdit;
    QLabel *label;
    QHBoxLayout *hboxLayout1;
    QComboBox *calculateCombo;
    QSpacerItem *spacerItem1;
    QLabel *label_5;
    QHBoxLayout *hboxLayout2;
    QComboBox *methodCombo;
    QSpacerItem *spacerItem2;
    QLabel *label_2;
    QHBoxLayout *hboxLayout3;
    QComboBox *basisCombo;
    QLabel *label_9;
    QComboBox *functionalCombo;
    QSpacerItem *spacerItem3;
    QSpacerItem *spacerItem4;
    QWidget *tab;
    QFormLayout *formLayout_2;
    QLabel *emaxSplineSpin_label;
    QHBoxLayout *horizontalLayout_6;
    QDoubleSpinBox *emaxSplineSpin;
    QSpacerItem *horizontalSpacer_3;
    QLabel *label_10;
    QHBoxLayout *horizontalLayout_5;
    QDoubleSpinBox *rcutnbSplineSpin;
    QSpacerItem *horizontalSpacer_4;
    QLabel *label_7;
    QHBoxLayout *horizontalLayout_7;
    QComboBox *ewaldtypeCombo;
    QSpacerItem *horizontalSpacer_5;
    QLabel *label_11;
    QHBoxLayout *horizontalLayout_8;
    QDoubleSpinBox *ewaldalphaSpin;
    QSpacerItem *horizontalSpacer_6;
    QLabel *label_23;
    QHBoxLayout *horizontalLayout_14;
    QSpinBox *ewaldgmaxSpin;
    QSpacerItem *horizontalSpacer_7;
    QWidget *tab_2;
    QFormLayout *formLayout;
    QLabel *LSD_label;
    QHBoxLayout *horizontalLayout_28;
    QCheckBox *lsdcheckBox;
    QSpacerItem *horizontalSpacer_26;
    QLabel *label_12;
    QHBoxLayout *horizontalLayout_29;
    QSpinBox *maxscfspinBox;
    QSpacerItem *horizontalSpacer_27;
    QLabel *label_14;
    QHBoxLayout *horizontalLayout_25;
    QDoubleSpinBox *epsscfSpinBox;
    QSpacerItem *horizontalSpacer_23;
    QLabel *label_13;
    QHBoxLayout *horizontalLayout_26;
    QComboBox *scfguessComboBox;
    QSpacerItem *horizontalSpacer_24;
    QLabel *label_24;
    QHBoxLayout *horizontalLayout_27;
    QSpinBox *outerMaxscfSpinBox;
    QSpacerItem *horizontalSpacer_25;
    QLabel *label_25;
    QHBoxLayout *horizontalLayout_30;
    QDoubleSpinBox *outerEpsscfSpinBox;
    QSpacerItem *horizontalSpacer_28;
    QLabel *label_26;
    QHBoxLayout *horizontalLayout_31;
    QComboBox *otminimizerComboBox;
    QSpacerItem *horizontalSpacer_29;

    void setupUi(QDialog *Cp2kInputDialog)
    {
        if (Cp2kInputDialog->objectName().isEmpty())
            Cp2kInputDialog->setObjectName(QString::fromUtf8("Cp2kInputDialog"));
        Cp2kInputDialog->resize(651, 566);
        gridLayout = new QGridLayout(Cp2kInputDialog);
        gridLayout->setObjectName(QString::fromUtf8("gridLayout"));
        hboxLayout = new QHBoxLayout();
        hboxLayout->setObjectName(QString::fromUtf8("hboxLayout"));
        resetAllButton = new QPushButton(Cp2kInputDialog);
        resetAllButton->setObjectName(QString::fromUtf8("resetAllButton"));

        hboxLayout->addWidget(resetAllButton);

        defaultsButton = new QPushButton(Cp2kInputDialog);
        defaultsButton->setObjectName(QString::fromUtf8("defaultsButton"));

        hboxLayout->addWidget(defaultsButton);

        spacerItem = new QSpacerItem(10, 20, QSizePolicy::MinimumExpanding, QSizePolicy::Minimum);

        hboxLayout->addItem(spacerItem);

        computeButton = new QPushButton(Cp2kInputDialog);
        computeButton->setObjectName(QString::fromUtf8("computeButton"));

        hboxLayout->addWidget(computeButton);

        generateButton = new QPushButton(Cp2kInputDialog);
        generateButton->setObjectName(QString::fromUtf8("generateButton"));

        hboxLayout->addWidget(generateButton);

        closeButton = new QPushButton(Cp2kInputDialog);
        closeButton->setObjectName(QString::fromUtf8("closeButton"));

        hboxLayout->addWidget(closeButton);


        gridLayout->addLayout(hboxLayout, 6, 0, 1, 1);

        previewText = new QTextEdit(Cp2kInputDialog);
        previewText->setObjectName(QString::fromUtf8("previewText"));
        QSizePolicy sizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
        sizePolicy.setHorizontalStretch(0);
        sizePolicy.setVerticalStretch(1);
        sizePolicy.setHeightForWidth(previewText->sizePolicy().hasHeightForWidth());
        previewText->setSizePolicy(sizePolicy);

        gridLayout->addWidget(previewText, 5, 0, 1, 1);

        modeTab = new QTabWidget(Cp2kInputDialog);
        modeTab->setObjectName(QString::fromUtf8("modeTab"));
        modeTab->setMinimumSize(QSize(0, 300));
        basicWidget = new QWidget();
        basicWidget->setObjectName(QString::fromUtf8("basicWidget"));
        formLayout_3 = new QFormLayout(basicWidget);
        formLayout_3->setObjectName(QString::fromUtf8("formLayout_3"));
        label_8 = new QLabel(basicWidget);
        label_8->setObjectName(QString::fromUtf8("label_8"));

        formLayout_3->setWidget(0, QFormLayout::LabelRole, label_8);

        titleEdit = new QLineEdit(basicWidget);
        titleEdit->setObjectName(QString::fromUtf8("titleEdit"));

        formLayout_3->setWidget(0, QFormLayout::FieldRole, titleEdit);

        label_4 = new QLabel(basicWidget);
        label_4->setObjectName(QString::fromUtf8("label_4"));

        formLayout_3->setWidget(1, QFormLayout::LabelRole, label_4);

        baseNameEdit = new QLineEdit(basicWidget);
        baseNameEdit->setObjectName(QString::fromUtf8("baseNameEdit"));

        formLayout_3->setWidget(1, QFormLayout::FieldRole, baseNameEdit);

        label = new QLabel(basicWidget);
        label->setObjectName(QString::fromUtf8("label"));
        label->setAlignment(Qt::AlignLeading|Qt::AlignLeft|Qt::AlignVCenter);

        formLayout_3->setWidget(2, QFormLayout::LabelRole, label);

        hboxLayout1 = new QHBoxLayout();
        hboxLayout1->setObjectName(QString::fromUtf8("hboxLayout1"));
        calculateCombo = new QComboBox(basicWidget);
        calculateCombo->setObjectName(QString::fromUtf8("calculateCombo"));

        hboxLayout1->addWidget(calculateCombo);

        spacerItem1 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        hboxLayout1->addItem(spacerItem1);


        formLayout_3->setLayout(2, QFormLayout::FieldRole, hboxLayout1);

        label_5 = new QLabel(basicWidget);
        label_5->setObjectName(QString::fromUtf8("label_5"));
        label_5->setAlignment(Qt::AlignLeading|Qt::AlignLeft|Qt::AlignVCenter);

        formLayout_3->setWidget(3, QFormLayout::LabelRole, label_5);

        hboxLayout2 = new QHBoxLayout();
        hboxLayout2->setObjectName(QString::fromUtf8("hboxLayout2"));
        methodCombo = new QComboBox(basicWidget);
        methodCombo->setObjectName(QString::fromUtf8("methodCombo"));

        hboxLayout2->addWidget(methodCombo);

        spacerItem2 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        hboxLayout2->addItem(spacerItem2);


        formLayout_3->setLayout(3, QFormLayout::FieldRole, hboxLayout2);

        label_2 = new QLabel(basicWidget);
        label_2->setObjectName(QString::fromUtf8("label_2"));
        label_2->setAlignment(Qt::AlignLeading|Qt::AlignLeft|Qt::AlignVCenter);

        formLayout_3->setWidget(4, QFormLayout::LabelRole, label_2);

        hboxLayout3 = new QHBoxLayout();
        hboxLayout3->setObjectName(QString::fromUtf8("hboxLayout3"));
        basisCombo = new QComboBox(basicWidget);
        basisCombo->setObjectName(QString::fromUtf8("basisCombo"));

        hboxLayout3->addWidget(basisCombo);

        label_9 = new QLabel(basicWidget);
        label_9->setObjectName(QString::fromUtf8("label_9"));

        hboxLayout3->addWidget(label_9);

        functionalCombo = new QComboBox(basicWidget);
        functionalCombo->setObjectName(QString::fromUtf8("functionalCombo"));
#if QT_CONFIG(accessibility)
        functionalCombo->setAccessibleDescription(QString::fromUtf8(""));
#endif // QT_CONFIG(accessibility)

        hboxLayout3->addWidget(functionalCombo);

        spacerItem3 = new QSpacerItem(16, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        hboxLayout3->addItem(spacerItem3);


        formLayout_3->setLayout(4, QFormLayout::FieldRole, hboxLayout3);

        spacerItem4 = new QSpacerItem(20, 0, QSizePolicy::Minimum, QSizePolicy::Expanding);

        formLayout_3->setItem(5, QFormLayout::LabelRole, spacerItem4);

        modeTab->addTab(basicWidget, QString());
        tab = new QWidget();
        tab->setObjectName(QString::fromUtf8("tab"));
        formLayout_2 = new QFormLayout(tab);
        formLayout_2->setObjectName(QString::fromUtf8("formLayout_2"));
        emaxSplineSpin_label = new QLabel(tab);
        emaxSplineSpin_label->setObjectName(QString::fromUtf8("emaxSplineSpin_label"));

        formLayout_2->setWidget(0, QFormLayout::LabelRole, emaxSplineSpin_label);

        horizontalLayout_6 = new QHBoxLayout();
        horizontalLayout_6->setObjectName(QString::fromUtf8("horizontalLayout_6"));
        emaxSplineSpin = new QDoubleSpinBox(tab);
        emaxSplineSpin->setObjectName(QString::fromUtf8("emaxSplineSpin"));
        emaxSplineSpin->setDecimals(6);
        emaxSplineSpin->setMinimum(-99.000000000000000);
        emaxSplineSpin->setSingleStep(0.000010000000000);
        emaxSplineSpin->setValue(0.000000000000000);

        horizontalLayout_6->addWidget(emaxSplineSpin);

        horizontalSpacer_3 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_6->addItem(horizontalSpacer_3);


        formLayout_2->setLayout(0, QFormLayout::FieldRole, horizontalLayout_6);

        label_10 = new QLabel(tab);
        label_10->setObjectName(QString::fromUtf8("label_10"));

        formLayout_2->setWidget(1, QFormLayout::LabelRole, label_10);

        horizontalLayout_5 = new QHBoxLayout();
        horizontalLayout_5->setObjectName(QString::fromUtf8("horizontalLayout_5"));
        rcutnbSplineSpin = new QDoubleSpinBox(tab);
        rcutnbSplineSpin->setObjectName(QString::fromUtf8("rcutnbSplineSpin"));
        rcutnbSplineSpin->setDecimals(6);
        rcutnbSplineSpin->setMinimum(-99.000000000000000);
        rcutnbSplineSpin->setValue(-1.000000000000000);

        horizontalLayout_5->addWidget(rcutnbSplineSpin);

        horizontalSpacer_4 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_5->addItem(horizontalSpacer_4);


        formLayout_2->setLayout(1, QFormLayout::FieldRole, horizontalLayout_5);

        label_7 = new QLabel(tab);
        label_7->setObjectName(QString::fromUtf8("label_7"));

        formLayout_2->setWidget(2, QFormLayout::LabelRole, label_7);

        horizontalLayout_7 = new QHBoxLayout();
        horizontalLayout_7->setObjectName(QString::fromUtf8("horizontalLayout_7"));
        ewaldtypeCombo = new QComboBox(tab);
        ewaldtypeCombo->setObjectName(QString::fromUtf8("ewaldtypeCombo"));

        horizontalLayout_7->addWidget(ewaldtypeCombo);

        horizontalSpacer_5 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_7->addItem(horizontalSpacer_5);


        formLayout_2->setLayout(2, QFormLayout::FieldRole, horizontalLayout_7);

        label_11 = new QLabel(tab);
        label_11->setObjectName(QString::fromUtf8("label_11"));

        formLayout_2->setWidget(3, QFormLayout::LabelRole, label_11);

        horizontalLayout_8 = new QHBoxLayout();
        horizontalLayout_8->setObjectName(QString::fromUtf8("horizontalLayout_8"));
        ewaldalphaSpin = new QDoubleSpinBox(tab);
        ewaldalphaSpin->setObjectName(QString::fromUtf8("ewaldalphaSpin"));
        ewaldalphaSpin->setMinimum(-99.000000000000000);

        horizontalLayout_8->addWidget(ewaldalphaSpin);

        horizontalSpacer_6 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_8->addItem(horizontalSpacer_6);


        formLayout_2->setLayout(3, QFormLayout::FieldRole, horizontalLayout_8);

        label_23 = new QLabel(tab);
        label_23->setObjectName(QString::fromUtf8("label_23"));

        formLayout_2->setWidget(4, QFormLayout::LabelRole, label_23);

        horizontalLayout_14 = new QHBoxLayout();
        horizontalLayout_14->setObjectName(QString::fromUtf8("horizontalLayout_14"));
        ewaldgmaxSpin = new QSpinBox(tab);
        ewaldgmaxSpin->setObjectName(QString::fromUtf8("ewaldgmaxSpin"));
        ewaldgmaxSpin->setMaximum(1000);
        ewaldgmaxSpin->setValue(10);

        horizontalLayout_14->addWidget(ewaldgmaxSpin);

        horizontalSpacer_7 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_14->addItem(horizontalSpacer_7);


        formLayout_2->setLayout(4, QFormLayout::FieldRole, horizontalLayout_14);

        modeTab->addTab(tab, QString());
        tab_2 = new QWidget();
        tab_2->setObjectName(QString::fromUtf8("tab_2"));
        formLayout = new QFormLayout(tab_2);
        formLayout->setObjectName(QString::fromUtf8("formLayout"));
        LSD_label = new QLabel(tab_2);
        LSD_label->setObjectName(QString::fromUtf8("LSD_label"));

        formLayout->setWidget(0, QFormLayout::LabelRole, LSD_label);

        horizontalLayout_28 = new QHBoxLayout();
        horizontalLayout_28->setObjectName(QString::fromUtf8("horizontalLayout_28"));
        lsdcheckBox = new QCheckBox(tab_2);
        lsdcheckBox->setObjectName(QString::fromUtf8("lsdcheckBox"));

        horizontalLayout_28->addWidget(lsdcheckBox);

        horizontalSpacer_26 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_28->addItem(horizontalSpacer_26);


        formLayout->setLayout(0, QFormLayout::FieldRole, horizontalLayout_28);

        label_12 = new QLabel(tab_2);
        label_12->setObjectName(QString::fromUtf8("label_12"));

        formLayout->setWidget(1, QFormLayout::LabelRole, label_12);

        horizontalLayout_29 = new QHBoxLayout();
        horizontalLayout_29->setObjectName(QString::fromUtf8("horizontalLayout_29"));
        maxscfspinBox = new QSpinBox(tab_2);
        maxscfspinBox->setObjectName(QString::fromUtf8("maxscfspinBox"));
        maxscfspinBox->setMaximum(999);
        maxscfspinBox->setValue(50);

        horizontalLayout_29->addWidget(maxscfspinBox);

        horizontalSpacer_27 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_29->addItem(horizontalSpacer_27);


        formLayout->setLayout(1, QFormLayout::FieldRole, horizontalLayout_29);

        label_14 = new QLabel(tab_2);
        label_14->setObjectName(QString::fromUtf8("label_14"));

        formLayout->setWidget(2, QFormLayout::LabelRole, label_14);

        horizontalLayout_25 = new QHBoxLayout();
        horizontalLayout_25->setObjectName(QString::fromUtf8("horizontalLayout_25"));
        epsscfSpinBox = new QDoubleSpinBox(tab_2);
        epsscfSpinBox->setObjectName(QString::fromUtf8("epsscfSpinBox"));
        epsscfSpinBox->setDecimals(8);
        epsscfSpinBox->setValue(0.000010000000000);
        epsscfSpinBox->setSingleStep(0.000010000000000);

        horizontalLayout_25->addWidget(epsscfSpinBox);

        horizontalSpacer_23 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_25->addItem(horizontalSpacer_23);


        formLayout->setLayout(2, QFormLayout::FieldRole, horizontalLayout_25);

        label_13 = new QLabel(tab_2);
        label_13->setObjectName(QString::fromUtf8("label_13"));

        formLayout->setWidget(3, QFormLayout::LabelRole, label_13);

        horizontalLayout_26 = new QHBoxLayout();
        horizontalLayout_26->setObjectName(QString::fromUtf8("horizontalLayout_26"));
        scfguessComboBox = new QComboBox(tab_2);
        scfguessComboBox->setObjectName(QString::fromUtf8("scfguessComboBox"));

        horizontalLayout_26->addWidget(scfguessComboBox);

        horizontalSpacer_24 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_26->addItem(horizontalSpacer_24);


        formLayout->setLayout(3, QFormLayout::FieldRole, horizontalLayout_26);

        label_24 = new QLabel(tab_2);
        label_24->setObjectName(QString::fromUtf8("label_24"));

        formLayout->setWidget(4, QFormLayout::LabelRole, label_24);

        horizontalLayout_27 = new QHBoxLayout();
        horizontalLayout_27->setObjectName(QString::fromUtf8("horizontalLayout_27"));
        outerMaxscfSpinBox = new QSpinBox(tab_2);
        outerMaxscfSpinBox->setObjectName(QString::fromUtf8("outerMaxscfSpinBox"));
        outerMaxscfSpinBox->setMaximum(999);
        outerMaxscfSpinBox->setValue(50);

        horizontalLayout_27->addWidget(outerMaxscfSpinBox);

        horizontalSpacer_25 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_27->addItem(horizontalSpacer_25);


        formLayout->setLayout(4, QFormLayout::FieldRole, horizontalLayout_27);

        label_25 = new QLabel(tab_2);
        label_25->setObjectName(QString::fromUtf8("label_25"));

        formLayout->setWidget(5, QFormLayout::LabelRole, label_25);

        horizontalLayout_30 = new QHBoxLayout();
        horizontalLayout_30->setObjectName(QString::fromUtf8("horizontalLayout_30"));
        outerEpsscfSpinBox = new QDoubleSpinBox(tab_2);
        outerEpsscfSpinBox->setObjectName(QString::fromUtf8("outerEpsscfSpinBox"));
        outerEpsscfSpinBox->setDecimals(8);
        outerEpsscfSpinBox->setValue(0.000010000000000);
        outerEpsscfSpinBox->setSingleStep(0.000010000000000);

        horizontalLayout_30->addWidget(outerEpsscfSpinBox);

        horizontalSpacer_28 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_30->addItem(horizontalSpacer_28);


        formLayout->setLayout(5, QFormLayout::FieldRole, horizontalLayout_30);

        label_26 = new QLabel(tab_2);
        label_26->setObjectName(QString::fromUtf8("label_26"));

        formLayout->setWidget(6, QFormLayout::LabelRole, label_26);

        horizontalLayout_31 = new QHBoxLayout();
        horizontalLayout_31->setObjectName(QString::fromUtf8("horizontalLayout_31"));
        otminimizerComboBox = new QComboBox(tab_2);
        otminimizerComboBox->setObjectName(QString::fromUtf8("otminimizerComboBox"));

        horizontalLayout_31->addWidget(otminimizerComboBox);

        horizontalSpacer_29 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_31->addItem(horizontalSpacer_29);


        formLayout->setLayout(6, QFormLayout::FieldRole, horizontalLayout_31);

        modeTab->addTab(tab_2, QString());

        gridLayout->addWidget(modeTab, 0, 0, 1, 1);

#if QT_CONFIG(shortcut)
        label_8->setBuddy(titleEdit);
        label->setBuddy(calculateCombo);
        label_5->setBuddy(methodCombo);
        label_2->setBuddy(basisCombo);
#endif // QT_CONFIG(shortcut)
        QWidget::setTabOrder(calculateCombo, basisCombo);
        QWidget::setTabOrder(basisCombo, functionalCombo);
        QWidget::setTabOrder(functionalCombo, methodCombo);
        QWidget::setTabOrder(methodCombo, previewText);
        QWidget::setTabOrder(previewText, resetAllButton);
        QWidget::setTabOrder(resetAllButton, defaultsButton);
        QWidget::setTabOrder(defaultsButton, generateButton);
        QWidget::setTabOrder(generateButton, closeButton);

        retranslateUi(Cp2kInputDialog);

        modeTab->setCurrentIndex(0);


        QMetaObject::connectSlotsByName(Cp2kInputDialog);
    } // setupUi

    void retranslateUi(QDialog *Cp2kInputDialog)
    {
        Cp2kInputDialog->setWindowTitle(QCoreApplication::translate("Cp2kInputDialog", "CP2K Input", nullptr));
        resetAllButton->setText(QCoreApplication::translate("Cp2kInputDialog", "Reset All", nullptr));
        defaultsButton->setText(QCoreApplication::translate("Cp2kInputDialog", "Defaults", nullptr));
        computeButton->setText(QCoreApplication::translate("Cp2kInputDialog", "Submit Calculation\342\200\246", nullptr));
        generateButton->setText(QCoreApplication::translate("Cp2kInputDialog", "Save File\342\200\246", nullptr));
        closeButton->setText(QCoreApplication::translate("Cp2kInputDialog", "Close", nullptr));
        label_8->setText(QCoreApplication::translate("Cp2kInputDialog", "Title:", nullptr));
        label_4->setText(QCoreApplication::translate("Cp2kInputDialog", "Filename Base:", nullptr));
        baseNameEdit->setText(QString());
        baseNameEdit->setPlaceholderText(QCoreApplication::translate("Cp2kInputDialog", "job", nullptr));
        label->setText(QCoreApplication::translate("Cp2kInputDialog", "Calculate:", nullptr));
        label_5->setText(QCoreApplication::translate("Cp2kInputDialog", "Method:", nullptr));
        label_2->setText(QCoreApplication::translate("Cp2kInputDialog", "Basis set:", nullptr));
        label_9->setText(QCoreApplication::translate("Cp2kInputDialog", "Functional", nullptr));
        modeTab->setTabText(modeTab->indexOf(basicWidget), QCoreApplication::translate("Cp2kInputDialog", "&Basic Setup", nullptr));
        emaxSplineSpin_label->setText(QCoreApplication::translate("Cp2kInputDialog", "FF Emax Spline Spin", nullptr));
        label_10->setText(QCoreApplication::translate("Cp2kInputDialog", "FF RCUT NB", nullptr));
        label_7->setText(QCoreApplication::translate("Cp2kInputDialog", "Poisson EWALD type", nullptr));
        label_11->setText(QCoreApplication::translate("Cp2kInputDialog", "Poisson EWALD Alpha", nullptr));
        label_23->setText(QCoreApplication::translate("Cp2kInputDialog", "Poisson EWALD GMAX", nullptr));
        modeTab->setTabText(modeTab->indexOf(tab), QCoreApplication::translate("Cp2kInputDialog", "MM", nullptr));
        LSD_label->setText(QCoreApplication::translate("Cp2kInputDialog", "LSD", nullptr));
        lsdcheckBox->setText(QCoreApplication::translate("Cp2kInputDialog", "TRUE", nullptr));
        label_12->setText(QCoreApplication::translate("Cp2kInputDialog", "MAX SCF", nullptr));
        label_14->setText(QCoreApplication::translate("Cp2kInputDialog", "EPS SCF", nullptr));
        label_13->setText(QCoreApplication::translate("Cp2kInputDialog", "SCF GUESS", nullptr));
        label_24->setText(QCoreApplication::translate("Cp2kInputDialog", "OUTER MAX SCF", nullptr));
        label_25->setText(QCoreApplication::translate("Cp2kInputDialog", "OUTER EPS SCF", nullptr));
        label_26->setText(QCoreApplication::translate("Cp2kInputDialog", "OT T MINIMIZER", nullptr));
        modeTab->setTabText(modeTab->indexOf(tab_2), QCoreApplication::translate("Cp2kInputDialog", "QM", nullptr));
    } // retranslateUi

};

namespace Ui {
    class Cp2kInputDialog: public Ui_Cp2kInputDialog {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_CP2KINPUTDIALOG_H
