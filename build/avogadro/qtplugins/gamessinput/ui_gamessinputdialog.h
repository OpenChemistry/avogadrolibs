/********************************************************************************
** Form generated from reading UI file 'gamessinputdialog.ui'
**
** Created by: Qt User Interface Compiler version 5.15.17
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_GAMESSINPUTDIALOG_H
#define UI_GAMESSINPUTDIALOG_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QDialog>
#include <QtWidgets/QDoubleSpinBox>
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

class Ui_GamessInputDialog
{
public:
    QGridLayout *gridLayout;
    QTextEdit *previewText;
    QTabWidget *modeTab;
    QWidget *basicWidget;
    QGridLayout *gridLayout1;
    QHBoxLayout *horizontalLayout;
    QComboBox *chargeCombo;
    QSpacerItem *horizontalSpacer;
    QLabel *label_3;
    QLabel *label_12;
    QHBoxLayout *horizontalLayout_29;
    QSpinBox *maxscfspinBox;
    QSpacerItem *horizontalSpacer_27;
    QLabel *label_13;
    QHBoxLayout *horizontalLayout_25;
    QDoubleSpinBox *convergeSpinBox;
    QSpacerItem *horizontalSpacer_23;
    QLabel *label_5;
    QLabel *label_2;
    QLabel *label_8;
    QHBoxLayout *hboxLayout;
    QComboBox *multiplicityCombo;
    QSpacerItem *spacerItem;
    QHBoxLayout *hboxLayout1;
    QComboBox *calculateCombo;
    QSpacerItem *spacerItem1;
    QHBoxLayout *hboxLayout2;
    QComboBox *theoryCombo;
    QComboBox *basisCombo;
    QComboBox *DCVerCombo;
    QSpacerItem *spacerItem2;
    QLabel *label_6;
    QLineEdit *titleEdit;
    QHBoxLayout *hboxLayout3;
    QComboBox *stateCombo;
    QSpacerItem *spacerItem3;
    QLabel *label;
    QSpacerItem *spacerItem4;
    QLabel *label_4;
    QLineEdit *baseNameEdit;
    QHBoxLayout *hboxLayout4;
    QPushButton *resetAllButton;
    QPushButton *defaultsButton;
    QSpacerItem *spacerItem5;
    QPushButton *computeButton;
    QPushButton *generateButton;
    QPushButton *closeButton;

    void setupUi(QDialog *GamessInputDialog)
    {
        if (GamessInputDialog->objectName().isEmpty())
            GamessInputDialog->setObjectName(QString::fromUtf8("GamessInputDialog"));
        GamessInputDialog->resize(785, 660);
        gridLayout = new QGridLayout(GamessInputDialog);
        gridLayout->setObjectName(QString::fromUtf8("gridLayout"));
        previewText = new QTextEdit(GamessInputDialog);
        previewText->setObjectName(QString::fromUtf8("previewText"));
        QSizePolicy sizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
        sizePolicy.setHorizontalStretch(0);
        sizePolicy.setVerticalStretch(1);
        sizePolicy.setHeightForWidth(previewText->sizePolicy().hasHeightForWidth());
        previewText->setSizePolicy(sizePolicy);

        gridLayout->addWidget(previewText, 2, 0, 1, 1);

        modeTab = new QTabWidget(GamessInputDialog);
        modeTab->setObjectName(QString::fromUtf8("modeTab"));
        basicWidget = new QWidget();
        basicWidget->setObjectName(QString::fromUtf8("basicWidget"));
        gridLayout1 = new QGridLayout(basicWidget);
        gridLayout1->setObjectName(QString::fromUtf8("gridLayout1"));
        horizontalLayout = new QHBoxLayout();
        horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));
        chargeCombo = new QComboBox(basicWidget);
        chargeCombo->setObjectName(QString::fromUtf8("chargeCombo"));

        horizontalLayout->addWidget(chargeCombo);

        horizontalSpacer = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout->addItem(horizontalSpacer);


        gridLayout1->addLayout(horizontalLayout, 6, 2, 1, 1);

        label_3 = new QLabel(basicWidget);
        label_3->setObjectName(QString::fromUtf8("label_3"));
        label_3->setAlignment(Qt::AlignLeading|Qt::AlignLeft|Qt::AlignVCenter);

        gridLayout1->addWidget(label_3, 4, 0, 1, 1);

        label_12 = new QLabel(basicWidget);
        label_12->setObjectName(QString::fromUtf8("label_12"));

        gridLayout1->addWidget(label_12, 7, 0, 1, 1);

        horizontalLayout_29 = new QHBoxLayout();
        horizontalLayout_29->setObjectName(QString::fromUtf8("horizontalLayout_29"));
        maxscfspinBox = new QSpinBox(basicWidget);
        maxscfspinBox->setObjectName(QString::fromUtf8("maxscfspinBox"));
        maxscfspinBox->setMaximum(999);
        maxscfspinBox->setValue(50);

        horizontalLayout_29->addWidget(maxscfspinBox);

        horizontalSpacer_27 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_29->addItem(horizontalSpacer_27);


        gridLayout1->addLayout(horizontalLayout_29, 7, 2, 1, 1);

        label_13 = new QLabel(basicWidget);
        label_13->setObjectName(QString::fromUtf8("label_13"));

        gridLayout1->addWidget(label_13, 8, 0, 1, 1);

        horizontalLayout_25 = new QHBoxLayout();
        horizontalLayout_25->setObjectName(QString::fromUtf8("horizontalLayout_25"));
        convergeSpinBox = new QDoubleSpinBox(basicWidget);
        convergeSpinBox->setObjectName(QString::fromUtf8("convergeSpinBox"));
        convergeSpinBox->setDecimals(8);
        convergeSpinBox->setValue(0.000010000000000);
        convergeSpinBox->setSingleStep(0.000010000000000);

        horizontalLayout_25->addWidget(convergeSpinBox);

        horizontalSpacer_23 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_25->addItem(horizontalSpacer_23);


        gridLayout1->addLayout(horizontalLayout_25, 8, 2, 1, 1);

        label_5 = new QLabel(basicWidget);
        label_5->setObjectName(QString::fromUtf8("label_5"));
        label_5->setAlignment(Qt::AlignLeading|Qt::AlignLeft|Qt::AlignVCenter);

        gridLayout1->addWidget(label_5, 5, 0, 1, 1);

        label_2 = new QLabel(basicWidget);
        label_2->setObjectName(QString::fromUtf8("label_2"));
        label_2->setAlignment(Qt::AlignLeading|Qt::AlignLeft|Qt::AlignVCenter);

        gridLayout1->addWidget(label_2, 3, 0, 1, 1);

        label_8 = new QLabel(basicWidget);
        label_8->setObjectName(QString::fromUtf8("label_8"));

        gridLayout1->addWidget(label_8, 0, 0, 1, 1);

        hboxLayout = new QHBoxLayout();
        hboxLayout->setObjectName(QString::fromUtf8("hboxLayout"));
        multiplicityCombo = new QComboBox(basicWidget);
        multiplicityCombo->setObjectName(QString::fromUtf8("multiplicityCombo"));

        hboxLayout->addWidget(multiplicityCombo);

        spacerItem = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        hboxLayout->addItem(spacerItem);


        gridLayout1->addLayout(hboxLayout, 5, 2, 1, 1);

        hboxLayout1 = new QHBoxLayout();
        hboxLayout1->setObjectName(QString::fromUtf8("hboxLayout1"));
        calculateCombo = new QComboBox(basicWidget);
        calculateCombo->setObjectName(QString::fromUtf8("calculateCombo"));

        hboxLayout1->addWidget(calculateCombo);

        spacerItem1 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        hboxLayout1->addItem(spacerItem1);


        gridLayout1->addLayout(hboxLayout1, 2, 2, 1, 1);

        hboxLayout2 = new QHBoxLayout();
        hboxLayout2->setObjectName(QString::fromUtf8("hboxLayout2"));
        theoryCombo = new QComboBox(basicWidget);
        theoryCombo->setObjectName(QString::fromUtf8("theoryCombo"));

        hboxLayout2->addWidget(theoryCombo);

        basisCombo = new QComboBox(basicWidget);
        basisCombo->setObjectName(QString::fromUtf8("basisCombo"));
#if QT_CONFIG(accessibility)
        basisCombo->setAccessibleDescription(QString::fromUtf8(""));
#endif // QT_CONFIG(accessibility)

        hboxLayout2->addWidget(basisCombo);

        DCVerCombo = new QComboBox(basicWidget);
        DCVerCombo->setObjectName(QString::fromUtf8("DCVerCombo"));
#if QT_CONFIG(accessibility)
        DCVerCombo->setAccessibleDescription(QString::fromUtf8(""));
#endif // QT_CONFIG(accessibility)

        hboxLayout2->addWidget(DCVerCombo);

        spacerItem2 = new QSpacerItem(16, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        hboxLayout2->addItem(spacerItem2);


        gridLayout1->addLayout(hboxLayout2, 3, 2, 1, 1);

        label_6 = new QLabel(basicWidget);
        label_6->setObjectName(QString::fromUtf8("label_6"));

        gridLayout1->addWidget(label_6, 6, 0, 1, 1);

        titleEdit = new QLineEdit(basicWidget);
        titleEdit->setObjectName(QString::fromUtf8("titleEdit"));

        gridLayout1->addWidget(titleEdit, 0, 2, 1, 1);

        hboxLayout3 = new QHBoxLayout();
        hboxLayout3->setObjectName(QString::fromUtf8("hboxLayout3"));
        stateCombo = new QComboBox(basicWidget);
        stateCombo->setObjectName(QString::fromUtf8("stateCombo"));

        hboxLayout3->addWidget(stateCombo);

        spacerItem3 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        hboxLayout3->addItem(spacerItem3);


        gridLayout1->addLayout(hboxLayout3, 4, 2, 1, 1);

        label = new QLabel(basicWidget);
        label->setObjectName(QString::fromUtf8("label"));
        label->setAlignment(Qt::AlignLeading|Qt::AlignLeft|Qt::AlignVCenter);

        gridLayout1->addWidget(label, 2, 0, 1, 1);

        spacerItem4 = new QSpacerItem(20, 0, QSizePolicy::Minimum, QSizePolicy::Expanding);

        gridLayout1->addItem(spacerItem4, 7, 0, 1, 1);

        label_4 = new QLabel(basicWidget);
        label_4->setObjectName(QString::fromUtf8("label_4"));

        gridLayout1->addWidget(label_4, 1, 0, 1, 1);

        baseNameEdit = new QLineEdit(basicWidget);
        baseNameEdit->setObjectName(QString::fromUtf8("baseNameEdit"));

        gridLayout1->addWidget(baseNameEdit, 1, 2, 1, 1);

        modeTab->addTab(basicWidget, QString());

        gridLayout->addWidget(modeTab, 0, 0, 1, 1);

        hboxLayout4 = new QHBoxLayout();
        hboxLayout4->setObjectName(QString::fromUtf8("hboxLayout4"));
        resetAllButton = new QPushButton(GamessInputDialog);
        resetAllButton->setObjectName(QString::fromUtf8("resetAllButton"));

        hboxLayout4->addWidget(resetAllButton);

        defaultsButton = new QPushButton(GamessInputDialog);
        defaultsButton->setObjectName(QString::fromUtf8("defaultsButton"));

        hboxLayout4->addWidget(defaultsButton);

        spacerItem5 = new QSpacerItem(10, 20, QSizePolicy::MinimumExpanding, QSizePolicy::Minimum);

        hboxLayout4->addItem(spacerItem5);

        computeButton = new QPushButton(GamessInputDialog);
        computeButton->setObjectName(QString::fromUtf8("computeButton"));

        hboxLayout4->addWidget(computeButton);

        generateButton = new QPushButton(GamessInputDialog);
        generateButton->setObjectName(QString::fromUtf8("generateButton"));

        hboxLayout4->addWidget(generateButton);

        closeButton = new QPushButton(GamessInputDialog);
        closeButton->setObjectName(QString::fromUtf8("closeButton"));

        hboxLayout4->addWidget(closeButton);


        gridLayout->addLayout(hboxLayout4, 3, 0, 1, 1);

#if QT_CONFIG(shortcut)
        label_3->setBuddy(stateCombo);
        label_5->setBuddy(multiplicityCombo);
        label_2->setBuddy(theoryCombo);
        label_8->setBuddy(titleEdit);
        label_6->setBuddy(chargeCombo);
        label->setBuddy(calculateCombo);
#endif // QT_CONFIG(shortcut)
        QWidget::setTabOrder(modeTab, titleEdit);
        QWidget::setTabOrder(titleEdit, calculateCombo);
        QWidget::setTabOrder(calculateCombo, theoryCombo);
        QWidget::setTabOrder(theoryCombo, basisCombo);
        QWidget::setTabOrder(basisCombo, stateCombo);
        QWidget::setTabOrder(stateCombo, multiplicityCombo);
        QWidget::setTabOrder(multiplicityCombo, chargeCombo);
        QWidget::setTabOrder(chargeCombo, previewText);
        QWidget::setTabOrder(previewText, resetAllButton);
        QWidget::setTabOrder(resetAllButton, defaultsButton);
        QWidget::setTabOrder(defaultsButton, generateButton);
        QWidget::setTabOrder(generateButton, closeButton);

        retranslateUi(GamessInputDialog);

        modeTab->setCurrentIndex(0);


        QMetaObject::connectSlotsByName(GamessInputDialog);
    } // setupUi

    void retranslateUi(QDialog *GamessInputDialog)
    {
        GamessInputDialog->setWindowTitle(QCoreApplication::translate("GamessInputDialog", "GAMESS Input", nullptr));
        label_3->setText(QCoreApplication::translate("GamessInputDialog", "In:", nullptr));
        label_12->setText(QCoreApplication::translate("GamessInputDialog", "MAX SCF", nullptr));
        label_13->setText(QCoreApplication::translate("GamessInputDialog", "CONV THRESH", nullptr));
        label_5->setText(QCoreApplication::translate("GamessInputDialog", "Multiplicity:", nullptr));
        label_2->setText(QCoreApplication::translate("GamessInputDialog", "With:", nullptr));
        label_8->setText(QCoreApplication::translate("GamessInputDialog", "Title:", nullptr));
        label_6->setText(QCoreApplication::translate("GamessInputDialog", "Charge:", nullptr));
        label->setText(QCoreApplication::translate("GamessInputDialog", "Calculate:", nullptr));
        label_4->setText(QCoreApplication::translate("GamessInputDialog", "Filename Base:", nullptr));
        baseNameEdit->setText(QString());
        baseNameEdit->setPlaceholderText(QCoreApplication::translate("GamessInputDialog", "job", nullptr));
        modeTab->setTabText(modeTab->indexOf(basicWidget), QCoreApplication::translate("GamessInputDialog", "&Basic Setup", nullptr));
        resetAllButton->setText(QCoreApplication::translate("GamessInputDialog", "Reset All", nullptr));
        defaultsButton->setText(QCoreApplication::translate("GamessInputDialog", "Defaults", nullptr));
        computeButton->setText(QCoreApplication::translate("GamessInputDialog", "Submit Calculation\342\200\246", nullptr));
        generateButton->setText(QCoreApplication::translate("GamessInputDialog", "Save File\342\200\246", nullptr));
        closeButton->setText(QCoreApplication::translate("GamessInputDialog", "Close", nullptr));
    } // retranslateUi

};

namespace Ui {
    class GamessInputDialog: public Ui_GamessInputDialog {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_GAMESSINPUTDIALOG_H
