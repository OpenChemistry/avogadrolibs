/********************************************************************************
** Form generated from reading UI file 'manipulatewidget.ui'
**
** Created by: Qt User Interface Compiler version 5.15.17
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_MANIPULATEWIDGET_H
#define UI_MANIPULATEWIDGET_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QDoubleSpinBox>
#include <QtWidgets/QGridLayout>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_ManipulateWidget
{
public:
    QVBoxLayout *verticalLayout;
    QGridLayout *gridLayout;
    QDoubleSpinBox *xTranslateSpinBox;
    QDoubleSpinBox *yTranslateSpinBox;
    QDoubleSpinBox *zTranslateSpinBox;
    QLabel *label_3;
    QLabel *label_4;
    QLabel *label_5;
    QLabel *label;
    QHBoxLayout *horizontalLayout_3;
    QLabel *label_2;
    QComboBox *rotateComboBox;
    QGridLayout *gridLayout_2;
    QDoubleSpinBox *xRotateSpinBox;
    QDoubleSpinBox *yRotateSpinBox;
    QDoubleSpinBox *zRotateSpinBox;
    QLabel *label_6;
    QLabel *label_7;
    QLabel *label_8;
    QHBoxLayout *horizontalLayout_4;
    QLabel *label_9;
    QComboBox *moveComboBox;
    QDialogButtonBox *buttonBox;
    QSpacerItem *verticalSpacer;

    void setupUi(QWidget *ManipulateWidget)
    {
        if (ManipulateWidget->objectName().isEmpty())
            ManipulateWidget->setObjectName(QString::fromUtf8("ManipulateWidget"));
        ManipulateWidget->resize(371, 292);
        verticalLayout = new QVBoxLayout(ManipulateWidget);
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        gridLayout = new QGridLayout();
        gridLayout->setObjectName(QString::fromUtf8("gridLayout"));
        xTranslateSpinBox = new QDoubleSpinBox(ManipulateWidget);
        xTranslateSpinBox->setObjectName(QString::fromUtf8("xTranslateSpinBox"));
        xTranslateSpinBox->setAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);
        xTranslateSpinBox->setDecimals(4);
        xTranslateSpinBox->setMinimum(-999.990000000000009);
        xTranslateSpinBox->setMaximum(999.990000000000009);

        gridLayout->addWidget(xTranslateSpinBox, 3, 0, 1, 1);

        yTranslateSpinBox = new QDoubleSpinBox(ManipulateWidget);
        yTranslateSpinBox->setObjectName(QString::fromUtf8("yTranslateSpinBox"));
        yTranslateSpinBox->setAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);
        yTranslateSpinBox->setDecimals(4);
        yTranslateSpinBox->setMinimum(-999.990000000000009);
        yTranslateSpinBox->setMaximum(999.990000000000009);

        gridLayout->addWidget(yTranslateSpinBox, 3, 1, 1, 1);

        zTranslateSpinBox = new QDoubleSpinBox(ManipulateWidget);
        zTranslateSpinBox->setObjectName(QString::fromUtf8("zTranslateSpinBox"));
        zTranslateSpinBox->setAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);
        zTranslateSpinBox->setDecimals(4);
        zTranslateSpinBox->setMinimum(-999.990000000000009);
        zTranslateSpinBox->setMaximum(999.990000000000009);

        gridLayout->addWidget(zTranslateSpinBox, 3, 2, 1, 1);

        label_3 = new QLabel(ManipulateWidget);
        label_3->setObjectName(QString::fromUtf8("label_3"));

        gridLayout->addWidget(label_3, 1, 0, 1, 1);

        label_4 = new QLabel(ManipulateWidget);
        label_4->setObjectName(QString::fromUtf8("label_4"));

        gridLayout->addWidget(label_4, 1, 1, 1, 1);

        label_5 = new QLabel(ManipulateWidget);
        label_5->setObjectName(QString::fromUtf8("label_5"));

        gridLayout->addWidget(label_5, 1, 2, 1, 1);

        label = new QLabel(ManipulateWidget);
        label->setObjectName(QString::fromUtf8("label"));

        gridLayout->addWidget(label, 0, 0, 1, 1);


        verticalLayout->addLayout(gridLayout);

        horizontalLayout_3 = new QHBoxLayout();
        horizontalLayout_3->setObjectName(QString::fromUtf8("horizontalLayout_3"));
        horizontalLayout_3->setContentsMargins(-1, 0, -1, -1);
        label_2 = new QLabel(ManipulateWidget);
        label_2->setObjectName(QString::fromUtf8("label_2"));

        horizontalLayout_3->addWidget(label_2);

        rotateComboBox = new QComboBox(ManipulateWidget);
        rotateComboBox->addItem(QString());
        rotateComboBox->addItem(QString());
        rotateComboBox->addItem(QString());
        rotateComboBox->setObjectName(QString::fromUtf8("rotateComboBox"));

        horizontalLayout_3->addWidget(rotateComboBox);


        verticalLayout->addLayout(horizontalLayout_3);

        gridLayout_2 = new QGridLayout();
        gridLayout_2->setObjectName(QString::fromUtf8("gridLayout_2"));
        xRotateSpinBox = new QDoubleSpinBox(ManipulateWidget);
        xRotateSpinBox->setObjectName(QString::fromUtf8("xRotateSpinBox"));
        xRotateSpinBox->setAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);
        xRotateSpinBox->setMinimum(-360.000000000000000);
        xRotateSpinBox->setMaximum(360.000000000000000);

        gridLayout_2->addWidget(xRotateSpinBox, 2, 0, 1, 1);

        yRotateSpinBox = new QDoubleSpinBox(ManipulateWidget);
        yRotateSpinBox->setObjectName(QString::fromUtf8("yRotateSpinBox"));
        yRotateSpinBox->setAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);
        yRotateSpinBox->setMinimum(-360.000000000000000);
        yRotateSpinBox->setMaximum(360.000000000000000);

        gridLayout_2->addWidget(yRotateSpinBox, 2, 1, 1, 1);

        zRotateSpinBox = new QDoubleSpinBox(ManipulateWidget);
        zRotateSpinBox->setObjectName(QString::fromUtf8("zRotateSpinBox"));
        zRotateSpinBox->setAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);
        zRotateSpinBox->setMinimum(-360.000000000000000);
        zRotateSpinBox->setMaximum(360.000000000000000);

        gridLayout_2->addWidget(zRotateSpinBox, 2, 2, 1, 1);

        label_6 = new QLabel(ManipulateWidget);
        label_6->setObjectName(QString::fromUtf8("label_6"));

        gridLayout_2->addWidget(label_6, 1, 0, 1, 1);

        label_7 = new QLabel(ManipulateWidget);
        label_7->setObjectName(QString::fromUtf8("label_7"));

        gridLayout_2->addWidget(label_7, 1, 1, 1, 1);

        label_8 = new QLabel(ManipulateWidget);
        label_8->setObjectName(QString::fromUtf8("label_8"));

        gridLayout_2->addWidget(label_8, 1, 2, 1, 1);


        verticalLayout->addLayout(gridLayout_2);

        horizontalLayout_4 = new QHBoxLayout();
        horizontalLayout_4->setObjectName(QString::fromUtf8("horizontalLayout_4"));
        horizontalLayout_4->setContentsMargins(-1, 0, -1, -1);
        label_9 = new QLabel(ManipulateWidget);
        label_9->setObjectName(QString::fromUtf8("label_9"));

        horizontalLayout_4->addWidget(label_9);

        moveComboBox = new QComboBox(ManipulateWidget);
        moveComboBox->addItem(QString());
        moveComboBox->addItem(QString());
        moveComboBox->setObjectName(QString::fromUtf8("moveComboBox"));

        horizontalLayout_4->addWidget(moveComboBox);


        verticalLayout->addLayout(horizontalLayout_4);

        buttonBox = new QDialogButtonBox(ManipulateWidget);
        buttonBox->setObjectName(QString::fromUtf8("buttonBox"));
        buttonBox->setStandardButtons(QDialogButtonBox::Apply|QDialogButtonBox::Reset);
        buttonBox->setCenterButtons(true);

        verticalLayout->addWidget(buttonBox);

        verticalSpacer = new QSpacerItem(20, 262, QSizePolicy::Minimum, QSizePolicy::Expanding);

        verticalLayout->addItem(verticalSpacer);


        retranslateUi(ManipulateWidget);

        QMetaObject::connectSlotsByName(ManipulateWidget);
    } // setupUi

    void retranslateUi(QWidget *ManipulateWidget)
    {
        ManipulateWidget->setWindowTitle(QCoreApplication::translate("ManipulateWidget", "Form", nullptr));
        xTranslateSpinBox->setSuffix(QCoreApplication::translate("ManipulateWidget", " \303\205", nullptr));
        yTranslateSpinBox->setSuffix(QCoreApplication::translate("ManipulateWidget", " \303\205", nullptr));
        zTranslateSpinBox->setSuffix(QCoreApplication::translate("ManipulateWidget", " \303\205", nullptr));
        label_3->setText(QCoreApplication::translate("ManipulateWidget", "X", nullptr));
        label_4->setText(QCoreApplication::translate("ManipulateWidget", "Y", nullptr));
        label_5->setText(QCoreApplication::translate("ManipulateWidget", "Z", nullptr));
        label->setText(QCoreApplication::translate("ManipulateWidget", "Translate by:", nullptr));
        label_2->setText(QCoreApplication::translate("ManipulateWidget", "Rotate around:", nullptr));
        rotateComboBox->setItemText(0, QCoreApplication::translate("ManipulateWidget", "Origin", nullptr));
        rotateComboBox->setItemText(1, QCoreApplication::translate("ManipulateWidget", "Center of Molecule", nullptr));
        rotateComboBox->setItemText(2, QCoreApplication::translate("ManipulateWidget", "Center of Selection", nullptr));

        xRotateSpinBox->setSuffix(QCoreApplication::translate("ManipulateWidget", "\302\260", nullptr));
        yRotateSpinBox->setSuffix(QCoreApplication::translate("ManipulateWidget", "\302\260", nullptr));
        zRotateSpinBox->setSuffix(QCoreApplication::translate("ManipulateWidget", "\302\260", nullptr));
        label_6->setText(QCoreApplication::translate("ManipulateWidget", "X-axis", nullptr));
        label_7->setText(QCoreApplication::translate("ManipulateWidget", "Y-axis", nullptr));
        label_8->setText(QCoreApplication::translate("ManipulateWidget", "Z-axis", nullptr));
        label_9->setText(QCoreApplication::translate("ManipulateWidget", "Move:", nullptr));
        moveComboBox->setItemText(0, QCoreApplication::translate("ManipulateWidget", "Selected Atoms", nullptr));
        moveComboBox->setItemText(1, QCoreApplication::translate("ManipulateWidget", "Everything Else", nullptr));

    } // retranslateUi

};

namespace Ui {
    class ManipulateWidget: public Ui_ManipulateWidget {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_MANIPULATEWIDGET_H
