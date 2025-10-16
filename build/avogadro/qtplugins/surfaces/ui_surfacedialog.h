/********************************************************************************
** Form generated from reading UI file 'surfacedialog.ui'
**
** Created by: Qt User Interface Compiler version 5.15.17
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_SURFACEDIALOG_H
#define UI_SURFACEDIALOG_H

#include <QtCore/QVariant>
#include <QtGui/QIcon>
#include <QtWidgets/QApplication>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QDialog>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QDoubleSpinBox>
#include <QtWidgets/QFormLayout>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QSpinBox>
#include <QtWidgets/QVBoxLayout>

QT_BEGIN_NAMESPACE

class Ui_SurfaceDialog
{
public:
    QVBoxLayout *verticalLayout;
    QFormLayout *formLayout;
    QLabel *label;
    QHBoxLayout *horizontalLayout_2;
    QComboBox *surfaceCombo;
    QComboBox *orbitalCombo;
    QComboBox *spinCombo;
    QSpacerItem *horizontalSpacer;
    QLabel *label_4;
    QHBoxLayout *horizontalLayout_5;
    QComboBox *propertyCombo;
    QComboBox *modelCombo;
    QSpacerItem *horizontalSpacer_4;
    QLabel *label_7;
    QHBoxLayout *horizontalLayout_8;
    QComboBox *colormapCombo;
    QSpacerItem *horizontalSpacer_7;
    QLabel *label_3;
    QHBoxLayout *horizontalLayout;
    QComboBox *resolutionCombo;
    QDoubleSpinBox *resolutionDoubleSpinBox;
    QSpacerItem *horizontalSpacer_2;
    QLabel *label_2;
    QHBoxLayout *horizontalLayout_3;
    QDoubleSpinBox *isosurfaceDoubleSpinBox;
    QSpacerItem *horizontalSpacer_3;
    QLabel *label_6;
    QHBoxLayout *horizontalLayout_7;
    QComboBox *smoothingCombo;
    QSpinBox *smoothingPassesSpinBox;
    QSpacerItem *horizontalSpacer_6;
    QLabel *frameLabel;
    QHBoxLayout *horizontalLayout_6;
    QSpinBox *stepValue;
    QPushButton *vcrBack;
    QPushButton *vcrPlay;
    QPushButton *vcrForward;
    QSpacerItem *horizontalSpacer_5;
    QHBoxLayout *horizontalLayout_4;
    QPushButton *calculateButton;
    QPushButton *recordButton;
    QDialogButtonBox *buttonBox;
    QSpacerItem *verticalSpacer;

    void setupUi(QDialog *SurfaceDialog)
    {
        if (SurfaceDialog->objectName().isEmpty())
            SurfaceDialog->setObjectName(QString::fromUtf8("SurfaceDialog"));
        SurfaceDialog->setWindowModality(Qt::NonModal);
        SurfaceDialog->setEnabled(true);
        SurfaceDialog->resize(443, 354);
        SurfaceDialog->setContextMenuPolicy(Qt::DefaultContextMenu);
        SurfaceDialog->setSizeGripEnabled(false);
        verticalLayout = new QVBoxLayout(SurfaceDialog);
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        formLayout = new QFormLayout();
        formLayout->setObjectName(QString::fromUtf8("formLayout"));
        label = new QLabel(SurfaceDialog);
        label->setObjectName(QString::fromUtf8("label"));
        label->setAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);

        formLayout->setWidget(0, QFormLayout::LabelRole, label);

        horizontalLayout_2 = new QHBoxLayout();
        horizontalLayout_2->setObjectName(QString::fromUtf8("horizontalLayout_2"));
        surfaceCombo = new QComboBox(SurfaceDialog);
        surfaceCombo->setObjectName(QString::fromUtf8("surfaceCombo"));
        surfaceCombo->setEnabled(true);

        horizontalLayout_2->addWidget(surfaceCombo);

        orbitalCombo = new QComboBox(SurfaceDialog);
        orbitalCombo->setObjectName(QString::fromUtf8("orbitalCombo"));
        orbitalCombo->setEnabled(false);

        horizontalLayout_2->addWidget(orbitalCombo);

        spinCombo = new QComboBox(SurfaceDialog);
        spinCombo->addItem(QString());
        spinCombo->addItem(QString());
        spinCombo->setObjectName(QString::fromUtf8("spinCombo"));
        spinCombo->setEnabled(false);

        horizontalLayout_2->addWidget(spinCombo);

        horizontalSpacer = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_2->addItem(horizontalSpacer);


        formLayout->setLayout(0, QFormLayout::FieldRole, horizontalLayout_2);

        label_4 = new QLabel(SurfaceDialog);
        label_4->setObjectName(QString::fromUtf8("label_4"));
        label_4->setAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);

        formLayout->setWidget(1, QFormLayout::LabelRole, label_4);

        horizontalLayout_5 = new QHBoxLayout();
        horizontalLayout_5->setObjectName(QString::fromUtf8("horizontalLayout_5"));
        propertyCombo = new QComboBox(SurfaceDialog);
        propertyCombo->addItem(QString());
        propertyCombo->addItem(QString());
        propertyCombo->setObjectName(QString::fromUtf8("propertyCombo"));

        horizontalLayout_5->addWidget(propertyCombo);

        modelCombo = new QComboBox(SurfaceDialog);
        modelCombo->setObjectName(QString::fromUtf8("modelCombo"));
        modelCombo->setEnabled(false);

        horizontalLayout_5->addWidget(modelCombo);

        horizontalSpacer_4 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_5->addItem(horizontalSpacer_4);


        formLayout->setLayout(1, QFormLayout::FieldRole, horizontalLayout_5);

        label_7 = new QLabel(SurfaceDialog);
        label_7->setObjectName(QString::fromUtf8("label_7"));
        label_7->setAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);

        formLayout->setWidget(2, QFormLayout::LabelRole, label_7);

        horizontalLayout_8 = new QHBoxLayout();
        horizontalLayout_8->setObjectName(QString::fromUtf8("horizontalLayout_8"));
        colormapCombo = new QComboBox(SurfaceDialog);
        colormapCombo->addItem(QString());
        colormapCombo->addItem(QString());
        colormapCombo->addItem(QString());
        colormapCombo->addItem(QString());
        colormapCombo->addItem(QString());
        colormapCombo->setObjectName(QString::fromUtf8("colormapCombo"));
        colormapCombo->setEnabled(false);

        horizontalLayout_8->addWidget(colormapCombo);

        horizontalSpacer_7 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_8->addItem(horizontalSpacer_7);


        formLayout->setLayout(2, QFormLayout::FieldRole, horizontalLayout_8);

        label_3 = new QLabel(SurfaceDialog);
        label_3->setObjectName(QString::fromUtf8("label_3"));
        label_3->setAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);

        formLayout->setWidget(3, QFormLayout::LabelRole, label_3);

        horizontalLayout = new QHBoxLayout();
        horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));
        resolutionCombo = new QComboBox(SurfaceDialog);
        resolutionCombo->addItem(QString());
        resolutionCombo->addItem(QString());
        resolutionCombo->addItem(QString());
        resolutionCombo->addItem(QString());
        resolutionCombo->addItem(QString());
        resolutionCombo->addItem(QString());
        resolutionCombo->addItem(QString());
        resolutionCombo->setObjectName(QString::fromUtf8("resolutionCombo"));
        resolutionCombo->setEnabled(true);

        horizontalLayout->addWidget(resolutionCombo);

        resolutionDoubleSpinBox = new QDoubleSpinBox(SurfaceDialog);
        resolutionDoubleSpinBox->setObjectName(QString::fromUtf8("resolutionDoubleSpinBox"));
        resolutionDoubleSpinBox->setEnabled(false);
        resolutionDoubleSpinBox->setMinimum(0.010000000000000);
        resolutionDoubleSpinBox->setMaximum(2.000000000000000);
        resolutionDoubleSpinBox->setSingleStep(0.100000000000000);
        resolutionDoubleSpinBox->setValue(0.180000000000000);

        horizontalLayout->addWidget(resolutionDoubleSpinBox);

        horizontalSpacer_2 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout->addItem(horizontalSpacer_2);


        formLayout->setLayout(3, QFormLayout::FieldRole, horizontalLayout);

        label_2 = new QLabel(SurfaceDialog);
        label_2->setObjectName(QString::fromUtf8("label_2"));
        label_2->setAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);

        formLayout->setWidget(4, QFormLayout::LabelRole, label_2);

        horizontalLayout_3 = new QHBoxLayout();
        horizontalLayout_3->setObjectName(QString::fromUtf8("horizontalLayout_3"));
        isosurfaceDoubleSpinBox = new QDoubleSpinBox(SurfaceDialog);
        isosurfaceDoubleSpinBox->setObjectName(QString::fromUtf8("isosurfaceDoubleSpinBox"));
        isosurfaceDoubleSpinBox->setDecimals(4);
        isosurfaceDoubleSpinBox->setMinimum(0.000100000000000);
        isosurfaceDoubleSpinBox->setMaximum(0.999000000000000);
        isosurfaceDoubleSpinBox->setSingleStep(0.001000000000000);
        isosurfaceDoubleSpinBox->setValue(0.030000000000000);

        horizontalLayout_3->addWidget(isosurfaceDoubleSpinBox);

        horizontalSpacer_3 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_3->addItem(horizontalSpacer_3);


        formLayout->setLayout(4, QFormLayout::FieldRole, horizontalLayout_3);

        label_6 = new QLabel(SurfaceDialog);
        label_6->setObjectName(QString::fromUtf8("label_6"));
        label_6->setAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);

        formLayout->setWidget(5, QFormLayout::LabelRole, label_6);

        horizontalLayout_7 = new QHBoxLayout();
        horizontalLayout_7->setObjectName(QString::fromUtf8("horizontalLayout_7"));
        smoothingCombo = new QComboBox(SurfaceDialog);
        smoothingCombo->addItem(QString());
        smoothingCombo->addItem(QString());
        smoothingCombo->addItem(QString());
        smoothingCombo->addItem(QString());
        smoothingCombo->addItem(QString());
        smoothingCombo->setObjectName(QString::fromUtf8("smoothingCombo"));
        smoothingCombo->setEnabled(true);

        horizontalLayout_7->addWidget(smoothingCombo);

        smoothingPassesSpinBox = new QSpinBox(SurfaceDialog);
        smoothingPassesSpinBox->setObjectName(QString::fromUtf8("smoothingPassesSpinBox"));
        smoothingPassesSpinBox->setEnabled(false);
        smoothingPassesSpinBox->setMinimum(0);
        smoothingPassesSpinBox->setMaximum(19);
        smoothingPassesSpinBox->setSingleStep(1);
        smoothingPassesSpinBox->setValue(1);

        horizontalLayout_7->addWidget(smoothingPassesSpinBox);

        horizontalSpacer_6 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_7->addItem(horizontalSpacer_6);


        formLayout->setLayout(5, QFormLayout::FieldRole, horizontalLayout_7);

        frameLabel = new QLabel(SurfaceDialog);
        frameLabel->setObjectName(QString::fromUtf8("frameLabel"));
        frameLabel->setAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);

        formLayout->setWidget(6, QFormLayout::LabelRole, frameLabel);

        horizontalLayout_6 = new QHBoxLayout();
        horizontalLayout_6->setObjectName(QString::fromUtf8("horizontalLayout_6"));
        stepValue = new QSpinBox(SurfaceDialog);
        stepValue->setObjectName(QString::fromUtf8("stepValue"));
        stepValue->setEnabled(false);

        horizontalLayout_6->addWidget(stepValue);

        vcrBack = new QPushButton(SurfaceDialog);
        vcrBack->setObjectName(QString::fromUtf8("vcrBack"));
        vcrBack->setEnabled(false);
        QIcon icon;
        QString iconThemeName = QString::fromUtf8("media-seek-backward");
        if (QIcon::hasThemeIcon(iconThemeName)) {
            icon = QIcon::fromTheme(iconThemeName);
        } else {
            icon.addFile(QString::fromUtf8("."), QSize(), QIcon::Normal, QIcon::Off);
        }
        vcrBack->setIcon(icon);

        horizontalLayout_6->addWidget(vcrBack);

        vcrPlay = new QPushButton(SurfaceDialog);
        vcrPlay->setObjectName(QString::fromUtf8("vcrPlay"));
        vcrPlay->setEnabled(false);
        QIcon icon1;
        iconThemeName = QString::fromUtf8("media-playback-start");
        if (QIcon::hasThemeIcon(iconThemeName)) {
            icon1 = QIcon::fromTheme(iconThemeName);
        } else {
            icon1.addFile(QString::fromUtf8("."), QSize(), QIcon::Normal, QIcon::Off);
        }
        vcrPlay->setIcon(icon1);

        horizontalLayout_6->addWidget(vcrPlay);

        vcrForward = new QPushButton(SurfaceDialog);
        vcrForward->setObjectName(QString::fromUtf8("vcrForward"));
        vcrForward->setEnabled(false);
        QIcon icon2;
        iconThemeName = QString::fromUtf8("media-seek-forward");
        if (QIcon::hasThemeIcon(iconThemeName)) {
            icon2 = QIcon::fromTheme(iconThemeName);
        } else {
            icon2.addFile(QString::fromUtf8("."), QSize(), QIcon::Normal, QIcon::Off);
        }
        vcrForward->setIcon(icon2);

        horizontalLayout_6->addWidget(vcrForward);

        horizontalSpacer_5 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_6->addItem(horizontalSpacer_5);


        formLayout->setLayout(6, QFormLayout::FieldRole, horizontalLayout_6);


        verticalLayout->addLayout(formLayout);

        horizontalLayout_4 = new QHBoxLayout();
        horizontalLayout_4->setObjectName(QString::fromUtf8("horizontalLayout_4"));
        calculateButton = new QPushButton(SurfaceDialog);
        calculateButton->setObjectName(QString::fromUtf8("calculateButton"));
        calculateButton->setEnabled(true);

        horizontalLayout_4->addWidget(calculateButton);

        recordButton = new QPushButton(SurfaceDialog);
        recordButton->setObjectName(QString::fromUtf8("recordButton"));
        recordButton->setEnabled(false);

        horizontalLayout_4->addWidget(recordButton);

        buttonBox = new QDialogButtonBox(SurfaceDialog);
        buttonBox->setObjectName(QString::fromUtf8("buttonBox"));
        buttonBox->setStandardButtons(QDialogButtonBox::Close);

        horizontalLayout_4->addWidget(buttonBox);


        verticalLayout->addLayout(horizontalLayout_4);

        verticalSpacer = new QSpacerItem(20, 40, QSizePolicy::Minimum, QSizePolicy::Expanding);

        verticalLayout->addItem(verticalSpacer);


        retranslateUi(SurfaceDialog);
        QObject::connect(buttonBox, SIGNAL(clicked(QAbstractButton*)), SurfaceDialog, SLOT(close()));

        resolutionCombo->setCurrentIndex(5);
        smoothingCombo->setCurrentIndex(1);
        calculateButton->setDefault(true);
        recordButton->setDefault(true);


        QMetaObject::connectSlotsByName(SurfaceDialog);
    } // setupUi

    void retranslateUi(QDialog *SurfaceDialog)
    {
        SurfaceDialog->setWindowTitle(QCoreApplication::translate("SurfaceDialog", "Create Surfaces", nullptr));
        SurfaceDialog->setWindowFilePath(QString());
        label->setText(QCoreApplication::translate("SurfaceDialog", "Surface:", nullptr));
        spinCombo->setItemText(0, QCoreApplication::translate("SurfaceDialog", "alpha", nullptr));
        spinCombo->setItemText(1, QCoreApplication::translate("SurfaceDialog", "beta", nullptr));

        label_4->setText(QCoreApplication::translate("SurfaceDialog", "Color by:", nullptr));
        propertyCombo->setItemText(0, QCoreApplication::translate("SurfaceDialog", "None", nullptr));
        propertyCombo->setItemText(1, QCoreApplication::translate("SurfaceDialog", "Electrostatic Potential", nullptr));

        label_7->setText(QCoreApplication::translate("SurfaceDialog", "Colormap:", nullptr));
        colormapCombo->setItemText(0, QCoreApplication::translate("SurfaceDialog", "Balance", "colormap"));
        colormapCombo->setItemText(1, QCoreApplication::translate("SurfaceDialog", "Blue-DarkRed", "colormap"));
        colormapCombo->setItemText(2, QCoreApplication::translate("SurfaceDialog", "Coolwarm", "colormap"));
        colormapCombo->setItemText(3, QCoreApplication::translate("SurfaceDialog", "Spectral", "colormap"));
        colormapCombo->setItemText(4, QCoreApplication::translate("SurfaceDialog", "Turbo", "colormap"));

        label_3->setText(QCoreApplication::translate("SurfaceDialog", "Resolution:", nullptr));
        resolutionCombo->setItemText(0, QCoreApplication::translate("SurfaceDialog", "Very Low", nullptr));
        resolutionCombo->setItemText(1, QCoreApplication::translate("SurfaceDialog", "Low", nullptr));
        resolutionCombo->setItemText(2, QCoreApplication::translate("SurfaceDialog", "Medium", nullptr));
        resolutionCombo->setItemText(3, QCoreApplication::translate("SurfaceDialog", "High", nullptr));
        resolutionCombo->setItemText(4, QCoreApplication::translate("SurfaceDialog", "Very High", nullptr));
        resolutionCombo->setItemText(5, QCoreApplication::translate("SurfaceDialog", "Automatic", nullptr));
        resolutionCombo->setItemText(6, QCoreApplication::translate("SurfaceDialog", "Custom", nullptr));

        resolutionCombo->setCurrentText(QCoreApplication::translate("SurfaceDialog", "Automatic", nullptr));
        resolutionDoubleSpinBox->setSuffix(QCoreApplication::translate("SurfaceDialog", " \303\205", nullptr));
        label_2->setText(QCoreApplication::translate("SurfaceDialog", "Isosurface Value:", nullptr));
        isosurfaceDoubleSpinBox->setPrefix(QString());
        label_6->setText(QCoreApplication::translate("SurfaceDialog", "Smoothing:", nullptr));
        smoothingCombo->setItemText(0, QCoreApplication::translate("SurfaceDialog", "None", nullptr));
        smoothingCombo->setItemText(1, QCoreApplication::translate("SurfaceDialog", "Light", nullptr));
        smoothingCombo->setItemText(2, QCoreApplication::translate("SurfaceDialog", "Medium", nullptr));
        smoothingCombo->setItemText(3, QCoreApplication::translate("SurfaceDialog", "Strong", nullptr));
        smoothingCombo->setItemText(4, QCoreApplication::translate("SurfaceDialog", "Custom", nullptr));

        smoothingCombo->setCurrentText(QCoreApplication::translate("SurfaceDialog", "Light", nullptr));
        frameLabel->setText(QCoreApplication::translate("SurfaceDialog", "Frame:", nullptr));
        vcrBack->setText(QString());
        vcrPlay->setText(QString());
        vcrForward->setText(QString());
        calculateButton->setText(QCoreApplication::translate("SurfaceDialog", "Calculate", nullptr));
        recordButton->setText(QCoreApplication::translate("SurfaceDialog", "Record Movie\342\200\246", nullptr));
    } // retranslateUi

};

namespace Ui {
    class SurfaceDialog: public Ui_SurfaceDialog {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_SURFACEDIALOG_H
