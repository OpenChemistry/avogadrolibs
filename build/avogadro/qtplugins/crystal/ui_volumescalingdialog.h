/********************************************************************************
** Form generated from reading UI file 'volumescalingdialog.ui'
**
** Created by: Qt User Interface Compiler version 5.15.17
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_VOLUMESCALINGDIALOG_H
#define UI_VOLUMESCALINGDIALOG_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QDialog>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QDoubleSpinBox>
#include <QtWidgets/QFormLayout>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QVBoxLayout>

namespace Avogadro {
namespace QtPlugins {

class Ui_VolumeScalingDialog
{
public:
    QVBoxLayout *verticalLayout;
    QFormLayout *formLayout;
    QLabel *label;
    QLabel *label_2;
    QLabel *label_3;
    QLabel *currentVolume;
    QDoubleSpinBox *newVolume;
    QDoubleSpinBox *scalingFactor;
    QSpacerItem *verticalSpacer;
    QHBoxLayout *horizontalLayout;
    QCheckBox *transformAtoms;
    QSpacerItem *horizontalSpacer;
    QDialogButtonBox *buttonBox;

    void setupUi(QDialog *Avogadro__QtPlugins__VolumeScalingDialog)
    {
        if (Avogadro__QtPlugins__VolumeScalingDialog->objectName().isEmpty())
            Avogadro__QtPlugins__VolumeScalingDialog->setObjectName(QString::fromUtf8("Avogadro__QtPlugins__VolumeScalingDialog"));
        Avogadro__QtPlugins__VolumeScalingDialog->resize(348, 151);
        verticalLayout = new QVBoxLayout(Avogadro__QtPlugins__VolumeScalingDialog);
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        formLayout = new QFormLayout();
        formLayout->setObjectName(QString::fromUtf8("formLayout"));
        formLayout->setLabelAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);
        label = new QLabel(Avogadro__QtPlugins__VolumeScalingDialog);
        label->setObjectName(QString::fromUtf8("label"));
        label->setAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);

        formLayout->setWidget(1, QFormLayout::LabelRole, label);

        label_2 = new QLabel(Avogadro__QtPlugins__VolumeScalingDialog);
        label_2->setObjectName(QString::fromUtf8("label_2"));
        label_2->setAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);

        formLayout->setWidget(2, QFormLayout::LabelRole, label_2);

        label_3 = new QLabel(Avogadro__QtPlugins__VolumeScalingDialog);
        label_3->setObjectName(QString::fromUtf8("label_3"));

        formLayout->setWidget(0, QFormLayout::LabelRole, label_3);

        currentVolume = new QLabel(Avogadro__QtPlugins__VolumeScalingDialog);
        currentVolume->setObjectName(QString::fromUtf8("currentVolume"));

        formLayout->setWidget(0, QFormLayout::FieldRole, currentVolume);

        newVolume = new QDoubleSpinBox(Avogadro__QtPlugins__VolumeScalingDialog);
        newVolume->setObjectName(QString::fromUtf8("newVolume"));
        newVolume->setDecimals(5);
        newVolume->setMinimum(0.010000000000000);
        newVolume->setMaximum(9999999.000000000000000);

        formLayout->setWidget(1, QFormLayout::FieldRole, newVolume);

        scalingFactor = new QDoubleSpinBox(Avogadro__QtPlugins__VolumeScalingDialog);
        scalingFactor->setObjectName(QString::fromUtf8("scalingFactor"));
        scalingFactor->setDecimals(5);
        scalingFactor->setMinimum(0.000010000000000);
        scalingFactor->setMaximum(999999.999990000040270);
        scalingFactor->setSingleStep(0.100000000000000);
        scalingFactor->setValue(1.000000000000000);

        formLayout->setWidget(2, QFormLayout::FieldRole, scalingFactor);


        verticalLayout->addLayout(formLayout);

        verticalSpacer = new QSpacerItem(20, 40, QSizePolicy::Minimum, QSizePolicy::Expanding);

        verticalLayout->addItem(verticalSpacer);

        horizontalLayout = new QHBoxLayout();
        horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));
        transformAtoms = new QCheckBox(Avogadro__QtPlugins__VolumeScalingDialog);
        transformAtoms->setObjectName(QString::fromUtf8("transformAtoms"));

        horizontalLayout->addWidget(transformAtoms);

        horizontalSpacer = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout->addItem(horizontalSpacer);

        buttonBox = new QDialogButtonBox(Avogadro__QtPlugins__VolumeScalingDialog);
        buttonBox->setObjectName(QString::fromUtf8("buttonBox"));
        buttonBox->setOrientation(Qt::Horizontal);
        buttonBox->setStandardButtons(QDialogButtonBox::Cancel|QDialogButtonBox::Ok);

        horizontalLayout->addWidget(buttonBox);


        verticalLayout->addLayout(horizontalLayout);

#if QT_CONFIG(shortcut)
        label->setBuddy(newVolume);
        label_2->setBuddy(scalingFactor);
#endif // QT_CONFIG(shortcut)
        QWidget::setTabOrder(newVolume, scalingFactor);
        QWidget::setTabOrder(scalingFactor, transformAtoms);
        QWidget::setTabOrder(transformAtoms, buttonBox);

        retranslateUi(Avogadro__QtPlugins__VolumeScalingDialog);
        QObject::connect(buttonBox, SIGNAL(accepted()), Avogadro__QtPlugins__VolumeScalingDialog, SLOT(accept()));
        QObject::connect(buttonBox, SIGNAL(rejected()), Avogadro__QtPlugins__VolumeScalingDialog, SLOT(reject()));

        QMetaObject::connectSlotsByName(Avogadro__QtPlugins__VolumeScalingDialog);
    } // setupUi

    void retranslateUi(QDialog *Avogadro__QtPlugins__VolumeScalingDialog)
    {
        Avogadro__QtPlugins__VolumeScalingDialog->setWindowTitle(QCoreApplication::translate("Avogadro::QtPlugins::VolumeScalingDialog", "Scale Unit Cell Volume", nullptr));
        label->setText(QCoreApplication::translate("Avogadro::QtPlugins::VolumeScalingDialog", "New &Volume:", nullptr));
        label_2->setText(QCoreApplication::translate("Avogadro::QtPlugins::VolumeScalingDialog", "&Scaling Factor:", nullptr));
        label_3->setText(QCoreApplication::translate("Avogadro::QtPlugins::VolumeScalingDialog", "Current Volume:", nullptr));
        currentVolume->setText(QCoreApplication::translate("Avogadro::QtPlugins::VolumeScalingDialog", "TextLabel", nullptr));
        transformAtoms->setText(QCoreApplication::translate("Avogadro::QtPlugins::VolumeScalingDialog", "&Transform Atoms", nullptr));
    } // retranslateUi

};

} // namespace QtPlugins
} // namespace Avogadro

namespace Avogadro {
namespace QtPlugins {
namespace Ui {
    class VolumeScalingDialog: public Ui_VolumeScalingDialog {};
} // namespace Ui
} // namespace QtPlugins
} // namespace Avogadro

#endif // UI_VOLUMESCALINGDIALOG_H
