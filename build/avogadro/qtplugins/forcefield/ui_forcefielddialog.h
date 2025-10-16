/********************************************************************************
** Form generated from reading UI file 'forcefielddialog.ui'
**
** Created by: Qt User Interface Compiler version 5.15.17
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_FORCEFIELDDIALOG_H
#define UI_FORCEFIELDDIALOG_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QDialog>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QFormLayout>
#include <QtWidgets/QGridLayout>
#include <QtWidgets/QGroupBox>
#include <QtWidgets/QLabel>
#include <QtWidgets/QSpinBox>

namespace Avogadro {
namespace QtPlugins {

class Ui_ForceFieldDialog
{
public:
    QGridLayout *gridLayout;
    QDialogButtonBox *buttonBox;
    QGroupBox *groupBox_3;
    QFormLayout *formLayout_3;
    QLabel *label_2;
    QLabel *label_5;
    QSpinBox *energyConv;
    QSpinBox *stepLimit;
    QLabel *label_4;
    QSpinBox *gradConv;
    QGroupBox *groupBox_2;
    QFormLayout *formLayout;
    QLabel *label;
    QComboBox *forceField;
    QCheckBox *useRecommended;

    void setupUi(QDialog *Avogadro__QtPlugins__ForceFieldDialog)
    {
        if (Avogadro__QtPlugins__ForceFieldDialog->objectName().isEmpty())
            Avogadro__QtPlugins__ForceFieldDialog->setObjectName(QString::fromUtf8("Avogadro__QtPlugins__ForceFieldDialog"));
        Avogadro__QtPlugins__ForceFieldDialog->resize(365, 275);
        QSizePolicy sizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
        sizePolicy.setHorizontalStretch(0);
        sizePolicy.setVerticalStretch(0);
        sizePolicy.setHeightForWidth(Avogadro__QtPlugins__ForceFieldDialog->sizePolicy().hasHeightForWidth());
        Avogadro__QtPlugins__ForceFieldDialog->setSizePolicy(sizePolicy);
        gridLayout = new QGridLayout(Avogadro__QtPlugins__ForceFieldDialog);
        gridLayout->setObjectName(QString::fromUtf8("gridLayout"));
        gridLayout->setSizeConstraint(QLayout::SetFixedSize);
        buttonBox = new QDialogButtonBox(Avogadro__QtPlugins__ForceFieldDialog);
        buttonBox->setObjectName(QString::fromUtf8("buttonBox"));
        buttonBox->setOrientation(Qt::Horizontal);
        buttonBox->setStandardButtons(QDialogButtonBox::Cancel|QDialogButtonBox::Ok);

        gridLayout->addWidget(buttonBox, 2, 0, 1, 1);

        groupBox_3 = new QGroupBox(Avogadro__QtPlugins__ForceFieldDialog);
        groupBox_3->setObjectName(QString::fromUtf8("groupBox_3"));
        formLayout_3 = new QFormLayout(groupBox_3);
        formLayout_3->setObjectName(QString::fromUtf8("formLayout_3"));
        label_2 = new QLabel(groupBox_3);
        label_2->setObjectName(QString::fromUtf8("label_2"));

        formLayout_3->setWidget(0, QFormLayout::LabelRole, label_2);

        label_5 = new QLabel(groupBox_3);
        label_5->setObjectName(QString::fromUtf8("label_5"));

        formLayout_3->setWidget(2, QFormLayout::LabelRole, label_5);

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
        stepLimit->setSingleStep(50);
        stepLimit->setValue(250);

        formLayout_3->setWidget(2, QFormLayout::FieldRole, stepLimit);

        label_4 = new QLabel(groupBox_3);
        label_4->setObjectName(QString::fromUtf8("label_4"));

        formLayout_3->setWidget(1, QFormLayout::LabelRole, label_4);

        gradConv = new QSpinBox(groupBox_3);
        gradConv->setObjectName(QString::fromUtf8("gradConv"));
        gradConv->setMinimum(-10);
        gradConv->setMaximum(-1);
        gradConv->setValue(-4);

        formLayout_3->setWidget(1, QFormLayout::FieldRole, gradConv);


        gridLayout->addWidget(groupBox_3, 1, 0, 1, 1);

        groupBox_2 = new QGroupBox(Avogadro__QtPlugins__ForceFieldDialog);
        groupBox_2->setObjectName(QString::fromUtf8("groupBox_2"));
        formLayout = new QFormLayout(groupBox_2);
        formLayout->setObjectName(QString::fromUtf8("formLayout"));
        label = new QLabel(groupBox_2);
        label->setObjectName(QString::fromUtf8("label"));

        formLayout->setWidget(0, QFormLayout::LabelRole, label);

        forceField = new QComboBox(groupBox_2);
        forceField->setObjectName(QString::fromUtf8("forceField"));

        formLayout->setWidget(0, QFormLayout::FieldRole, forceField);

        useRecommended = new QCheckBox(groupBox_2);
        useRecommended->setObjectName(QString::fromUtf8("useRecommended"));

        formLayout->setWidget(1, QFormLayout::FieldRole, useRecommended);


        gridLayout->addWidget(groupBox_2, 0, 0, 1, 1);

        QWidget::setTabOrder(forceField, useRecommended);
        QWidget::setTabOrder(useRecommended, energyConv);
        QWidget::setTabOrder(energyConv, stepLimit);
        QWidget::setTabOrder(stepLimit, buttonBox);

        retranslateUi(Avogadro__QtPlugins__ForceFieldDialog);
        QObject::connect(buttonBox, SIGNAL(accepted()), Avogadro__QtPlugins__ForceFieldDialog, SLOT(accept()));
        QObject::connect(buttonBox, SIGNAL(rejected()), Avogadro__QtPlugins__ForceFieldDialog, SLOT(reject()));

        QMetaObject::connectSlotsByName(Avogadro__QtPlugins__ForceFieldDialog);
    } // setupUi

    void retranslateUi(QDialog *Avogadro__QtPlugins__ForceFieldDialog)
    {
        Avogadro__QtPlugins__ForceFieldDialog->setWindowTitle(QCoreApplication::translate("Avogadro::QtPlugins::ForceFieldDialog", "Geometry Optimization Parameters", nullptr));
        groupBox_3->setTitle(QCoreApplication::translate("Avogadro::QtPlugins::ForceFieldDialog", "Convergence Criteria", nullptr));
        label_2->setText(QCoreApplication::translate("Avogadro::QtPlugins::ForceFieldDialog", "Energy convergence:", nullptr));
        label_5->setText(QCoreApplication::translate("Avogadro::QtPlugins::ForceFieldDialog", "Step limit:", nullptr));
        energyConv->setSuffix(QCoreApplication::translate("Avogadro::QtPlugins::ForceFieldDialog", " units", nullptr));
        energyConv->setPrefix(QCoreApplication::translate("Avogadro::QtPlugins::ForceFieldDialog", "10^", nullptr));
        stepLimit->setSuffix(QCoreApplication::translate("Avogadro::QtPlugins::ForceFieldDialog", " steps", nullptr));
        label_4->setText(QCoreApplication::translate("Avogadro::QtPlugins::ForceFieldDialog", "Gradient convergence:", nullptr));
        gradConv->setSuffix(QCoreApplication::translate("Avogadro::QtPlugins::ForceFieldDialog", " units", nullptr));
        gradConv->setPrefix(QCoreApplication::translate("Avogadro::QtPlugins::ForceFieldDialog", "10^", nullptr));
        groupBox_2->setTitle(QCoreApplication::translate("Avogadro::QtPlugins::ForceFieldDialog", "Optimization Method", nullptr));
        label->setText(QCoreApplication::translate("Avogadro::QtPlugins::ForceFieldDialog", "Force field:", nullptr));
        useRecommended->setText(QCoreApplication::translate("Avogadro::QtPlugins::ForceFieldDialog", "Autodetect", nullptr));
    } // retranslateUi

};

} // namespace QtPlugins
} // namespace Avogadro

namespace Avogadro {
namespace QtPlugins {
namespace Ui {
    class ForceFieldDialog: public Ui_ForceFieldDialog {};
} // namespace Ui
} // namespace QtPlugins
} // namespace Avogadro

#endif // UI_FORCEFIELDDIALOG_H
