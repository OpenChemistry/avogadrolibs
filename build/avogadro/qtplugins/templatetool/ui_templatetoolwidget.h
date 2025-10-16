/********************************************************************************
** Form generated from reading UI file 'templatetoolwidget.ui'
**
** Created by: Qt User Interface Compiler version 5.15.17
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_TEMPLATETOOLWIDGET_H
#define UI_TEMPLATETOOLWIDGET_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QFormLayout>
#include <QtWidgets/QGridLayout>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QSpinBox>
#include <QtWidgets/QTabWidget>
#include <QtWidgets/QToolButton>
#include <QtWidgets/QWidget>

namespace Avogadro {
namespace QtPlugins {

class Ui_TemplateToolWidget
{
public:
    QGridLayout *gridLayout;
    QTabWidget *tabWidget;
    QWidget *centersTab;
    QFormLayout *formLayout_4;
    QLabel *elementLabel;
    QHBoxLayout *horizontalLayout_2;
    QComboBox *elementComboBox;
    QSpacerItem *horizontalSpacer_3;
    QLabel *formalChargeLabel;
    QHBoxLayout *horizontalLayout_8;
    QSpinBox *chargeSpinBox;
    QSpacerItem *horizontalSpacer_8;
    QLabel *coordinationLabel;
    QHBoxLayout *horizontalLayout_5;
    QComboBox *coordinationComboBox;
    QSpacerItem *horizontalSpacer_7;
    QHBoxLayout *horizontalLayout_1;
    QToolButton *centerPreview;
    QSpacerItem *horizontalSpacer_5;
    QSpacerItem *verticalSpacer;
    QWidget *ligandTab;
    QFormLayout *formLayout_3;
    QLabel *typeLabel;
    QHBoxLayout *horizontalLayout_4;
    QComboBox *typeComboBox;
    QSpacerItem *horizontalSpacer_4;
    QLabel *ligandLabel;
    QHBoxLayout *horizontalLayout_3;
    QComboBox *ligandComboBox;
    QSpacerItem *horizontalSpacer_2;
    QHBoxLayout *horizontalLayout_11;
    QToolButton *ligandPreview;
    QSpacerItem *horizontalSpacer_10;
    QSpacerItem *verticalSpacer_2;
    QWidget *tab;
    QFormLayout *formLayout_2;
    QLabel *label;
    QHBoxLayout *horizontalLayout;
    QComboBox *groupComboBox;
    QSpacerItem *horizontalSpacer;
    QHBoxLayout *horizontalLayout_6;
    QToolButton *groupPreview;
    QSpacerItem *horizontalSpacer_6;
    QSpacerItem *verticalSpacer_3;

    void setupUi(QWidget *Avogadro__QtPlugins__TemplateToolWidget)
    {
        if (Avogadro__QtPlugins__TemplateToolWidget->objectName().isEmpty())
            Avogadro__QtPlugins__TemplateToolWidget->setObjectName(QString::fromUtf8("Avogadro__QtPlugins__TemplateToolWidget"));
        Avogadro__QtPlugins__TemplateToolWidget->resize(361, 318);
        QSizePolicy sizePolicy(QSizePolicy::MinimumExpanding, QSizePolicy::MinimumExpanding);
        sizePolicy.setHorizontalStretch(0);
        sizePolicy.setVerticalStretch(0);
        sizePolicy.setHeightForWidth(Avogadro__QtPlugins__TemplateToolWidget->sizePolicy().hasHeightForWidth());
        Avogadro__QtPlugins__TemplateToolWidget->setSizePolicy(sizePolicy);
        gridLayout = new QGridLayout(Avogadro__QtPlugins__TemplateToolWidget);
        gridLayout->setObjectName(QString::fromUtf8("gridLayout"));
        tabWidget = new QTabWidget(Avogadro__QtPlugins__TemplateToolWidget);
        tabWidget->setObjectName(QString::fromUtf8("tabWidget"));
        tabWidget->setMinimumSize(QSize(326, 285));
        centersTab = new QWidget();
        centersTab->setObjectName(QString::fromUtf8("centersTab"));
        centersTab->setMinimumSize(QSize(320, 256));
        formLayout_4 = new QFormLayout(centersTab);
        formLayout_4->setObjectName(QString::fromUtf8("formLayout_4"));
        elementLabel = new QLabel(centersTab);
        elementLabel->setObjectName(QString::fromUtf8("elementLabel"));

        formLayout_4->setWidget(0, QFormLayout::LabelRole, elementLabel);

        horizontalLayout_2 = new QHBoxLayout();
        horizontalLayout_2->setObjectName(QString::fromUtf8("horizontalLayout_2"));
        elementComboBox = new QComboBox(centersTab);
        elementComboBox->addItem(QString());
        elementComboBox->addItem(QString());
        elementComboBox->addItem(QString());
        elementComboBox->addItem(QString());
        elementComboBox->setObjectName(QString::fromUtf8("elementComboBox"));

        horizontalLayout_2->addWidget(elementComboBox);

        horizontalSpacer_3 = new QSpacerItem(0, 0, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_2->addItem(horizontalSpacer_3);


        formLayout_4->setLayout(0, QFormLayout::FieldRole, horizontalLayout_2);

        formalChargeLabel = new QLabel(centersTab);
        formalChargeLabel->setObjectName(QString::fromUtf8("formalChargeLabel"));

        formLayout_4->setWidget(1, QFormLayout::LabelRole, formalChargeLabel);

        horizontalLayout_8 = new QHBoxLayout();
        horizontalLayout_8->setObjectName(QString::fromUtf8("horizontalLayout_8"));
        chargeSpinBox = new QSpinBox(centersTab);
        chargeSpinBox->setObjectName(QString::fromUtf8("chargeSpinBox"));
        chargeSpinBox->setMinimum(-7);
        chargeSpinBox->setMaximum(7);

        horizontalLayout_8->addWidget(chargeSpinBox);

        horizontalSpacer_8 = new QSpacerItem(0, 0, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_8->addItem(horizontalSpacer_8);


        formLayout_4->setLayout(1, QFormLayout::FieldRole, horizontalLayout_8);

        coordinationLabel = new QLabel(centersTab);
        coordinationLabel->setObjectName(QString::fromUtf8("coordinationLabel"));

        formLayout_4->setWidget(2, QFormLayout::LabelRole, coordinationLabel);

        horizontalLayout_5 = new QHBoxLayout();
        horizontalLayout_5->setObjectName(QString::fromUtf8("horizontalLayout_5"));
        coordinationComboBox = new QComboBox(centersTab);
        coordinationComboBox->addItem(QString());
        coordinationComboBox->addItem(QString());
        coordinationComboBox->addItem(QString());
        coordinationComboBox->addItem(QString());
        coordinationComboBox->addItem(QString());
        coordinationComboBox->addItem(QString());
        coordinationComboBox->addItem(QString());
        coordinationComboBox->addItem(QString());
        coordinationComboBox->addItem(QString());
        coordinationComboBox->addItem(QString());
        coordinationComboBox->addItem(QString());
        coordinationComboBox->setObjectName(QString::fromUtf8("coordinationComboBox"));
        coordinationComboBox->setMaximumSize(QSize(184, 16777215));
        coordinationComboBox->setMaxCount(2147483646);

        horizontalLayout_5->addWidget(coordinationComboBox);

        horizontalSpacer_7 = new QSpacerItem(0, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_5->addItem(horizontalSpacer_7);


        formLayout_4->setLayout(2, QFormLayout::FieldRole, horizontalLayout_5);

        horizontalLayout_1 = new QHBoxLayout();
        horizontalLayout_1->setObjectName(QString::fromUtf8("horizontalLayout_1"));
        centerPreview = new QToolButton(centersTab);
        centerPreview->setObjectName(QString::fromUtf8("centerPreview"));
        centerPreview->setText(QString::fromUtf8(""));
        centerPreview->setIconSize(QSize(64, 64));

        horizontalLayout_1->addWidget(centerPreview);

        horizontalSpacer_5 = new QSpacerItem(0, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_1->addItem(horizontalSpacer_5);


        formLayout_4->setLayout(4, QFormLayout::FieldRole, horizontalLayout_1);

        verticalSpacer = new QSpacerItem(20, 0, QSizePolicy::Minimum, QSizePolicy::Expanding);

        formLayout_4->setItem(5, QFormLayout::FieldRole, verticalSpacer);

        tabWidget->addTab(centersTab, QString());
        ligandTab = new QWidget();
        ligandTab->setObjectName(QString::fromUtf8("ligandTab"));
        ligandTab->setMinimumSize(QSize(320, 254));
        formLayout_3 = new QFormLayout(ligandTab);
        formLayout_3->setObjectName(QString::fromUtf8("formLayout_3"));
        typeLabel = new QLabel(ligandTab);
        typeLabel->setObjectName(QString::fromUtf8("typeLabel"));

        formLayout_3->setWidget(0, QFormLayout::LabelRole, typeLabel);

        horizontalLayout_4 = new QHBoxLayout();
        horizontalLayout_4->setObjectName(QString::fromUtf8("horizontalLayout_4"));
        typeComboBox = new QComboBox(ligandTab);
        typeComboBox->addItem(QString());
        typeComboBox->addItem(QString());
        typeComboBox->addItem(QString());
        typeComboBox->addItem(QString());
        typeComboBox->addItem(QString());
        typeComboBox->addItem(QString());
        typeComboBox->addItem(QString());
        typeComboBox->setObjectName(QString::fromUtf8("typeComboBox"));

        horizontalLayout_4->addWidget(typeComboBox);

        horizontalSpacer_4 = new QSpacerItem(0, 0, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_4->addItem(horizontalSpacer_4);


        formLayout_3->setLayout(0, QFormLayout::FieldRole, horizontalLayout_4);

        ligandLabel = new QLabel(ligandTab);
        ligandLabel->setObjectName(QString::fromUtf8("ligandLabel"));

        formLayout_3->setWidget(1, QFormLayout::LabelRole, ligandLabel);

        horizontalLayout_3 = new QHBoxLayout();
        horizontalLayout_3->setObjectName(QString::fromUtf8("horizontalLayout_3"));
        ligandComboBox = new QComboBox(ligandTab);
        ligandComboBox->setObjectName(QString::fromUtf8("ligandComboBox"));

        horizontalLayout_3->addWidget(ligandComboBox);

        horizontalSpacer_2 = new QSpacerItem(0, 0, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_3->addItem(horizontalSpacer_2);


        formLayout_3->setLayout(1, QFormLayout::FieldRole, horizontalLayout_3);

        horizontalLayout_11 = new QHBoxLayout();
        horizontalLayout_11->setObjectName(QString::fromUtf8("horizontalLayout_11"));
        ligandPreview = new QToolButton(ligandTab);
        ligandPreview->setObjectName(QString::fromUtf8("ligandPreview"));
        ligandPreview->setIconSize(QSize(96, 96));

        horizontalLayout_11->addWidget(ligandPreview);

        horizontalSpacer_10 = new QSpacerItem(0, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_11->addItem(horizontalSpacer_10);


        formLayout_3->setLayout(2, QFormLayout::FieldRole, horizontalLayout_11);

        verticalSpacer_2 = new QSpacerItem(20, 0, QSizePolicy::Minimum, QSizePolicy::Expanding);

        formLayout_3->setItem(3, QFormLayout::FieldRole, verticalSpacer_2);

        tabWidget->addTab(ligandTab, QString());
        tab = new QWidget();
        tab->setObjectName(QString::fromUtf8("tab"));
        formLayout_2 = new QFormLayout(tab);
        formLayout_2->setObjectName(QString::fromUtf8("formLayout_2"));
        label = new QLabel(tab);
        label->setObjectName(QString::fromUtf8("label"));

        formLayout_2->setWidget(0, QFormLayout::LabelRole, label);

        horizontalLayout = new QHBoxLayout();
        horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));
        groupComboBox = new QComboBox(tab);
        groupComboBox->addItem(QString());
        groupComboBox->addItem(QString());
        groupComboBox->addItem(QString());
        groupComboBox->addItem(QString());
        groupComboBox->addItem(QString());
        groupComboBox->addItem(QString());
        groupComboBox->addItem(QString());
        groupComboBox->addItem(QString());
        groupComboBox->addItem(QString());
        groupComboBox->addItem(QString());
        groupComboBox->setObjectName(QString::fromUtf8("groupComboBox"));

        horizontalLayout->addWidget(groupComboBox);

        horizontalSpacer = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout->addItem(horizontalSpacer);


        formLayout_2->setLayout(0, QFormLayout::FieldRole, horizontalLayout);

        horizontalLayout_6 = new QHBoxLayout();
        horizontalLayout_6->setObjectName(QString::fromUtf8("horizontalLayout_6"));
        groupPreview = new QToolButton(tab);
        groupPreview->setObjectName(QString::fromUtf8("groupPreview"));
        groupPreview->setIconSize(QSize(96, 96));

        horizontalLayout_6->addWidget(groupPreview);

        horizontalSpacer_6 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_6->addItem(horizontalSpacer_6);


        formLayout_2->setLayout(1, QFormLayout::FieldRole, horizontalLayout_6);

        verticalSpacer_3 = new QSpacerItem(20, 40, QSizePolicy::Minimum, QSizePolicy::Expanding);

        formLayout_2->setItem(2, QFormLayout::FieldRole, verticalSpacer_3);

        tabWidget->addTab(tab, QString());

        gridLayout->addWidget(tabWidget, 0, 0, 1, 1);


        retranslateUi(Avogadro__QtPlugins__TemplateToolWidget);

        tabWidget->setCurrentIndex(0);
        elementComboBox->setCurrentIndex(2);
        coordinationComboBox->setCurrentIndex(7);


        QMetaObject::connectSlotsByName(Avogadro__QtPlugins__TemplateToolWidget);
    } // setupUi

    void retranslateUi(QWidget *Avogadro__QtPlugins__TemplateToolWidget)
    {
        Avogadro__QtPlugins__TemplateToolWidget->setWindowTitle(QCoreApplication::translate("Avogadro::QtPlugins::TemplateToolWidget", "Form", nullptr));
        elementLabel->setText(QCoreApplication::translate("Avogadro::QtPlugins::TemplateToolWidget", "Element:", nullptr));
        elementComboBox->setItemText(0, QCoreApplication::translate("Avogadro::QtPlugins::TemplateToolWidget", "Hydrogen", nullptr));
        elementComboBox->setItemText(1, QCoreApplication::translate("Avogadro::QtPlugins::TemplateToolWidget", "Carbon", nullptr));
        elementComboBox->setItemText(2, QCoreApplication::translate("Avogadro::QtPlugins::TemplateToolWidget", "Iron", nullptr));
        elementComboBox->setItemText(3, QCoreApplication::translate("Avogadro::QtPlugins::TemplateToolWidget", "Cobalt", nullptr));

        formalChargeLabel->setText(QCoreApplication::translate("Avogadro::QtPlugins::TemplateToolWidget", "Formal Charge:", nullptr));
        coordinationLabel->setText(QCoreApplication::translate("Avogadro::QtPlugins::TemplateToolWidget", "Coordination:", nullptr));
        coordinationComboBox->setItemText(0, QCoreApplication::translate("Avogadro::QtPlugins::TemplateToolWidget", "1: Linear", nullptr));
        coordinationComboBox->setItemText(1, QCoreApplication::translate("Avogadro::QtPlugins::TemplateToolWidget", "2: Linear", nullptr));
        coordinationComboBox->setItemText(2, QCoreApplication::translate("Avogadro::QtPlugins::TemplateToolWidget", "3: Trigonal Planar", nullptr));
        coordinationComboBox->setItemText(3, QCoreApplication::translate("Avogadro::QtPlugins::TemplateToolWidget", "4: Tetrahedral", nullptr));
        coordinationComboBox->setItemText(4, QCoreApplication::translate("Avogadro::QtPlugins::TemplateToolWidget", "4: Square Planar", nullptr));
        coordinationComboBox->setItemText(5, QCoreApplication::translate("Avogadro::QtPlugins::TemplateToolWidget", "5: Trigonal Bipyramidal", nullptr));
        coordinationComboBox->setItemText(6, QCoreApplication::translate("Avogadro::QtPlugins::TemplateToolWidget", "5: Square Pyramidal", nullptr));
        coordinationComboBox->setItemText(7, QCoreApplication::translate("Avogadro::QtPlugins::TemplateToolWidget", "6: Octahedral", nullptr));
        coordinationComboBox->setItemText(8, QCoreApplication::translate("Avogadro::QtPlugins::TemplateToolWidget", "6: Trigonal Prism", nullptr));
        coordinationComboBox->setItemText(9, QCoreApplication::translate("Avogadro::QtPlugins::TemplateToolWidget", "7: Pentagonal Bipyramidal", nullptr));
        coordinationComboBox->setItemText(10, QCoreApplication::translate("Avogadro::QtPlugins::TemplateToolWidget", "8: Square Antiprism", nullptr));

        coordinationComboBox->setCurrentText(QCoreApplication::translate("Avogadro::QtPlugins::TemplateToolWidget", "6: Octahedral", nullptr));
        tabWidget->setTabText(tabWidget->indexOf(centersTab), QCoreApplication::translate("Avogadro::QtPlugins::TemplateToolWidget", "Centers", nullptr));
        typeLabel->setText(QCoreApplication::translate("Avogadro::QtPlugins::TemplateToolWidget", "Type:", nullptr));
        typeComboBox->setItemText(0, QCoreApplication::translate("Avogadro::QtPlugins::TemplateToolWidget", "Monodentate", nullptr));
        typeComboBox->setItemText(1, QCoreApplication::translate("Avogadro::QtPlugins::TemplateToolWidget", "Bidentate", nullptr));
        typeComboBox->setItemText(2, QCoreApplication::translate("Avogadro::QtPlugins::TemplateToolWidget", "Tridentate", nullptr));
        typeComboBox->setItemText(3, QCoreApplication::translate("Avogadro::QtPlugins::TemplateToolWidget", "Tetradentate", nullptr));
        typeComboBox->setItemText(4, QCoreApplication::translate("Avogadro::QtPlugins::TemplateToolWidget", "Hexadentate", nullptr));
        typeComboBox->setItemText(5, QCoreApplication::translate("Avogadro::QtPlugins::TemplateToolWidget", "Haptic", nullptr));
        typeComboBox->setItemText(6, QCoreApplication::translate("Avogadro::QtPlugins::TemplateToolWidget", "From Clipboard", nullptr));

        ligandLabel->setText(QCoreApplication::translate("Avogadro::QtPlugins::TemplateToolWidget", "Ligand:", nullptr));
        ligandPreview->setText(QString());
        tabWidget->setTabText(tabWidget->indexOf(ligandTab), QCoreApplication::translate("Avogadro::QtPlugins::TemplateToolWidget", "Ligands", nullptr));
        label->setText(QCoreApplication::translate("Avogadro::QtPlugins::TemplateToolWidget", "Group:", nullptr));
        groupComboBox->setItemText(0, QCoreApplication::translate("Avogadro::QtPlugins::TemplateToolWidget", "amide", nullptr));
        groupComboBox->setItemText(1, QCoreApplication::translate("Avogadro::QtPlugins::TemplateToolWidget", "carboxylate", nullptr));
        groupComboBox->setItemText(2, QCoreApplication::translate("Avogadro::QtPlugins::TemplateToolWidget", "ester", nullptr));
        groupComboBox->setItemText(3, QCoreApplication::translate("Avogadro::QtPlugins::TemplateToolWidget", "ethylene", nullptr));
        groupComboBox->setItemText(4, QCoreApplication::translate("Avogadro::QtPlugins::TemplateToolWidget", "ethyne", nullptr));
        groupComboBox->setItemText(5, QCoreApplication::translate("Avogadro::QtPlugins::TemplateToolWidget", "nitro", nullptr));
        groupComboBox->setItemText(6, QCoreApplication::translate("Avogadro::QtPlugins::TemplateToolWidget", "phenyl", nullptr));
        groupComboBox->setItemText(7, QCoreApplication::translate("Avogadro::QtPlugins::TemplateToolWidget", "phosphate", nullptr));
        groupComboBox->setItemText(8, QCoreApplication::translate("Avogadro::QtPlugins::TemplateToolWidget", "sulfonate", nullptr));
        groupComboBox->setItemText(9, QCoreApplication::translate("Avogadro::QtPlugins::TemplateToolWidget", "Other\342\200\246", nullptr));

        groupPreview->setText(QString());
        tabWidget->setTabText(tabWidget->indexOf(tab), QCoreApplication::translate("Avogadro::QtPlugins::TemplateToolWidget", "Groups", nullptr));
    } // retranslateUi

};

} // namespace QtPlugins
} // namespace Avogadro

namespace Avogadro {
namespace QtPlugins {
namespace Ui {
    class TemplateToolWidget: public Ui_TemplateToolWidget {};
} // namespace Ui
} // namespace QtPlugins
} // namespace Avogadro

#endif // UI_TEMPLATETOOLWIDGET_H
