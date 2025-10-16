/********************************************************************************
** Form generated from reading UI file 'editortoolwidget.ui'
**
** Created by: Qt User Interface Compiler version 5.15.17
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_EDITORTOOLWIDGET_H
#define UI_EDITORTOOLWIDGET_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QFormLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QWidget>

namespace Avogadro {
namespace QtPlugins {

class Ui_EditorToolWidget
{
public:
    QFormLayout *formLayout;
    QLabel *label;
    QComboBox *element;
    QLabel *label_2;
    QComboBox *bondOrder;
    QCheckBox *adjustHydrogens;

    void setupUi(QWidget *Avogadro__QtPlugins__EditorToolWidget)
    {
        if (Avogadro__QtPlugins__EditorToolWidget->objectName().isEmpty())
            Avogadro__QtPlugins__EditorToolWidget->setObjectName(QString::fromUtf8("Avogadro__QtPlugins__EditorToolWidget"));
        Avogadro__QtPlugins__EditorToolWidget->resize(400, 300);
        formLayout = new QFormLayout(Avogadro__QtPlugins__EditorToolWidget);
        formLayout->setObjectName(QString::fromUtf8("formLayout"));
        formLayout->setFieldGrowthPolicy(QFormLayout::ExpandingFieldsGrow);
        label = new QLabel(Avogadro__QtPlugins__EditorToolWidget);
        label->setObjectName(QString::fromUtf8("label"));

        formLayout->setWidget(0, QFormLayout::LabelRole, label);

        element = new QComboBox(Avogadro__QtPlugins__EditorToolWidget);
        element->setObjectName(QString::fromUtf8("element"));

        formLayout->setWidget(0, QFormLayout::FieldRole, element);

        label_2 = new QLabel(Avogadro__QtPlugins__EditorToolWidget);
        label_2->setObjectName(QString::fromUtf8("label_2"));

        formLayout->setWidget(1, QFormLayout::LabelRole, label_2);

        bondOrder = new QComboBox(Avogadro__QtPlugins__EditorToolWidget);
        bondOrder->setObjectName(QString::fromUtf8("bondOrder"));

        formLayout->setWidget(1, QFormLayout::FieldRole, bondOrder);

        adjustHydrogens = new QCheckBox(Avogadro__QtPlugins__EditorToolWidget);
        adjustHydrogens->setObjectName(QString::fromUtf8("adjustHydrogens"));
        adjustHydrogens->setChecked(true);

        formLayout->setWidget(2, QFormLayout::FieldRole, adjustHydrogens);


        retranslateUi(Avogadro__QtPlugins__EditorToolWidget);

        QMetaObject::connectSlotsByName(Avogadro__QtPlugins__EditorToolWidget);
    } // setupUi

    void retranslateUi(QWidget *Avogadro__QtPlugins__EditorToolWidget)
    {
        Avogadro__QtPlugins__EditorToolWidget->setWindowTitle(QCoreApplication::translate("Avogadro::QtPlugins::EditorToolWidget", "Form", nullptr));
        label->setText(QCoreApplication::translate("Avogadro::QtPlugins::EditorToolWidget", "Element:", nullptr));
        label_2->setText(QCoreApplication::translate("Avogadro::QtPlugins::EditorToolWidget", "Bond Order:", nullptr));
        adjustHydrogens->setText(QCoreApplication::translate("Avogadro::QtPlugins::EditorToolWidget", "Adjust Hydrogens", nullptr));
    } // retranslateUi

};

} // namespace QtPlugins
} // namespace Avogadro

namespace Avogadro {
namespace QtPlugins {
namespace Ui {
    class EditorToolWidget: public Ui_EditorToolWidget {};
} // namespace Ui
} // namespace QtPlugins
} // namespace Avogadro

#endif // UI_EDITORTOOLWIDGET_H
