/********************************************************************************
** Form generated from reading UI file 'selectiontoolwidget.ui'
**
** Created by: Qt User Interface Compiler version 5.15.17
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_SELECTIONTOOLWIDGET_H
#define UI_SELECTIONTOOLWIDGET_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QFormLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QWidget>

namespace Avogadro {
namespace QtPlugins {

class Ui_SelectionToolWidget
{
public:
    QFormLayout *formLayout;
    QLabel *label;
    QPushButton *applyColorButton;
    QLabel *label1;
    QComboBox *changeLayerDropDown;

    void setupUi(QWidget *Avogadro__QtPlugins__SelectionToolWidget)
    {
        if (Avogadro__QtPlugins__SelectionToolWidget->objectName().isEmpty())
            Avogadro__QtPlugins__SelectionToolWidget->setObjectName(QString::fromUtf8("Avogadro__QtPlugins__SelectionToolWidget"));
        Avogadro__QtPlugins__SelectionToolWidget->resize(400, 300);
        formLayout = new QFormLayout(Avogadro__QtPlugins__SelectionToolWidget);
        formLayout->setObjectName(QString::fromUtf8("formLayout"));
        label = new QLabel(Avogadro__QtPlugins__SelectionToolWidget);
        label->setObjectName(QString::fromUtf8("label"));

        formLayout->setWidget(0, QFormLayout::LabelRole, label);

        applyColorButton = new QPushButton(Avogadro__QtPlugins__SelectionToolWidget);
        applyColorButton->setObjectName(QString::fromUtf8("applyColorButton"));
        applyColorButton->setAutoFillBackground(true);

        formLayout->setWidget(0, QFormLayout::FieldRole, applyColorButton);

        label1 = new QLabel(Avogadro__QtPlugins__SelectionToolWidget);
        label1->setObjectName(QString::fromUtf8("label1"));

        formLayout->setWidget(1, QFormLayout::LabelRole, label1);

        changeLayerDropDown = new QComboBox(Avogadro__QtPlugins__SelectionToolWidget);
        changeLayerDropDown->setObjectName(QString::fromUtf8("changeLayerDropDown"));

        formLayout->setWidget(1, QFormLayout::FieldRole, changeLayerDropDown);


        retranslateUi(Avogadro__QtPlugins__SelectionToolWidget);

        QMetaObject::connectSlotsByName(Avogadro__QtPlugins__SelectionToolWidget);
    } // setupUi

    void retranslateUi(QWidget *Avogadro__QtPlugins__SelectionToolWidget)
    {
        Avogadro__QtPlugins__SelectionToolWidget->setWindowTitle(QCoreApplication::translate("Avogadro::QtPlugins::SelectionToolWidget", "Form", nullptr));
        label->setText(QCoreApplication::translate("Avogadro::QtPlugins::SelectionToolWidget", "Apply Color", nullptr));
        applyColorButton->setText(QString());
        label1->setText(QCoreApplication::translate("Avogadro::QtPlugins::SelectionToolWidget", "Change Layer", nullptr));
    } // retranslateUi

};

} // namespace QtPlugins
} // namespace Avogadro

namespace Avogadro {
namespace QtPlugins {
namespace Ui {
    class SelectionToolWidget: public Ui_SelectionToolWidget {};
} // namespace Ui
} // namespace QtPlugins
} // namespace Avogadro

#endif // UI_SELECTIONTOOLWIDGET_H
