/********************************************************************************
** Form generated from reading UI file 'customelementdialog.ui'
**
** Created by: Qt User Interface Compiler version 5.15.17
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_CUSTOMELEMENTDIALOG_H
#define UI_CUSTOMELEMENTDIALOG_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QDialog>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QFormLayout>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QScrollArea>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>

namespace Avogadro {
namespace QtGui {

class Ui_CustomElementDialog
{
public:
    QVBoxLayout *verticalLayout;
    QScrollArea *scrollArea;
    QWidget *scrollAreaWidgetContents;
    QFormLayout *form;
    QSpacerItem *verticalSpacer;
    QHBoxLayout *horizontalLayout;
    QDialogButtonBox *buttonBox;

    void setupUi(QDialog *Avogadro__QtGui__CustomElementDialog)
    {
        if (Avogadro__QtGui__CustomElementDialog->objectName().isEmpty())
            Avogadro__QtGui__CustomElementDialog->setObjectName(QString::fromUtf8("Avogadro__QtGui__CustomElementDialog"));
        Avogadro__QtGui__CustomElementDialog->resize(250, 200);
        verticalLayout = new QVBoxLayout(Avogadro__QtGui__CustomElementDialog);
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        scrollArea = new QScrollArea(Avogadro__QtGui__CustomElementDialog);
        scrollArea->setObjectName(QString::fromUtf8("scrollArea"));
        scrollArea->setWidgetResizable(true);
        scrollAreaWidgetContents = new QWidget();
        scrollAreaWidgetContents->setObjectName(QString::fromUtf8("scrollAreaWidgetContents"));
        scrollAreaWidgetContents->setGeometry(QRect(0, 0, 230, 130));
        form = new QFormLayout(scrollAreaWidgetContents);
        form->setObjectName(QString::fromUtf8("form"));
        form->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);
        form->setLabelAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);
        scrollArea->setWidget(scrollAreaWidgetContents);

        verticalLayout->addWidget(scrollArea);

        verticalSpacer = new QSpacerItem(20, 40, QSizePolicy::Minimum, QSizePolicy::Expanding);

        verticalLayout->addItem(verticalSpacer);

        horizontalLayout = new QHBoxLayout();
        horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));
        buttonBox = new QDialogButtonBox(Avogadro__QtGui__CustomElementDialog);
        buttonBox->setObjectName(QString::fromUtf8("buttonBox"));
        buttonBox->setOrientation(Qt::Horizontal);
        buttonBox->setStandardButtons(QDialogButtonBox::Cancel|QDialogButtonBox::Ok);

        horizontalLayout->addWidget(buttonBox);


        verticalLayout->addLayout(horizontalLayout);


        retranslateUi(Avogadro__QtGui__CustomElementDialog);
        QObject::connect(buttonBox, SIGNAL(accepted()), Avogadro__QtGui__CustomElementDialog, SLOT(accept()));
        QObject::connect(buttonBox, SIGNAL(rejected()), Avogadro__QtGui__CustomElementDialog, SLOT(reject()));

        QMetaObject::connectSlotsByName(Avogadro__QtGui__CustomElementDialog);
    } // setupUi

    void retranslateUi(QDialog *Avogadro__QtGui__CustomElementDialog)
    {
        Avogadro__QtGui__CustomElementDialog->setWindowTitle(QCoreApplication::translate("Avogadro::QtGui::CustomElementDialog", "Rename Elements", nullptr));
    } // retranslateUi

};

} // namespace QtGui
} // namespace Avogadro

namespace Avogadro {
namespace QtGui {
namespace Ui {
    class CustomElementDialog: public Ui_CustomElementDialog {};
} // namespace Ui
} // namespace QtGui
} // namespace Avogadro

#endif // UI_CUSTOMELEMENTDIALOG_H
