/********************************************************************************
** Form generated from reading UI file 'lineformatinputdialog.ui'
**
** Created by: Qt User Interface Compiler version 5.15.17
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_LINEFORMATINPUTDIALOG_H
#define UI_LINEFORMATINPUTDIALOG_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QDialog>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QFormLayout>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QVBoxLayout>

namespace Avogadro {
namespace QtPlugins {

class Ui_LineFormatInputDialog
{
public:
    QVBoxLayout *verticalLayout_2;
    QFormLayout *formLayout;
    QLabel *label;
    QLabel *label_2;
    QLineEdit *descriptor;
    QHBoxLayout *horizontalLayout;
    QComboBox *formats;
    QSpacerItem *spacer;
    QDialogButtonBox *buttonBox;

    void setupUi(QDialog *Avogadro__QtPlugins__LineFormatInputDialog)
    {
        if (Avogadro__QtPlugins__LineFormatInputDialog->objectName().isEmpty())
            Avogadro__QtPlugins__LineFormatInputDialog->setObjectName(QString::fromUtf8("Avogadro__QtPlugins__LineFormatInputDialog"));
        Avogadro__QtPlugins__LineFormatInputDialog->resize(269, 123);
        QSizePolicy sizePolicy(QSizePolicy::Preferred, QSizePolicy::Minimum);
        sizePolicy.setHorizontalStretch(0);
        sizePolicy.setVerticalStretch(0);
        sizePolicy.setHeightForWidth(Avogadro__QtPlugins__LineFormatInputDialog->sizePolicy().hasHeightForWidth());
        Avogadro__QtPlugins__LineFormatInputDialog->setSizePolicy(sizePolicy);
        verticalLayout_2 = new QVBoxLayout(Avogadro__QtPlugins__LineFormatInputDialog);
        verticalLayout_2->setObjectName(QString::fromUtf8("verticalLayout_2"));
        formLayout = new QFormLayout();
        formLayout->setObjectName(QString::fromUtf8("formLayout"));
        formLayout->setFieldGrowthPolicy(QFormLayout::ExpandingFieldsGrow);
        label = new QLabel(Avogadro__QtPlugins__LineFormatInputDialog);
        label->setObjectName(QString::fromUtf8("label"));
        label->setAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);

        formLayout->setWidget(0, QFormLayout::LabelRole, label);

        label_2 = new QLabel(Avogadro__QtPlugins__LineFormatInputDialog);
        label_2->setObjectName(QString::fromUtf8("label_2"));
        label_2->setAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);

        formLayout->setWidget(1, QFormLayout::LabelRole, label_2);

        descriptor = new QLineEdit(Avogadro__QtPlugins__LineFormatInputDialog);
        descriptor->setObjectName(QString::fromUtf8("descriptor"));

        formLayout->setWidget(1, QFormLayout::FieldRole, descriptor);

        horizontalLayout = new QHBoxLayout();
        horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));
        formats = new QComboBox(Avogadro__QtPlugins__LineFormatInputDialog);
        formats->setObjectName(QString::fromUtf8("formats"));

        horizontalLayout->addWidget(formats);

        spacer = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout->addItem(spacer);


        formLayout->setLayout(0, QFormLayout::FieldRole, horizontalLayout);


        verticalLayout_2->addLayout(formLayout);

        buttonBox = new QDialogButtonBox(Avogadro__QtPlugins__LineFormatInputDialog);
        buttonBox->setObjectName(QString::fromUtf8("buttonBox"));
        buttonBox->setOrientation(Qt::Horizontal);
        buttonBox->setStandardButtons(QDialogButtonBox::Cancel|QDialogButtonBox::Ok);

        verticalLayout_2->addWidget(buttonBox);


        retranslateUi(Avogadro__QtPlugins__LineFormatInputDialog);
        QObject::connect(buttonBox, SIGNAL(accepted()), Avogadro__QtPlugins__LineFormatInputDialog, SLOT(accept()));
        QObject::connect(buttonBox, SIGNAL(rejected()), Avogadro__QtPlugins__LineFormatInputDialog, SLOT(reject()));

        QMetaObject::connectSlotsByName(Avogadro__QtPlugins__LineFormatInputDialog);
    } // setupUi

    void retranslateUi(QDialog *Avogadro__QtPlugins__LineFormatInputDialog)
    {
        Avogadro__QtPlugins__LineFormatInputDialog->setWindowTitle(QCoreApplication::translate("Avogadro::QtPlugins::LineFormatInputDialog", "Insert Molecule\342\200\246", nullptr));
        label->setText(QCoreApplication::translate("Avogadro::QtPlugins::LineFormatInputDialog", "Format:", nullptr));
        label_2->setText(QCoreApplication::translate("Avogadro::QtPlugins::LineFormatInputDialog", "Descriptor:", nullptr));
    } // retranslateUi

};

} // namespace QtPlugins
} // namespace Avogadro

namespace Avogadro {
namespace QtPlugins {
namespace Ui {
    class LineFormatInputDialog: public Ui_LineFormatInputDialog {};
} // namespace Ui
} // namespace QtPlugins
} // namespace Avogadro

#endif // UI_LINEFORMATINPUTDIALOG_H
