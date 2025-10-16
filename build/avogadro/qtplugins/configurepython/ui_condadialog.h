/********************************************************************************
** Form generated from reading UI file 'condadialog.ui'
**
** Created by: Qt User Interface Compiler version 5.15.17
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_CONDADIALOG_H
#define UI_CONDADIALOG_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QDialog>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QVBoxLayout>

namespace Avogadro {
namespace QtPlugins {

class Ui_CondaDialog
{
public:
    QVBoxLayout *verticalLayout_2;
    QLabel *textLabel;
    QHBoxLayout *horizontalLayout;
    QLabel *label;
    QLineEdit *environmentName;
    QSpacerItem *verticalSpacer;
    QDialogButtonBox *buttonBox;

    void setupUi(QDialog *Avogadro__QtPlugins__CondaDialog)
    {
        if (Avogadro__QtPlugins__CondaDialog->objectName().isEmpty())
            Avogadro__QtPlugins__CondaDialog->setObjectName(QString::fromUtf8("Avogadro__QtPlugins__CondaDialog"));
        Avogadro__QtPlugins__CondaDialog->resize(376, 169);
        QSizePolicy sizePolicy(QSizePolicy::Preferred, QSizePolicy::Minimum);
        sizePolicy.setHorizontalStretch(0);
        sizePolicy.setVerticalStretch(0);
        sizePolicy.setHeightForWidth(Avogadro__QtPlugins__CondaDialog->sizePolicy().hasHeightForWidth());
        Avogadro__QtPlugins__CondaDialog->setSizePolicy(sizePolicy);
        verticalLayout_2 = new QVBoxLayout(Avogadro__QtPlugins__CondaDialog);
        verticalLayout_2->setObjectName(QString::fromUtf8("verticalLayout_2"));
        textLabel = new QLabel(Avogadro__QtPlugins__CondaDialog);
        textLabel->setObjectName(QString::fromUtf8("textLabel"));

        verticalLayout_2->addWidget(textLabel);

        horizontalLayout = new QHBoxLayout();
        horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));
        label = new QLabel(Avogadro__QtPlugins__CondaDialog);
        label->setObjectName(QString::fromUtf8("label"));

        horizontalLayout->addWidget(label);

        environmentName = new QLineEdit(Avogadro__QtPlugins__CondaDialog);
        environmentName->setObjectName(QString::fromUtf8("environmentName"));

        horizontalLayout->addWidget(environmentName);


        verticalLayout_2->addLayout(horizontalLayout);

        verticalSpacer = new QSpacerItem(20, 0, QSizePolicy::Minimum, QSizePolicy::Expanding);

        verticalLayout_2->addItem(verticalSpacer);

        buttonBox = new QDialogButtonBox(Avogadro__QtPlugins__CondaDialog);
        buttonBox->setObjectName(QString::fromUtf8("buttonBox"));
        buttonBox->setOrientation(Qt::Horizontal);
        buttonBox->setStandardButtons(QDialogButtonBox::Cancel|QDialogButtonBox::Ok);

        verticalLayout_2->addWidget(buttonBox);


        retranslateUi(Avogadro__QtPlugins__CondaDialog);
        QObject::connect(buttonBox, SIGNAL(accepted()), Avogadro__QtPlugins__CondaDialog, SLOT(accept()));
        QObject::connect(buttonBox, SIGNAL(rejected()), Avogadro__QtPlugins__CondaDialog, SLOT(reject()));

        QMetaObject::connectSlotsByName(Avogadro__QtPlugins__CondaDialog);
    } // setupUi

    void retranslateUi(QDialog *Avogadro__QtPlugins__CondaDialog)
    {
        Avogadro__QtPlugins__CondaDialog->setWindowTitle(QCoreApplication::translate("Avogadro::QtPlugins::CondaDialog", "Python Settings\342\200\246", nullptr));
        textLabel->setText(QCoreApplication::translate("Avogadro::QtPlugins::CondaDialog", "Only the \342\200\234base\342\200\235 conda environment exists.\n"
"Would you like to create a new environment for Avogadro?\n"
"This will make a copy of your base environment.\n"
"", nullptr));
        label->setText(QCoreApplication::translate("Avogadro::QtPlugins::CondaDialog", "Environment name:", nullptr));
        environmentName->setPlaceholderText(QCoreApplication::translate("Avogadro::QtPlugins::CondaDialog", "avogadro", nullptr));
    } // retranslateUi

};

} // namespace QtPlugins
} // namespace Avogadro

namespace Avogadro {
namespace QtPlugins {
namespace Ui {
    class CondaDialog: public Ui_CondaDialog {};
} // namespace Ui
} // namespace QtPlugins
} // namespace Avogadro

#endif // UI_CONDADIALOG_H
