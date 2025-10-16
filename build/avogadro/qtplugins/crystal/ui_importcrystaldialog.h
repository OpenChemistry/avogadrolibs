/********************************************************************************
** Form generated from reading UI file 'importcrystaldialog.ui'
**
** Created by: Qt User Interface Compiler version 5.15.17
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_IMPORTCRYSTALDIALOG_H
#define UI_IMPORTCRYSTALDIALOG_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QDialog>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QGridLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QTextEdit>

namespace Avogadro {
namespace QtPlugins {

class Ui_ImportCrystalDialog
{
public:
    QGridLayout *gridLayout;
    QLabel *label;
    QLineEdit *edit_extension;
    QDialogButtonBox *buttonBox;
    QTextEdit *edit_text;

    void setupUi(QDialog *Avogadro__QtPlugins__ImportCrystalDialog)
    {
        if (Avogadro__QtPlugins__ImportCrystalDialog->objectName().isEmpty())
            Avogadro__QtPlugins__ImportCrystalDialog->setObjectName(QString::fromUtf8("Avogadro__QtPlugins__ImportCrystalDialog"));
        Avogadro__QtPlugins__ImportCrystalDialog->resize(400, 300);
        gridLayout = new QGridLayout(Avogadro__QtPlugins__ImportCrystalDialog);
        gridLayout->setObjectName(QString::fromUtf8("gridLayout"));
        label = new QLabel(Avogadro__QtPlugins__ImportCrystalDialog);
        label->setObjectName(QString::fromUtf8("label"));

        gridLayout->addWidget(label, 0, 0, 1, 1);

        edit_extension = new QLineEdit(Avogadro__QtPlugins__ImportCrystalDialog);
        edit_extension->setObjectName(QString::fromUtf8("edit_extension"));

        gridLayout->addWidget(edit_extension, 0, 1, 1, 1);

        buttonBox = new QDialogButtonBox(Avogadro__QtPlugins__ImportCrystalDialog);
        buttonBox->setObjectName(QString::fromUtf8("buttonBox"));
        buttonBox->setOrientation(Qt::Horizontal);
        buttonBox->setStandardButtons(QDialogButtonBox::Cancel|QDialogButtonBox::Ok);

        gridLayout->addWidget(buttonBox, 2, 0, 1, 2);

        edit_text = new QTextEdit(Avogadro__QtPlugins__ImportCrystalDialog);
        edit_text->setObjectName(QString::fromUtf8("edit_text"));

        gridLayout->addWidget(edit_text, 1, 0, 1, 2);

#if QT_CONFIG(shortcut)
        label->setBuddy(edit_extension);
#endif // QT_CONFIG(shortcut)

        retranslateUi(Avogadro__QtPlugins__ImportCrystalDialog);
        QObject::connect(buttonBox, SIGNAL(accepted()), Avogadro__QtPlugins__ImportCrystalDialog, SLOT(accept()));
        QObject::connect(buttonBox, SIGNAL(rejected()), Avogadro__QtPlugins__ImportCrystalDialog, SLOT(reject()));

        QMetaObject::connectSlotsByName(Avogadro__QtPlugins__ImportCrystalDialog);
    } // setupUi

    void retranslateUi(QDialog *Avogadro__QtPlugins__ImportCrystalDialog)
    {
        Avogadro__QtPlugins__ImportCrystalDialog->setWindowTitle(QCoreApplication::translate("Avogadro::QtPlugins::ImportCrystalDialog", "Import Crystal", nullptr));
        label->setText(QCoreApplication::translate("Avogadro::QtPlugins::ImportCrystalDialog", "File extension for Open Babel conversion (default - Avogadro::POSCAR):", nullptr));
    } // retranslateUi

};

} // namespace QtPlugins
} // namespace Avogadro

namespace Avogadro {
namespace QtPlugins {
namespace Ui {
    class ImportCrystalDialog: public Ui_ImportCrystalDialog {};
} // namespace Ui
} // namespace QtPlugins
} // namespace Avogadro

#endif // UI_IMPORTCRYSTALDIALOG_H
