/********************************************************************************
** Form generated from reading UI file '3dmoldialog.ui'
**
** Created by: Qt User Interface Compiler version 5.15.17
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_3DMOLDIALOG_H
#define UI_3DMOLDIALOG_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QDialog>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QPlainTextEdit>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QVBoxLayout>

namespace Avogadro {
namespace QtPlugins {

class Ui_ThreeDMolDialog
{
public:
    QVBoxLayout *verticalLayout;
    QVBoxLayout *verticalLayout_2;
    QPlainTextEdit *plainTextEdit;
    QHBoxLayout *horizontalLayout_3;
    QPushButton *copyButton;
    QPushButton *closeButton;

    void setupUi(QDialog *Avogadro__QtPlugins__ThreeDMolDialog)
    {
        if (Avogadro__QtPlugins__ThreeDMolDialog->objectName().isEmpty())
            Avogadro__QtPlugins__ThreeDMolDialog->setObjectName(QString::fromUtf8("Avogadro__QtPlugins__ThreeDMolDialog"));
        Avogadro__QtPlugins__ThreeDMolDialog->setEnabled(true);
        Avogadro__QtPlugins__ThreeDMolDialog->resize(370, 257);
        verticalLayout = new QVBoxLayout(Avogadro__QtPlugins__ThreeDMolDialog);
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        verticalLayout_2 = new QVBoxLayout();
        verticalLayout_2->setObjectName(QString::fromUtf8("verticalLayout_2"));
        plainTextEdit = new QPlainTextEdit(Avogadro__QtPlugins__ThreeDMolDialog);
        plainTextEdit->setObjectName(QString::fromUtf8("plainTextEdit"));
        plainTextEdit->setReadOnly(true);

        verticalLayout_2->addWidget(plainTextEdit);

        horizontalLayout_3 = new QHBoxLayout();
        horizontalLayout_3->setObjectName(QString::fromUtf8("horizontalLayout_3"));
        copyButton = new QPushButton(Avogadro__QtPlugins__ThreeDMolDialog);
        copyButton->setObjectName(QString::fromUtf8("copyButton"));

        horizontalLayout_3->addWidget(copyButton);

        closeButton = new QPushButton(Avogadro__QtPlugins__ThreeDMolDialog);
        closeButton->setObjectName(QString::fromUtf8("closeButton"));

        horizontalLayout_3->addWidget(closeButton);


        verticalLayout_2->addLayout(horizontalLayout_3);


        verticalLayout->addLayout(verticalLayout_2);


        retranslateUi(Avogadro__QtPlugins__ThreeDMolDialog);

        QMetaObject::connectSlotsByName(Avogadro__QtPlugins__ThreeDMolDialog);
    } // setupUi

    void retranslateUi(QDialog *Avogadro__QtPlugins__ThreeDMolDialog)
    {
        Avogadro__QtPlugins__ThreeDMolDialog->setWindowTitle(QCoreApplication::translate("Avogadro::QtPlugins::ThreeDMolDialog", "3DMol HTML Snippet", nullptr));
        copyButton->setText(QCoreApplication::translate("Avogadro::QtPlugins::ThreeDMolDialog", "&Copy to Clipboard", nullptr));
#if QT_CONFIG(shortcut)
        copyButton->setShortcut(QCoreApplication::translate("Avogadro::QtPlugins::ThreeDMolDialog", "Ctrl+C", nullptr));
#endif // QT_CONFIG(shortcut)
        closeButton->setText(QCoreApplication::translate("Avogadro::QtPlugins::ThreeDMolDialog", "Close", nullptr));
    } // retranslateUi

};

} // namespace QtPlugins
} // namespace Avogadro

namespace Avogadro {
namespace QtPlugins {
namespace Ui {
    class ThreeDMolDialog: public Ui_ThreeDMolDialog {};
} // namespace Ui
} // namespace QtPlugins
} // namespace Avogadro

#endif // UI_3DMOLDIALOG_H
