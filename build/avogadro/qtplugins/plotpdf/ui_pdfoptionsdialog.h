/********************************************************************************
** Form generated from reading UI file 'pdfoptionsdialog.ui'
**
** Created by: Qt User Interface Compiler version 5.15.17
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_PDFOPTIONSDIALOG_H
#define UI_PDFOPTIONSDIALOG_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QDialog>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QDoubleSpinBox>
#include <QtWidgets/QGridLayout>
#include <QtWidgets/QLabel>

namespace Avogadro {
namespace QtPlugins {

class Ui_PdfOptionsDialog
{
public:
    QGridLayout *gridLayout;
    QLabel *label;
    QDoubleSpinBox *spin_maxRadius;
    QLabel *label2;
    QDoubleSpinBox *spin_step;
    QDialogButtonBox *buttonBox;

    void setupUi(QDialog *Avogadro__QtPlugins__PdfOptionsDialog)
    {
        if (Avogadro__QtPlugins__PdfOptionsDialog->objectName().isEmpty())
            Avogadro__QtPlugins__PdfOptionsDialog->setObjectName(QString::fromUtf8("Avogadro__QtPlugins__PdfOptionsDialog"));
        Avogadro__QtPlugins__PdfOptionsDialog->resize(324, 145);
        gridLayout = new QGridLayout(Avogadro__QtPlugins__PdfOptionsDialog);
        gridLayout->setObjectName(QString::fromUtf8("gridLayout"));
        label = new QLabel(Avogadro__QtPlugins__PdfOptionsDialog);
        label->setObjectName(QString::fromUtf8("label"));
        label->setAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);

        gridLayout->addWidget(label, 0, 0, 1, 1);

        spin_maxRadius = new QDoubleSpinBox(Avogadro__QtPlugins__PdfOptionsDialog);
        spin_maxRadius->setObjectName(QString::fromUtf8("spin_maxRadius"));
        spin_maxRadius->setDecimals(5);
        spin_maxRadius->setMinimum(0.000010000000000);
        spin_maxRadius->setMaximum(100.000000000000000);
        spin_maxRadius->setValue(10.000000000000000);

        gridLayout->addWidget(spin_maxRadius, 0, 1, 1, 1);

        label2 = new QLabel(Avogadro__QtPlugins__PdfOptionsDialog);
        label2->setObjectName(QString::fromUtf8("label2"));
        label2->setAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);

        gridLayout->addWidget(label2, 1, 0, 1, 1);

        spin_step = new QDoubleSpinBox(Avogadro__QtPlugins__PdfOptionsDialog);
        spin_step->setObjectName(QString::fromUtf8("spin_step"));
        spin_step->setDecimals(5);
        spin_step->setMinimum(0.000010000000000);
        spin_step->setMaximum(100.000000000000000);
        spin_step->setValue(10.000000000000000);

        gridLayout->addWidget(spin_step, 1, 1, 1, 1);

        buttonBox = new QDialogButtonBox(Avogadro__QtPlugins__PdfOptionsDialog);
        buttonBox->setObjectName(QString::fromUtf8("buttonBox"));
        buttonBox->setStandardButtons(QDialogButtonBox::Cancel|QDialogButtonBox::Ok);

        gridLayout->addWidget(buttonBox, 2, 1, 1, 1);

        QWidget::setTabOrder(spin_maxRadius, spin_step);

        retranslateUi(Avogadro__QtPlugins__PdfOptionsDialog);
        QObject::connect(buttonBox, SIGNAL(accepted()), Avogadro__QtPlugins__PdfOptionsDialog, SLOT(accept()));
        QObject::connect(buttonBox, SIGNAL(rejected()), Avogadro__QtPlugins__PdfOptionsDialog, SLOT(reject()));

        QMetaObject::connectSlotsByName(Avogadro__QtPlugins__PdfOptionsDialog);
    } // setupUi

    void retranslateUi(QDialog *Avogadro__QtPlugins__PdfOptionsDialog)
    {
        Avogadro__QtPlugins__PdfOptionsDialog->setWindowTitle(QCoreApplication::translate("Avogadro::QtPlugins::PdfOptionsDialog", "PDF Plot Options", nullptr));
        label->setText(QCoreApplication::translate("Avogadro::QtPlugins::PdfOptionsDialog", "Maximum Radius:", nullptr));
        spin_maxRadius->setSuffix(QCoreApplication::translate("Avogadro::QtPlugins::PdfOptionsDialog", " \303\205", nullptr));
        label2->setText(QCoreApplication::translate("Avogadro::QtPlugins::PdfOptionsDialog", "Step (dr):", nullptr));
        spin_step->setSuffix(QCoreApplication::translate("Avogadro::QtPlugins::PdfOptionsDialog", " \303\205", nullptr));
    } // retranslateUi

};

} // namespace QtPlugins
} // namespace Avogadro

namespace Avogadro {
namespace QtPlugins {
namespace Ui {
    class PdfOptionsDialog: public Ui_PdfOptionsDialog {};
} // namespace Ui
} // namespace QtPlugins
} // namespace Avogadro

#endif // UI_PDFOPTIONSDIALOG_H
