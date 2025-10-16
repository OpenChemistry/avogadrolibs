/********************************************************************************
** Form generated from reading UI file 'xrdoptionsdialog.ui'
**
** Created by: Qt User Interface Compiler version 5.15.17
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_XRDOPTIONSDIALOG_H
#define UI_XRDOPTIONSDIALOG_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QDialog>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QDoubleSpinBox>
#include <QtWidgets/QGridLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QSpinBox>

namespace Avogadro {
namespace QtPlugins {

class Ui_XrdOptionsDialog
{
public:
    QGridLayout *gridLayout;
    QDoubleSpinBox *spin_max2Theta;
    QDoubleSpinBox *spin_peakWidth;
    QLabel *label_3;
    QLabel *label_2;
    QLabel *label;
    QDoubleSpinBox *spin_wavelength;
    QSpinBox *spin_numDataPoints;
    QLabel *label_4;
    QDialogButtonBox *buttonBox;

    void setupUi(QDialog *Avogadro__QtPlugins__XrdOptionsDialog)
    {
        if (Avogadro__QtPlugins__XrdOptionsDialog->objectName().isEmpty())
            Avogadro__QtPlugins__XrdOptionsDialog->setObjectName(QString::fromUtf8("Avogadro__QtPlugins__XrdOptionsDialog"));
        Avogadro__QtPlugins__XrdOptionsDialog->resize(324, 237);
        gridLayout = new QGridLayout(Avogadro__QtPlugins__XrdOptionsDialog);
        gridLayout->setObjectName(QString::fromUtf8("gridLayout"));
        spin_max2Theta = new QDoubleSpinBox(Avogadro__QtPlugins__XrdOptionsDialog);
        spin_max2Theta->setObjectName(QString::fromUtf8("spin_max2Theta"));
        spin_max2Theta->setDecimals(2);
        spin_max2Theta->setMaximum(360.000000000000000);
        spin_max2Theta->setSingleStep(0.100000000000000);
        spin_max2Theta->setValue(162.000000000000000);

        gridLayout->addWidget(spin_max2Theta, 3, 1, 1, 1);

        spin_peakWidth = new QDoubleSpinBox(Avogadro__QtPlugins__XrdOptionsDialog);
        spin_peakWidth->setObjectName(QString::fromUtf8("spin_peakWidth"));
        spin_peakWidth->setDecimals(5);
        spin_peakWidth->setMaximum(100.000000000000000);
        spin_peakWidth->setSingleStep(0.100000000000000);
        spin_peakWidth->setValue(0.529580000000000);

        gridLayout->addWidget(spin_peakWidth, 1, 1, 1, 1);

        label_3 = new QLabel(Avogadro__QtPlugins__XrdOptionsDialog);
        label_3->setObjectName(QString::fromUtf8("label_3"));
        label_3->setAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);

        gridLayout->addWidget(label_3, 2, 0, 1, 1);

        label_2 = new QLabel(Avogadro__QtPlugins__XrdOptionsDialog);
        label_2->setObjectName(QString::fromUtf8("label_2"));
        label_2->setAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);

        gridLayout->addWidget(label_2, 1, 0, 1, 1);

        label = new QLabel(Avogadro__QtPlugins__XrdOptionsDialog);
        label->setObjectName(QString::fromUtf8("label"));
        label->setAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);

        gridLayout->addWidget(label, 0, 0, 1, 1);

        spin_wavelength = new QDoubleSpinBox(Avogadro__QtPlugins__XrdOptionsDialog);
        spin_wavelength->setObjectName(QString::fromUtf8("spin_wavelength"));
        spin_wavelength->setDecimals(5);
        spin_wavelength->setMinimum(0.000000000000000);
        spin_wavelength->setMaximum(100.000000000000000);
        spin_wavelength->setSingleStep(0.100000000000000);
        spin_wavelength->setValue(1.505600000000000);

        gridLayout->addWidget(spin_wavelength, 0, 1, 1, 1);

        spin_numDataPoints = new QSpinBox(Avogadro__QtPlugins__XrdOptionsDialog);
        spin_numDataPoints->setObjectName(QString::fromUtf8("spin_numDataPoints"));
        spin_numDataPoints->setMinimum(1);
        spin_numDataPoints->setMaximum(100000);
        spin_numDataPoints->setValue(1000);

        gridLayout->addWidget(spin_numDataPoints, 2, 1, 1, 1);

        label_4 = new QLabel(Avogadro__QtPlugins__XrdOptionsDialog);
        label_4->setObjectName(QString::fromUtf8("label_4"));
        label_4->setLayoutDirection(Qt::LeftToRight);
        label_4->setAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);

        gridLayout->addWidget(label_4, 3, 0, 1, 1);

        buttonBox = new QDialogButtonBox(Avogadro__QtPlugins__XrdOptionsDialog);
        buttonBox->setObjectName(QString::fromUtf8("buttonBox"));
        buttonBox->setStandardButtons(QDialogButtonBox::Cancel|QDialogButtonBox::Ok);

        gridLayout->addWidget(buttonBox, 4, 1, 1, 1);

        QWidget::setTabOrder(spin_wavelength, spin_peakWidth);
        QWidget::setTabOrder(spin_peakWidth, spin_numDataPoints);
        QWidget::setTabOrder(spin_numDataPoints, spin_max2Theta);

        retranslateUi(Avogadro__QtPlugins__XrdOptionsDialog);
        QObject::connect(buttonBox, SIGNAL(accepted()), Avogadro__QtPlugins__XrdOptionsDialog, SLOT(accept()));
        QObject::connect(buttonBox, SIGNAL(rejected()), Avogadro__QtPlugins__XrdOptionsDialog, SLOT(reject()));

        QMetaObject::connectSlotsByName(Avogadro__QtPlugins__XrdOptionsDialog);
    } // setupUi

    void retranslateUi(QDialog *Avogadro__QtPlugins__XrdOptionsDialog)
    {
        Avogadro__QtPlugins__XrdOptionsDialog->setWindowTitle(QCoreApplication::translate("Avogadro::QtPlugins::XrdOptionsDialog", "Theoretical XRD Pattern Options", nullptr));
#if QT_CONFIG(tooltip)
        Avogadro__QtPlugins__XrdOptionsDialog->setToolTip(QCoreApplication::translate("Avogadro::QtPlugins::XrdOptionsDialog", "<html><head/><body><p>The broadening of the peak at the base (in degrees).</p></body></html>", nullptr));
#endif // QT_CONFIG(tooltip)
#if QT_CONFIG(tooltip)
        spin_max2Theta->setToolTip(QCoreApplication::translate("Avogadro::QtPlugins::XrdOptionsDialog", "<html><head/><body><p>The max 2theta value in degrees.</p><p>Default: 162.00\302\260</p></body></html>", nullptr));
#endif // QT_CONFIG(tooltip)
        spin_max2Theta->setSuffix(QCoreApplication::translate("Avogadro::QtPlugins::XrdOptionsDialog", "\302\260", nullptr));
#if QT_CONFIG(tooltip)
        spin_peakWidth->setToolTip(QCoreApplication::translate("Avogadro::QtPlugins::XrdOptionsDialog", "<html><head/><body><p>The broadening of the peaks at the base in degrees.</p><p>Default: 0.52958\302\260</p></body></html>", nullptr));
#endif // QT_CONFIG(tooltip)
        spin_peakWidth->setSuffix(QCoreApplication::translate("Avogadro::QtPlugins::XrdOptionsDialog", "\302\260", nullptr));
        label_3->setText(QCoreApplication::translate("Avogadro::QtPlugins::XrdOptionsDialog", "Number of points:", nullptr));
        label_2->setText(QCoreApplication::translate("Avogadro::QtPlugins::XrdOptionsDialog", "Peak width:", nullptr));
        label->setText(QCoreApplication::translate("Avogadro::QtPlugins::XrdOptionsDialog", "Wavelength:", nullptr));
#if QT_CONFIG(tooltip)
        spin_wavelength->setToolTip(QCoreApplication::translate("Avogadro::QtPlugins::XrdOptionsDialog", "<html><head/><body><p>The wavelength of the x-ray in Angstroms. </p><p>Default: 1.50560 \303\205</p></body></html>", nullptr));
#endif // QT_CONFIG(tooltip)
        spin_wavelength->setSuffix(QCoreApplication::translate("Avogadro::QtPlugins::XrdOptionsDialog", " \303\205", nullptr));
#if QT_CONFIG(tooltip)
        spin_numDataPoints->setToolTip(QCoreApplication::translate("Avogadro::QtPlugins::XrdOptionsDialog", "<html><head/><body><p>The number of 2theta points to generate.</p><p>Default: 1000</p></body></html>", nullptr));
#endif // QT_CONFIG(tooltip)
        label_4->setText(QCoreApplication::translate("Avogadro::QtPlugins::XrdOptionsDialog", "Max 2\316\270:", nullptr));
    } // retranslateUi

};

} // namespace QtPlugins
} // namespace Avogadro

namespace Avogadro {
namespace QtPlugins {
namespace Ui {
    class XrdOptionsDialog: public Ui_XrdOptionsDialog {};
} // namespace Ui
} // namespace QtPlugins
} // namespace Avogadro

#endif // UI_XRDOPTIONSDIALOG_H
