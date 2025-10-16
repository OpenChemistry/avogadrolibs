/********************************************************************************
** Form generated from reading UI file 'banddialog.ui'
**
** Created by: Qt User Interface Compiler version 5.15.17
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_BANDDIALOG_H
#define UI_BANDDIALOG_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QDialog>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QDoubleSpinBox>
#include <QtWidgets/QGridLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QSpinBox>
#include <QtWidgets/QTextEdit>

namespace Avogadro {
namespace QtPlugins {

class Ui_BandDialog
{
public:
    QGridLayout *gridLayout;
    QDialogButtonBox *buttonBox;
    QDoubleSpinBox *spin_minY;
    QCheckBox *cb_plotFermi;
    QCheckBox *cb_zeroFermi;
    QLabel *label;
    QLabel *label_2;
    QDoubleSpinBox *spin_maxY;
    QDoubleSpinBox *spin_fermi;
    QTextEdit *edit_specialKPoints;
    QSpinBox *spin_numKPoints;
    QCheckBox *cb_limitY;
    QLabel *label_3;
    QSpinBox *spin_numDim;
    QCheckBox *cb_displayYaehmopInput;

    void setupUi(QDialog *Avogadro__QtPlugins__BandDialog)
    {
        if (Avogadro__QtPlugins__BandDialog->objectName().isEmpty())
            Avogadro__QtPlugins__BandDialog->setObjectName(QString::fromUtf8("Avogadro__QtPlugins__BandDialog"));
        Avogadro__QtPlugins__BandDialog->resize(599, 406);
        gridLayout = new QGridLayout(Avogadro__QtPlugins__BandDialog);
        gridLayout->setObjectName(QString::fromUtf8("gridLayout"));
        buttonBox = new QDialogButtonBox(Avogadro__QtPlugins__BandDialog);
        buttonBox->setObjectName(QString::fromUtf8("buttonBox"));
        buttonBox->setOrientation(Qt::Horizontal);
        buttonBox->setStandardButtons(QDialogButtonBox::Cancel|QDialogButtonBox::Ok);

        gridLayout->addWidget(buttonBox, 11, 1, 1, 3);

        spin_minY = new QDoubleSpinBox(Avogadro__QtPlugins__BandDialog);
        spin_minY->setObjectName(QString::fromUtf8("spin_minY"));
        spin_minY->setEnabled(false);
        spin_minY->setDecimals(5);
        spin_minY->setMinimum(-10000.000000000000000);
        spin_minY->setMaximum(10000.000000000000000);

        gridLayout->addWidget(spin_minY, 6, 1, 1, 1);

        cb_plotFermi = new QCheckBox(Avogadro__QtPlugins__BandDialog);
        cb_plotFermi->setObjectName(QString::fromUtf8("cb_plotFermi"));
        cb_plotFermi->setLayoutDirection(Qt::RightToLeft);

        gridLayout->addWidget(cb_plotFermi, 8, 1, 1, 1);

        cb_zeroFermi = new QCheckBox(Avogadro__QtPlugins__BandDialog);
        cb_zeroFermi->setObjectName(QString::fromUtf8("cb_zeroFermi"));
        cb_zeroFermi->setEnabled(false);
        cb_zeroFermi->setLayoutDirection(Qt::RightToLeft);

        gridLayout->addWidget(cb_zeroFermi, 9, 1, 1, 1);

        label = new QLabel(Avogadro__QtPlugins__BandDialog);
        label->setObjectName(QString::fromUtf8("label"));

        gridLayout->addWidget(label, 0, 1, 1, 1);

        label_2 = new QLabel(Avogadro__QtPlugins__BandDialog);
        label_2->setObjectName(QString::fromUtf8("label_2"));

        gridLayout->addWidget(label_2, 1, 1, 1, 1);

        spin_maxY = new QDoubleSpinBox(Avogadro__QtPlugins__BandDialog);
        spin_maxY->setObjectName(QString::fromUtf8("spin_maxY"));
        spin_maxY->setEnabled(false);
        spin_maxY->setDecimals(5);
        spin_maxY->setMinimum(-1000.000000000000000);
        spin_maxY->setMaximum(1000.000000000000000);

        gridLayout->addWidget(spin_maxY, 6, 2, 1, 2);

        spin_fermi = new QDoubleSpinBox(Avogadro__QtPlugins__BandDialog);
        spin_fermi->setObjectName(QString::fromUtf8("spin_fermi"));
        spin_fermi->setEnabled(false);
        spin_fermi->setDecimals(5);
        spin_fermi->setMinimum(-10000.000000000000000);
        spin_fermi->setMaximum(10000.000000000000000);
        spin_fermi->setSingleStep(0.100000000000000);

        gridLayout->addWidget(spin_fermi, 8, 2, 1, 2);

        edit_specialKPoints = new QTextEdit(Avogadro__QtPlugins__BandDialog);
        edit_specialKPoints->setObjectName(QString::fromUtf8("edit_specialKPoints"));

        gridLayout->addWidget(edit_specialKPoints, 2, 1, 1, 3);

        spin_numKPoints = new QSpinBox(Avogadro__QtPlugins__BandDialog);
        spin_numKPoints->setObjectName(QString::fromUtf8("spin_numKPoints"));
        spin_numKPoints->setAlignment(Qt::AlignLeading|Qt::AlignLeft|Qt::AlignVCenter);
        spin_numKPoints->setMinimum(0);
        spin_numKPoints->setMaximum(999999);
        spin_numKPoints->setValue(40);

        gridLayout->addWidget(spin_numKPoints, 0, 2, 1, 2);

        cb_limitY = new QCheckBox(Avogadro__QtPlugins__BandDialog);
        cb_limitY->setObjectName(QString::fromUtf8("cb_limitY"));

        gridLayout->addWidget(cb_limitY, 4, 2, 1, 2);

        label_3 = new QLabel(Avogadro__QtPlugins__BandDialog);
        label_3->setObjectName(QString::fromUtf8("label_3"));
        label_3->setLayoutDirection(Qt::LeftToRight);
        label_3->setAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);

        gridLayout->addWidget(label_3, 10, 2, 1, 1);

        spin_numDim = new QSpinBox(Avogadro__QtPlugins__BandDialog);
        spin_numDim->setObjectName(QString::fromUtf8("spin_numDim"));
        spin_numDim->setMinimum(1);
        spin_numDim->setMaximum(3);
        spin_numDim->setValue(3);

        gridLayout->addWidget(spin_numDim, 10, 3, 1, 1);

        cb_displayYaehmopInput = new QCheckBox(Avogadro__QtPlugins__BandDialog);
        cb_displayYaehmopInput->setObjectName(QString::fromUtf8("cb_displayYaehmopInput"));

        gridLayout->addWidget(cb_displayYaehmopInput, 3, 2, 1, 1);

        QWidget::setTabOrder(spin_numKPoints, edit_specialKPoints);
        QWidget::setTabOrder(edit_specialKPoints, cb_displayYaehmopInput);
        QWidget::setTabOrder(cb_displayYaehmopInput, cb_limitY);
        QWidget::setTabOrder(cb_limitY, spin_minY);
        QWidget::setTabOrder(spin_minY, spin_maxY);
        QWidget::setTabOrder(spin_maxY, cb_plotFermi);
        QWidget::setTabOrder(cb_plotFermi, spin_fermi);
        QWidget::setTabOrder(spin_fermi, cb_zeroFermi);
        QWidget::setTabOrder(cb_zeroFermi, spin_numDim);

        retranslateUi(Avogadro__QtPlugins__BandDialog);
        QObject::connect(buttonBox, SIGNAL(accepted()), Avogadro__QtPlugins__BandDialog, SLOT(accept()));
        QObject::connect(buttonBox, SIGNAL(rejected()), Avogadro__QtPlugins__BandDialog, SLOT(reject()));
        QObject::connect(cb_limitY, SIGNAL(toggled(bool)), spin_minY, SLOT(setEnabled(bool)));
        QObject::connect(cb_limitY, SIGNAL(toggled(bool)), spin_maxY, SLOT(setEnabled(bool)));
        QObject::connect(cb_plotFermi, SIGNAL(toggled(bool)), spin_fermi, SLOT(setEnabled(bool)));
        QObject::connect(cb_plotFermi, SIGNAL(toggled(bool)), cb_zeroFermi, SLOT(setEnabled(bool)));

        QMetaObject::connectSlotsByName(Avogadro__QtPlugins__BandDialog);
    } // setupUi

    void retranslateUi(QDialog *Avogadro__QtPlugins__BandDialog)
    {
        Avogadro__QtPlugins__BandDialog->setWindowTitle(QCoreApplication::translate("Avogadro::QtPlugins::BandDialog", "Yaehmop Band", nullptr));
        spin_minY->setPrefix(QCoreApplication::translate("Avogadro::QtPlugins::BandDialog", "Min y: ", nullptr));
        spin_minY->setSuffix(QCoreApplication::translate("Avogadro::QtPlugins::BandDialog", " eV", nullptr));
#if QT_CONFIG(tooltip)
        cb_plotFermi->setToolTip(QCoreApplication::translate("Avogadro::QtPlugins::BandDialog", "<html><head/><body><p>The Fermi level should be known before checking this box. You can discover the Fermi level by performing a density of states calculation and displaying the data (it will be at the top of the data). In addition, if a density of states calculation is performed, the Fermi level here will automatically be set to what was detected during the density of states calculation.</p><p>If this box is checked, be sure the correct Fermi level is set in the spinbox on the right.</p><p>Default: off</p></body></html>", nullptr));
#endif // QT_CONFIG(tooltip)
        cb_plotFermi->setText(QCoreApplication::translate("Avogadro::QtPlugins::BandDialog", "Plot Fermi?", nullptr));
#if QT_CONFIG(tooltip)
        cb_zeroFermi->setToolTip(QCoreApplication::translate("Avogadro::QtPlugins::BandDialog", "<html><head/><body><p>Adjust the energies so that the zero is the Fermi? Only available if we are plotting the Fermi level.</p><p><br/></p><p>Default: off</p></body></html>", nullptr));
#endif // QT_CONFIG(tooltip)
        cb_zeroFermi->setText(QCoreApplication::translate("Avogadro::QtPlugins::BandDialog", "Zero Fermi?", nullptr));
        label->setText(QCoreApplication::translate("Avogadro::QtPlugins::BandDialog", "# of k-points connecting special k-points:", nullptr));
        label_2->setText(QCoreApplication::translate("Avogadro::QtPlugins::BandDialog", "Special k-points", nullptr));
        spin_maxY->setPrefix(QCoreApplication::translate("Avogadro::QtPlugins::BandDialog", "Max y: ", nullptr));
        spin_maxY->setSuffix(QCoreApplication::translate("Avogadro::QtPlugins::BandDialog", " eV", nullptr));
#if QT_CONFIG(tooltip)
        spin_fermi->setToolTip(QCoreApplication::translate("Avogadro::QtPlugins::BandDialog", "<html><head/><body><p>The Fermi Level</p></body></html>", nullptr));
#endif // QT_CONFIG(tooltip)
        spin_fermi->setSuffix(QCoreApplication::translate("Avogadro::QtPlugins::BandDialog", " eV", nullptr));
#if QT_CONFIG(tooltip)
        edit_specialKPoints->setToolTip(QCoreApplication::translate("Avogadro::QtPlugins::BandDialog", "<html><head/><body><p>Enter special k-points as such:</p><p>L 0.5 0.5 0.5</p><p>G 0.0 0.0 0.0</p><p>X 0.5 0.0 0.5</p><p>That is, &lt;symbol&gt; &lt;x&gt; &lt;y&gt; &lt;z&gt; where x, y, and z are fractional reciprocal space coordinates. Lines will be drawn connecting these k-points on the graph in the order you put them in. Please note that the orientation of your cell may have an effect on the locations of these reciprocal space points.</p><p>If the space group of the crystal has been perceived or set, the special k points will be automatically filled up with the primitive cell high symmetry points for that space group. There are a few space groups will different high symmetry points depending on the lattice (such as if a &gt; b or a &lt; b) - that is taken into account automatically.</p></body></html>", nullptr));
#endif // QT_CONFIG(tooltip)
        edit_specialKPoints->setHtml(QCoreApplication::translate("Avogadro::QtPlugins::BandDialog", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
"<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
"p, li { white-space: pre-wrap; }\n"
"</style></head><body style=\" font-family:'.AppleSystemUIFont'; font-size:13pt; font-weight:400; font-style:normal;\">\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-family:'Ubuntu'; font-size:11pt;\">GM 0.0 0.0 0.0</span></p></body></html>", nullptr));
#if QT_CONFIG(tooltip)
        spin_numKPoints->setToolTip(QCoreApplication::translate("Avogadro::QtPlugins::BandDialog", "<html><head/><body><p>Enter the number of k-points that will be connecting the special k-points. More of these k-points will smooth out the graph, but the calculation may take longer.</p><p>Default: 40</p></body></html>", nullptr));
#endif // QT_CONFIG(tooltip)
        spin_numKPoints->setSuffix(QString());
#if QT_CONFIG(tooltip)
        cb_limitY->setToolTip(QCoreApplication::translate("Avogadro::QtPlugins::BandDialog", "<html><head/><body><p>Limit the y-range in the plot?</p><p>Default: off</p></body></html>", nullptr));
#endif // QT_CONFIG(tooltip)
        cb_limitY->setText(QCoreApplication::translate("Avogadro::QtPlugins::BandDialog", "Limit y-range?", nullptr));
#if QT_CONFIG(tooltip)
        label_3->setToolTip(QCoreApplication::translate("Avogadro::QtPlugins::BandDialog", "<html><head/><body><p>The number of periodic dimensions.</p><p><br/></p><p>If this is set to 1, the material will be periodic only along the A vector of the crystal.</p><p><br/></p><p>If this is set to 2, the material will be periodic along both the A and B vectors of the crystal.</p><p><br/></p><p>If this is set to 3, the material will be periodic along the A, B, and C vectors of the crystal.</p><p><br/></p></body></html>", nullptr));
#endif // QT_CONFIG(tooltip)
        label_3->setText(QCoreApplication::translate("Avogadro::QtPlugins::BandDialog", "Number of Dimensions:", nullptr));
#if QT_CONFIG(tooltip)
        spin_numDim->setToolTip(QCoreApplication::translate("Avogadro::QtPlugins::BandDialog", "<html><head/><body><p>The number of periodic dimensions.</p><p><br/></p><p>If this is set to 1, the material will be periodic only along the A vector of the crystal.</p><p><br/></p><p>If this is set to 2, the material will be periodic along both the A and B vectors of the crystal.</p><p><br/></p><p>If this is set to 3, the material will be periodic along the A, B, and C vectors of the crystal.</p><p><br/></p></body></html>", nullptr));
#endif // QT_CONFIG(tooltip)
        cb_displayYaehmopInput->setText(QCoreApplication::translate("Avogadro::QtPlugins::BandDialog", "Display Yaehmop Input?", nullptr));
    } // retranslateUi

};

} // namespace QtPlugins
} // namespace Avogadro

namespace Avogadro {
namespace QtPlugins {
namespace Ui {
    class BandDialog: public Ui_BandDialog {};
} // namespace Ui
} // namespace QtPlugins
} // namespace Avogadro

#endif // UI_BANDDIALOG_H
