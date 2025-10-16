/********************************************************************************
** Form generated from reading UI file 'coordinateeditordialog.ui'
**
** Created by: Qt User Interface Compiler version 5.15.17
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_COORDINATEEDITORDIALOG_H
#define UI_COORDINATEEDITORDIALOG_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QDialog>
#include <QtWidgets/QFormLayout>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QToolButton>
#include <QtWidgets/QVBoxLayout>
#include "coordinatetextedit.h"

namespace Avogadro {
namespace QtPlugins {

class Ui_CoordinateEditorDialog
{
public:
    QVBoxLayout *verticalLayout;
    QFormLayout *formLayout;
    QLabel *label;
    QLabel *label_3;
    QComboBox *distanceUnit;
    QLabel *label_2;
    QHBoxLayout *horizontalLayout;
    QLineEdit *spec;
    QToolButton *help;
    QComboBox *presets;
    Avogadro::QtPlugins::CoordinateTextEdit *text;
    QHBoxLayout *horizontalLayout_2;
    QToolButton *cut;
    QToolButton *copy;
    QToolButton *paste;
    QSpacerItem *horizontalSpacer;
    QPushButton *revert;
    QPushButton *clear;
    QPushButton *apply;

    void setupUi(QDialog *Avogadro__QtPlugins__CoordinateEditorDialog)
    {
        if (Avogadro__QtPlugins__CoordinateEditorDialog->objectName().isEmpty())
            Avogadro__QtPlugins__CoordinateEditorDialog->setObjectName(QString::fromUtf8("Avogadro__QtPlugins__CoordinateEditorDialog"));
        Avogadro__QtPlugins__CoordinateEditorDialog->resize(500, 400);
        verticalLayout = new QVBoxLayout(Avogadro__QtPlugins__CoordinateEditorDialog);
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        formLayout = new QFormLayout();
        formLayout->setObjectName(QString::fromUtf8("formLayout"));
        formLayout->setLabelAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);
        label = new QLabel(Avogadro__QtPlugins__CoordinateEditorDialog);
        label->setObjectName(QString::fromUtf8("label"));

        formLayout->setWidget(0, QFormLayout::LabelRole, label);

        label_3 = new QLabel(Avogadro__QtPlugins__CoordinateEditorDialog);
        label_3->setObjectName(QString::fromUtf8("label_3"));

        formLayout->setWidget(2, QFormLayout::LabelRole, label_3);

        distanceUnit = new QComboBox(Avogadro__QtPlugins__CoordinateEditorDialog);
        distanceUnit->addItem(QString());
        distanceUnit->addItem(QString());
        distanceUnit->setObjectName(QString::fromUtf8("distanceUnit"));

        formLayout->setWidget(2, QFormLayout::FieldRole, distanceUnit);

        label_2 = new QLabel(Avogadro__QtPlugins__CoordinateEditorDialog);
        label_2->setObjectName(QString::fromUtf8("label_2"));

        formLayout->setWidget(1, QFormLayout::LabelRole, label_2);

        horizontalLayout = new QHBoxLayout();
        horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));
        spec = new QLineEdit(Avogadro__QtPlugins__CoordinateEditorDialog);
        spec->setObjectName(QString::fromUtf8("spec"));

        horizontalLayout->addWidget(spec);

        help = new QToolButton(Avogadro__QtPlugins__CoordinateEditorDialog);
        help->setObjectName(QString::fromUtf8("help"));

        horizontalLayout->addWidget(help);


        formLayout->setLayout(1, QFormLayout::FieldRole, horizontalLayout);

        presets = new QComboBox(Avogadro__QtPlugins__CoordinateEditorDialog);
        presets->setObjectName(QString::fromUtf8("presets"));

        formLayout->setWidget(0, QFormLayout::FieldRole, presets);


        verticalLayout->addLayout(formLayout);

        text = new Avogadro::QtPlugins::CoordinateTextEdit(Avogadro__QtPlugins__CoordinateEditorDialog);
        text->setObjectName(QString::fromUtf8("text"));
        text->setLineWrapMode(QTextEdit::NoWrap);

        verticalLayout->addWidget(text);

        horizontalLayout_2 = new QHBoxLayout();
        horizontalLayout_2->setObjectName(QString::fromUtf8("horizontalLayout_2"));
        cut = new QToolButton(Avogadro__QtPlugins__CoordinateEditorDialog);
        cut->setObjectName(QString::fromUtf8("cut"));

        horizontalLayout_2->addWidget(cut);

        copy = new QToolButton(Avogadro__QtPlugins__CoordinateEditorDialog);
        copy->setObjectName(QString::fromUtf8("copy"));

        horizontalLayout_2->addWidget(copy);

        paste = new QToolButton(Avogadro__QtPlugins__CoordinateEditorDialog);
        paste->setObjectName(QString::fromUtf8("paste"));

        horizontalLayout_2->addWidget(paste);

        horizontalSpacer = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_2->addItem(horizontalSpacer);

        revert = new QPushButton(Avogadro__QtPlugins__CoordinateEditorDialog);
        revert->setObjectName(QString::fromUtf8("revert"));

        horizontalLayout_2->addWidget(revert);

        clear = new QPushButton(Avogadro__QtPlugins__CoordinateEditorDialog);
        clear->setObjectName(QString::fromUtf8("clear"));

        horizontalLayout_2->addWidget(clear);

        apply = new QPushButton(Avogadro__QtPlugins__CoordinateEditorDialog);
        apply->setObjectName(QString::fromUtf8("apply"));

        horizontalLayout_2->addWidget(apply);


        verticalLayout->addLayout(horizontalLayout_2);

#if QT_CONFIG(shortcut)
        label->setBuddy(presets);
        label_3->setBuddy(distanceUnit);
        label_2->setBuddy(spec);
#endif // QT_CONFIG(shortcut)
        QWidget::setTabOrder(presets, spec);
        QWidget::setTabOrder(spec, help);
        QWidget::setTabOrder(help, distanceUnit);
        QWidget::setTabOrder(distanceUnit, text);
        QWidget::setTabOrder(text, cut);
        QWidget::setTabOrder(cut, copy);
        QWidget::setTabOrder(copy, paste);
        QWidget::setTabOrder(paste, revert);
        QWidget::setTabOrder(revert, clear);
        QWidget::setTabOrder(clear, apply);

        retranslateUi(Avogadro__QtPlugins__CoordinateEditorDialog);

        QMetaObject::connectSlotsByName(Avogadro__QtPlugins__CoordinateEditorDialog);
    } // setupUi

    void retranslateUi(QDialog *Avogadro__QtPlugins__CoordinateEditorDialog)
    {
        Avogadro__QtPlugins__CoordinateEditorDialog->setWindowTitle(QCoreApplication::translate("Avogadro::QtPlugins::CoordinateEditorDialog", "Coordinate Editor", nullptr));
        label->setText(QCoreApplication::translate("Avogadro::QtPlugins::CoordinateEditorDialog", "Preset:", nullptr));
        label_3->setText(QCoreApplication::translate("Avogadro::QtPlugins::CoordinateEditorDialog", "Distance Unit:", nullptr));
        distanceUnit->setItemText(0, QCoreApplication::translate("Avogadro::QtPlugins::CoordinateEditorDialog", "Angstrom", nullptr));
        distanceUnit->setItemText(1, QCoreApplication::translate("Avogadro::QtPlugins::CoordinateEditorDialog", "Bohr", nullptr));

        label_2->setText(QCoreApplication::translate("Avogadro::QtPlugins::CoordinateEditorDialog", "Format:", nullptr));
#if QT_CONFIG(tooltip)
        spec->setToolTip(QCoreApplication::translate("Avogadro::QtPlugins::CoordinateEditorDialog", "<html><head/><body><p>Specification of format. Each character indicates a value to write per atom:</p><p><span style=\" font-weight:600;\">#</span> - Atom index (1, 2, ..., numAtoms)<br/><span style=\" font-weight:600;\">Z</span> - Atomic number (e.g. &quot;6&quot; for carbon)<br/><span style=\" font-weight:600;\">G</span> - GAMESS-style atomic number (e.g. &quot;6.0&quot; for carbon)<br/><span style=\" font-weight:600;\">N</span> - Element name (e.g. &quot;Carbon&quot;)<br/><span style=\" font-weight:600;\">S</span> - Element symbol (e.g. &quot;C&quot; for carbon)<br/><span style=\" font-weight:700;\">L</span> - Atom label (e.g., &quot;C2&quot; for second carbon atom, &quot;H1&quot; for first hydrogen) <br/><span style=\" font-weight:600;\">x</span> - X position coordinate<br/><span style=\" font-weight:600;\">y</span> - Y position coordinate<br/><span style=\" font-weight:600;\">z</span> - Z position coordinate<br/><span style=\" font-weight:600;\">a</span> - 'a' lattice coordinate (crystals only)<br/><span "
                        "style=\" font-weight:600;\">b</span> - 'b' lattice coordinate (crystals only)<br/><span style=\" font-weight:600;\">c</span> - 'c' lattice coordinate (crystals only)<br/><span style=\" font-weight:600;\">_</span> - A literal space (&quot; &quot;), useful for alignment<br/><span style=\" font-weight:600;\">0</span> - A literal 0 (&quot;0&quot;), useful for optimization flags<br/><span style=\" font-weight:600;\">1</span> - A literal 1 (&quot;1&quot;), useful for optimization flags<br/></p></body></html>", nullptr));
#endif // QT_CONFIG(tooltip)
        help->setText(QCoreApplication::translate("Avogadro::QtPlugins::CoordinateEditorDialog", "Help\342\200\246", nullptr));
        cut->setText(QCoreApplication::translate("Avogadro::QtPlugins::CoordinateEditorDialog", "Cut", nullptr));
        copy->setText(QCoreApplication::translate("Avogadro::QtPlugins::CoordinateEditorDialog", "Copy", nullptr));
        paste->setText(QCoreApplication::translate("Avogadro::QtPlugins::CoordinateEditorDialog", "Paste", nullptr));
        revert->setText(QCoreApplication::translate("Avogadro::QtPlugins::CoordinateEditorDialog", "Revert", nullptr));
        clear->setText(QCoreApplication::translate("Avogadro::QtPlugins::CoordinateEditorDialog", "Clear", nullptr));
        apply->setText(QCoreApplication::translate("Avogadro::QtPlugins::CoordinateEditorDialog", "Apply", nullptr));
    } // retranslateUi

};

} // namespace QtPlugins
} // namespace Avogadro

namespace Avogadro {
namespace QtPlugins {
namespace Ui {
    class CoordinateEditorDialog: public Ui_CoordinateEditorDialog {};
} // namespace Ui
} // namespace QtPlugins
} // namespace Avogadro

#endif // UI_COORDINATEEDITORDIALOG_H
