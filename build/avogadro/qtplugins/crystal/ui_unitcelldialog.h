/********************************************************************************
** Form generated from reading UI file 'unitcelldialog.ui'
**
** Created by: Qt User Interface Compiler version 5.15.17
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_UNITCELLDIALOG_H
#define UI_UNITCELLDIALOG_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QDialog>
#include <QtWidgets/QDoubleSpinBox>
#include <QtWidgets/QFormLayout>
#include <QtWidgets/QFrame>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QPlainTextEdit>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QVBoxLayout>

namespace Avogadro {
namespace QtPlugins {

class Ui_UnitCellDialog
{
public:
    QVBoxLayout *verticalLayout;
    QHBoxLayout *horizontalLayout;
    QFormLayout *formLayout;
    QLabel *label;
    QDoubleSpinBox *a;
    QLabel *label_2;
    QDoubleSpinBox *b;
    QLabel *label_4;
    QDoubleSpinBox *c;
    QFormLayout *formLayout_2;
    QLabel *label_3;
    QLabel *label_5;
    QLabel *label_6;
    QDoubleSpinBox *alpha;
    QDoubleSpinBox *gamma;
    QDoubleSpinBox *beta;
    QFrame *line_2;
    QLabel *label_7;
    QPlainTextEdit *cellMatrix;
    QFrame *line;
    QLabel *label_8;
    QPlainTextEdit *fractionalMatrix;
    QSpacerItem *verticalSpacer;
    QFrame *line_3;
    QCheckBox *transformAtoms;
    QHBoxLayout *horizontalLayout_2;
    QSpacerItem *horizontalSpacer;
    QPushButton *apply;
    QPushButton *revert;
    QPushButton *pushButton;

    void setupUi(QDialog *Avogadro__QtPlugins__UnitCellDialog)
    {
        if (Avogadro__QtPlugins__UnitCellDialog->objectName().isEmpty())
            Avogadro__QtPlugins__UnitCellDialog->setObjectName(QString::fromUtf8("Avogadro__QtPlugins__UnitCellDialog"));
        Avogadro__QtPlugins__UnitCellDialog->resize(334, 431);
        verticalLayout = new QVBoxLayout(Avogadro__QtPlugins__UnitCellDialog);
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        horizontalLayout = new QHBoxLayout();
        horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));
        formLayout = new QFormLayout();
        formLayout->setObjectName(QString::fromUtf8("formLayout"));
        formLayout->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);
        label = new QLabel(Avogadro__QtPlugins__UnitCellDialog);
        label->setObjectName(QString::fromUtf8("label"));
        label->setAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);

        formLayout->setWidget(0, QFormLayout::LabelRole, label);

        a = new QDoubleSpinBox(Avogadro__QtPlugins__UnitCellDialog);
        a->setObjectName(QString::fromUtf8("a"));
        a->setDecimals(5);
        a->setMinimum(0.010000000000000);
        a->setMaximum(1000000.000000000000000);
        a->setSingleStep(0.100000000000000);
        a->setValue(3.000000000000000);

        formLayout->setWidget(0, QFormLayout::FieldRole, a);

        label_2 = new QLabel(Avogadro__QtPlugins__UnitCellDialog);
        label_2->setObjectName(QString::fromUtf8("label_2"));
        label_2->setAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);

        formLayout->setWidget(1, QFormLayout::LabelRole, label_2);

        b = new QDoubleSpinBox(Avogadro__QtPlugins__UnitCellDialog);
        b->setObjectName(QString::fromUtf8("b"));
        b->setDecimals(5);
        b->setMinimum(0.010000000000000);
        b->setMaximum(1000000.000000000000000);
        b->setSingleStep(0.100000000000000);
        b->setValue(3.000000000000000);

        formLayout->setWidget(1, QFormLayout::FieldRole, b);

        label_4 = new QLabel(Avogadro__QtPlugins__UnitCellDialog);
        label_4->setObjectName(QString::fromUtf8("label_4"));
        label_4->setAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);

        formLayout->setWidget(2, QFormLayout::LabelRole, label_4);

        c = new QDoubleSpinBox(Avogadro__QtPlugins__UnitCellDialog);
        c->setObjectName(QString::fromUtf8("c"));
        c->setDecimals(5);
        c->setMinimum(0.010000000000000);
        c->setMaximum(1000000.000000000000000);
        c->setSingleStep(0.100000000000000);
        c->setValue(3.000000000000000);

        formLayout->setWidget(2, QFormLayout::FieldRole, c);


        horizontalLayout->addLayout(formLayout);

        formLayout_2 = new QFormLayout();
        formLayout_2->setObjectName(QString::fromUtf8("formLayout_2"));
        formLayout_2->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);
        label_3 = new QLabel(Avogadro__QtPlugins__UnitCellDialog);
        label_3->setObjectName(QString::fromUtf8("label_3"));
        label_3->setAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);

        formLayout_2->setWidget(0, QFormLayout::LabelRole, label_3);

        label_5 = new QLabel(Avogadro__QtPlugins__UnitCellDialog);
        label_5->setObjectName(QString::fromUtf8("label_5"));
        label_5->setAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);

        formLayout_2->setWidget(1, QFormLayout::LabelRole, label_5);

        label_6 = new QLabel(Avogadro__QtPlugins__UnitCellDialog);
        label_6->setObjectName(QString::fromUtf8("label_6"));
        label_6->setAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);

        formLayout_2->setWidget(2, QFormLayout::LabelRole, label_6);

        alpha = new QDoubleSpinBox(Avogadro__QtPlugins__UnitCellDialog);
        alpha->setObjectName(QString::fromUtf8("alpha"));
        alpha->setDecimals(5);
        alpha->setMinimum(5.000000000000000);
        alpha->setMaximum(175.000000000000000);
        alpha->setValue(90.000000000000000);

        formLayout_2->setWidget(0, QFormLayout::FieldRole, alpha);

        gamma = new QDoubleSpinBox(Avogadro__QtPlugins__UnitCellDialog);
        gamma->setObjectName(QString::fromUtf8("gamma"));
        gamma->setDecimals(5);
        gamma->setMinimum(5.000000000000000);
        gamma->setMaximum(175.000000000000000);
        gamma->setValue(90.000000000000000);

        formLayout_2->setWidget(2, QFormLayout::FieldRole, gamma);

        beta = new QDoubleSpinBox(Avogadro__QtPlugins__UnitCellDialog);
        beta->setObjectName(QString::fromUtf8("beta"));
        beta->setDecimals(5);
        beta->setMinimum(5.000000000000000);
        beta->setMaximum(175.000000000000000);
        beta->setValue(90.000000000000000);

        formLayout_2->setWidget(1, QFormLayout::FieldRole, beta);


        horizontalLayout->addLayout(formLayout_2);


        verticalLayout->addLayout(horizontalLayout);

        line_2 = new QFrame(Avogadro__QtPlugins__UnitCellDialog);
        line_2->setObjectName(QString::fromUtf8("line_2"));
        line_2->setFrameShape(QFrame::HLine);
        line_2->setFrameShadow(QFrame::Sunken);

        verticalLayout->addWidget(line_2);

        label_7 = new QLabel(Avogadro__QtPlugins__UnitCellDialog);
        label_7->setObjectName(QString::fromUtf8("label_7"));

        verticalLayout->addWidget(label_7);

        cellMatrix = new QPlainTextEdit(Avogadro__QtPlugins__UnitCellDialog);
        cellMatrix->setObjectName(QString::fromUtf8("cellMatrix"));

        verticalLayout->addWidget(cellMatrix);

        line = new QFrame(Avogadro__QtPlugins__UnitCellDialog);
        line->setObjectName(QString::fromUtf8("line"));
        line->setFrameShape(QFrame::HLine);
        line->setFrameShadow(QFrame::Sunken);

        verticalLayout->addWidget(line);

        label_8 = new QLabel(Avogadro__QtPlugins__UnitCellDialog);
        label_8->setObjectName(QString::fromUtf8("label_8"));

        verticalLayout->addWidget(label_8);

        fractionalMatrix = new QPlainTextEdit(Avogadro__QtPlugins__UnitCellDialog);
        fractionalMatrix->setObjectName(QString::fromUtf8("fractionalMatrix"));

        verticalLayout->addWidget(fractionalMatrix);

        verticalSpacer = new QSpacerItem(20, 54, QSizePolicy::Minimum, QSizePolicy::Expanding);

        verticalLayout->addItem(verticalSpacer);

        line_3 = new QFrame(Avogadro__QtPlugins__UnitCellDialog);
        line_3->setObjectName(QString::fromUtf8("line_3"));
        line_3->setFrameShape(QFrame::HLine);
        line_3->setFrameShadow(QFrame::Sunken);

        verticalLayout->addWidget(line_3);

        transformAtoms = new QCheckBox(Avogadro__QtPlugins__UnitCellDialog);
        transformAtoms->setObjectName(QString::fromUtf8("transformAtoms"));

        verticalLayout->addWidget(transformAtoms);

        horizontalLayout_2 = new QHBoxLayout();
        horizontalLayout_2->setObjectName(QString::fromUtf8("horizontalLayout_2"));
        horizontalSpacer = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_2->addItem(horizontalSpacer);

        apply = new QPushButton(Avogadro__QtPlugins__UnitCellDialog);
        apply->setObjectName(QString::fromUtf8("apply"));

        horizontalLayout_2->addWidget(apply);

        revert = new QPushButton(Avogadro__QtPlugins__UnitCellDialog);
        revert->setObjectName(QString::fromUtf8("revert"));

        horizontalLayout_2->addWidget(revert);

        pushButton = new QPushButton(Avogadro__QtPlugins__UnitCellDialog);
        pushButton->setObjectName(QString::fromUtf8("pushButton"));

        horizontalLayout_2->addWidget(pushButton);


        verticalLayout->addLayout(horizontalLayout_2);

        QWidget::setTabOrder(a, b);
        QWidget::setTabOrder(b, c);
        QWidget::setTabOrder(c, alpha);
        QWidget::setTabOrder(alpha, beta);
        QWidget::setTabOrder(beta, gamma);
        QWidget::setTabOrder(gamma, cellMatrix);
        QWidget::setTabOrder(cellMatrix, fractionalMatrix);
        QWidget::setTabOrder(fractionalMatrix, apply);
        QWidget::setTabOrder(apply, revert);

        retranslateUi(Avogadro__QtPlugins__UnitCellDialog);
        QObject::connect(pushButton, SIGNAL(clicked()), Avogadro__QtPlugins__UnitCellDialog, SLOT(hide()));

        QMetaObject::connectSlotsByName(Avogadro__QtPlugins__UnitCellDialog);
    } // setupUi

    void retranslateUi(QDialog *Avogadro__QtPlugins__UnitCellDialog)
    {
        Avogadro__QtPlugins__UnitCellDialog->setWindowTitle(QCoreApplication::translate("Avogadro::QtPlugins::UnitCellDialog", "Unit Cell Editor", nullptr));
        label->setText(QCoreApplication::translate("Avogadro::QtPlugins::UnitCellDialog", "A:", nullptr));
        a->setPrefix(QString());
        a->setSuffix(QCoreApplication::translate("Avogadro::QtPlugins::UnitCellDialog", " \303\205", nullptr));
        label_2->setText(QCoreApplication::translate("Avogadro::QtPlugins::UnitCellDialog", "B:", nullptr));
        b->setSuffix(QCoreApplication::translate("Avogadro::QtPlugins::UnitCellDialog", " \303\205", nullptr));
        label_4->setText(QCoreApplication::translate("Avogadro::QtPlugins::UnitCellDialog", "C:", nullptr));
        c->setSuffix(QCoreApplication::translate("Avogadro::QtPlugins::UnitCellDialog", " \303\205", nullptr));
        label_3->setText(QCoreApplication::translate("Avogadro::QtPlugins::UnitCellDialog", "\316\261:", nullptr));
        label_5->setText(QCoreApplication::translate("Avogadro::QtPlugins::UnitCellDialog", "\316\262:", nullptr));
        label_6->setText(QCoreApplication::translate("Avogadro::QtPlugins::UnitCellDialog", "\316\263:", nullptr));
        alpha->setSuffix(QCoreApplication::translate("Avogadro::QtPlugins::UnitCellDialog", "\302\260", nullptr));
        gamma->setSuffix(QCoreApplication::translate("Avogadro::QtPlugins::UnitCellDialog", "\302\260", nullptr));
        beta->setSuffix(QCoreApplication::translate("Avogadro::QtPlugins::UnitCellDialog", "\302\260", nullptr));
        label_7->setText(QCoreApplication::translate("Avogadro::QtPlugins::UnitCellDialog", "Cell Matrix:", nullptr));
        label_8->setText(QCoreApplication::translate("Avogadro::QtPlugins::UnitCellDialog", "Fractional Matrix:", nullptr));
        transformAtoms->setText(QCoreApplication::translate("Avogadro::QtPlugins::UnitCellDialog", "&Transform Atoms", nullptr));
        apply->setText(QCoreApplication::translate("Avogadro::QtPlugins::UnitCellDialog", "&Apply", nullptr));
        revert->setText(QCoreApplication::translate("Avogadro::QtPlugins::UnitCellDialog", "&Revert", nullptr));
        pushButton->setText(QCoreApplication::translate("Avogadro::QtPlugins::UnitCellDialog", "&Hide", nullptr));
    } // retranslateUi

};

} // namespace QtPlugins
} // namespace Avogadro

namespace Avogadro {
namespace QtPlugins {
namespace Ui {
    class UnitCellDialog: public Ui_UnitCellDialog {};
} // namespace Ui
} // namespace QtPlugins
} // namespace Avogadro

#endif // UI_UNITCELLDIALOG_H
