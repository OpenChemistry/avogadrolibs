/********************************************************************************
** Form generated from reading UI file 'constraintsdialog.ui'
**
** Created by: Qt User Interface Compiler version 5.15.17
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_CONSTRAINTSDIALOG_H
#define UI_CONSTRAINTSDIALOG_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QDialog>
#include <QtWidgets/QDoubleSpinBox>
#include <QtWidgets/QFormLayout>
#include <QtWidgets/QGroupBox>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLabel>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QSpinBox>
#include <QtWidgets/QTableView>
#include <QtWidgets/QVBoxLayout>

namespace Avogadro {
namespace QtPlugins {

class Ui_ConstraintsDialog
{
public:
    QVBoxLayout *vboxLayout;
    QTableView *constraintsTableView;
    QGroupBox *groupBox;
    QFormLayout *formLayout;
    QLabel *label;
    QComboBox *comboType;
    QLabel *label_3;
    QHBoxLayout *horizontalLayout;
    QSpinBox *editB;
    QSpinBox *editA;
    QSpinBox *editC;
    QSpinBox *editD;
    QLabel *label_2;
    QHBoxLayout *horizontalLayout_3;
    QDoubleSpinBox *editValue;
    QHBoxLayout *horizontalLayout_2;
    QPushButton *addConstraint;
    QSpacerItem *verticalSpacer;
    QGroupBox *groupBox_2;
    QHBoxLayout *hboxLayout;
    QHBoxLayout *hboxLayout1;
    QSpacerItem *spacerItem;
    QPushButton *deleteConstraint;
    QPushButton *deleteAllConstraints;
    QPushButton *okButton;

    void setupUi(QDialog *Avogadro__QtPlugins__ConstraintsDialog)
    {
        if (Avogadro__QtPlugins__ConstraintsDialog->objectName().isEmpty())
            Avogadro__QtPlugins__ConstraintsDialog->setObjectName(QString::fromUtf8("Avogadro__QtPlugins__ConstraintsDialog"));
        Avogadro__QtPlugins__ConstraintsDialog->resize(441, 446);
        vboxLayout = new QVBoxLayout(Avogadro__QtPlugins__ConstraintsDialog);
        vboxLayout->setObjectName(QString::fromUtf8("vboxLayout"));
        constraintsTableView = new QTableView(Avogadro__QtPlugins__ConstraintsDialog);
        constraintsTableView->setObjectName(QString::fromUtf8("constraintsTableView"));
        constraintsTableView->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        constraintsTableView->setSizeAdjustPolicy(QAbstractScrollArea::AdjustIgnored);
        constraintsTableView->setSelectionBehavior(QAbstractItemView::SelectRows);

        vboxLayout->addWidget(constraintsTableView);

        groupBox = new QGroupBox(Avogadro__QtPlugins__ConstraintsDialog);
        groupBox->setObjectName(QString::fromUtf8("groupBox"));
        formLayout = new QFormLayout(groupBox);
        formLayout->setObjectName(QString::fromUtf8("formLayout"));
        label = new QLabel(groupBox);
        label->setObjectName(QString::fromUtf8("label"));
        label->setMaximumSize(QSize(40, 16777215));

        formLayout->setWidget(0, QFormLayout::LabelRole, label);

        comboType = new QComboBox(groupBox);
        comboType->addItem(QString());
        comboType->addItem(QString());
        comboType->addItem(QString());
        comboType->setObjectName(QString::fromUtf8("comboType"));

        formLayout->setWidget(0, QFormLayout::FieldRole, comboType);

        label_3 = new QLabel(groupBox);
        label_3->setObjectName(QString::fromUtf8("label_3"));

        formLayout->setWidget(1, QFormLayout::LabelRole, label_3);

        horizontalLayout = new QHBoxLayout();
        horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));
        editB = new QSpinBox(groupBox);
        editB->setObjectName(QString::fromUtf8("editB"));
        editB->setMaximum(999);

        horizontalLayout->addWidget(editB);

        editA = new QSpinBox(groupBox);
        editA->setObjectName(QString::fromUtf8("editA"));
        editA->setMaximum(999);

        horizontalLayout->addWidget(editA);

        editC = new QSpinBox(groupBox);
        editC->setObjectName(QString::fromUtf8("editC"));
        editC->setMaximum(999);

        horizontalLayout->addWidget(editC);

        editD = new QSpinBox(groupBox);
        editD->setObjectName(QString::fromUtf8("editD"));
        editD->setMaximum(999);

        horizontalLayout->addWidget(editD);


        formLayout->setLayout(1, QFormLayout::FieldRole, horizontalLayout);

        label_2 = new QLabel(groupBox);
        label_2->setObjectName(QString::fromUtf8("label_2"));

        formLayout->setWidget(2, QFormLayout::LabelRole, label_2);

        horizontalLayout_3 = new QHBoxLayout();
        horizontalLayout_3->setObjectName(QString::fromUtf8("horizontalLayout_3"));
        editValue = new QDoubleSpinBox(groupBox);
        editValue->setObjectName(QString::fromUtf8("editValue"));
        editValue->setAlignment(Qt::AlignLeading|Qt::AlignLeft|Qt::AlignVCenter);
        editValue->setDecimals(3);
        editValue->setMaximum(105.989999999999995);

        horizontalLayout_3->addWidget(editValue);


        formLayout->setLayout(2, QFormLayout::FieldRole, horizontalLayout_3);

        horizontalLayout_2 = new QHBoxLayout();
        horizontalLayout_2->setObjectName(QString::fromUtf8("horizontalLayout_2"));
        addConstraint = new QPushButton(groupBox);
        addConstraint->setObjectName(QString::fromUtf8("addConstraint"));

        horizontalLayout_2->addWidget(addConstraint);


        formLayout->setLayout(3, QFormLayout::FieldRole, horizontalLayout_2);

        verticalSpacer = new QSpacerItem(20, 40, QSizePolicy::Minimum, QSizePolicy::Expanding);

        formLayout->setItem(4, QFormLayout::FieldRole, verticalSpacer);


        vboxLayout->addWidget(groupBox);

        groupBox_2 = new QGroupBox(Avogadro__QtPlugins__ConstraintsDialog);
        groupBox_2->setObjectName(QString::fromUtf8("groupBox_2"));
        hboxLayout = new QHBoxLayout(groupBox_2);
        hboxLayout->setObjectName(QString::fromUtf8("hboxLayout"));
        hboxLayout1 = new QHBoxLayout();
        hboxLayout1->setObjectName(QString::fromUtf8("hboxLayout1"));
        spacerItem = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        hboxLayout1->addItem(spacerItem);

        deleteConstraint = new QPushButton(groupBox_2);
        deleteConstraint->setObjectName(QString::fromUtf8("deleteConstraint"));
        QSizePolicy sizePolicy(QSizePolicy::Minimum, QSizePolicy::Fixed);
        sizePolicy.setHorizontalStretch(0);
        sizePolicy.setVerticalStretch(0);
        sizePolicy.setHeightForWidth(deleteConstraint->sizePolicy().hasHeightForWidth());
        deleteConstraint->setSizePolicy(sizePolicy);
        deleteConstraint->setMinimumSize(QSize(100, 0));

        hboxLayout1->addWidget(deleteConstraint);

        deleteAllConstraints = new QPushButton(groupBox_2);
        deleteAllConstraints->setObjectName(QString::fromUtf8("deleteAllConstraints"));

        hboxLayout1->addWidget(deleteAllConstraints);

        okButton = new QPushButton(groupBox_2);
        okButton->setObjectName(QString::fromUtf8("okButton"));

        hboxLayout1->addWidget(okButton);


        hboxLayout->addLayout(hboxLayout1);


        vboxLayout->addWidget(groupBox_2);


        retranslateUi(Avogadro__QtPlugins__ConstraintsDialog);

        comboType->setCurrentIndex(0);


        QMetaObject::connectSlotsByName(Avogadro__QtPlugins__ConstraintsDialog);
    } // setupUi

    void retranslateUi(QDialog *Avogadro__QtPlugins__ConstraintsDialog)
    {
        Avogadro__QtPlugins__ConstraintsDialog->setWindowTitle(QCoreApplication::translate("Avogadro::QtPlugins::ConstraintsDialog", "Constraints", nullptr));
        groupBox->setTitle(QCoreApplication::translate("Avogadro::QtPlugins::ConstraintsDialog", "Add Constraints", nullptr));
        label->setText(QCoreApplication::translate("Avogadro::QtPlugins::ConstraintsDialog", "Type:", nullptr));
        comboType->setItemText(0, QCoreApplication::translate("Avogadro::QtPlugins::ConstraintsDialog", "Distance", nullptr));
        comboType->setItemText(1, QCoreApplication::translate("Avogadro::QtPlugins::ConstraintsDialog", "Angle", nullptr));
        comboType->setItemText(2, QCoreApplication::translate("Avogadro::QtPlugins::ConstraintsDialog", "Torsion Angle", nullptr));

        label_3->setText(QCoreApplication::translate("Avogadro::QtPlugins::ConstraintsDialog", "Atom Indices:", nullptr));
        label_2->setText(QCoreApplication::translate("Avogadro::QtPlugins::ConstraintsDialog", "Value:", nullptr));
        editValue->setSuffix(QCoreApplication::translate("Avogadro::QtPlugins::ConstraintsDialog", "\303\205", nullptr));
        addConstraint->setText(QCoreApplication::translate("Avogadro::QtPlugins::ConstraintsDialog", "Add", nullptr));
        groupBox_2->setTitle(QCoreApplication::translate("Avogadro::QtPlugins::ConstraintsDialog", "Options", nullptr));
        deleteConstraint->setText(QCoreApplication::translate("Avogadro::QtPlugins::ConstraintsDialog", "Delete Selected", nullptr));
        deleteAllConstraints->setText(QCoreApplication::translate("Avogadro::QtPlugins::ConstraintsDialog", "Delete All", nullptr));
        okButton->setText(QCoreApplication::translate("Avogadro::QtPlugins::ConstraintsDialog", "OK", nullptr));
    } // retranslateUi

};

} // namespace QtPlugins
} // namespace Avogadro

namespace Avogadro {
namespace QtPlugins {
namespace Ui {
    class ConstraintsDialog: public Ui_ConstraintsDialog {};
} // namespace Ui
} // namespace QtPlugins
} // namespace Avogadro

#endif // UI_CONSTRAINTSDIALOG_H
