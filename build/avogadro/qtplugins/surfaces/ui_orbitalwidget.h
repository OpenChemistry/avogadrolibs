/********************************************************************************
** Form generated from reading UI file 'orbitalwidget.ui'
**
** Created by: Qt User Interface Compiler version 5.15.17
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_ORBITALWIDGET_H
#define UI_ORBITALWIDGET_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLabel>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QTableView>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_OrbitalWidget
{
public:
    QVBoxLayout *verticalLayout;
    QTableView *table;
    QHBoxLayout *horizontalLayout;
    QLabel *label;
    QComboBox *combo_quality;
    QPushButton *push_render;
    QHBoxLayout *horizontalLayout_2;
    QSpacerItem *horizontalSpacer;
    QPushButton *push_configure;

    void setupUi(QWidget *OrbitalWidget)
    {
        if (OrbitalWidget->objectName().isEmpty())
            OrbitalWidget->setObjectName(QString::fromUtf8("OrbitalWidget"));
        OrbitalWidget->resize(366, 696);
        QSizePolicy sizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
        sizePolicy.setHorizontalStretch(0);
        sizePolicy.setVerticalStretch(0);
        sizePolicy.setHeightForWidth(OrbitalWidget->sizePolicy().hasHeightForWidth());
        OrbitalWidget->setSizePolicy(sizePolicy);
        verticalLayout = new QVBoxLayout(OrbitalWidget);
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        table = new QTableView(OrbitalWidget);
        table->setObjectName(QString::fromUtf8("table"));
        QSizePolicy sizePolicy1(QSizePolicy::MinimumExpanding, QSizePolicy::Expanding);
        sizePolicy1.setHorizontalStretch(0);
        sizePolicy1.setVerticalStretch(0);
        sizePolicy1.setHeightForWidth(table->sizePolicy().hasHeightForWidth());
        table->setSizePolicy(sizePolicy1);
        table->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        table->setSelectionMode(QAbstractItemView::SingleSelection);
        table->setSelectionBehavior(QAbstractItemView::SelectRows);
        table->setVerticalScrollMode(QAbstractItemView::ScrollPerItem);
        table->setSortingEnabled(true);
        table->horizontalHeader()->setStretchLastSection(true);
        table->verticalHeader()->setCascadingSectionResizes(true);

        verticalLayout->addWidget(table);

        horizontalLayout = new QHBoxLayout();
        horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));
        label = new QLabel(OrbitalWidget);
        label->setObjectName(QString::fromUtf8("label"));
        QSizePolicy sizePolicy2(QSizePolicy::Maximum, QSizePolicy::Preferred);
        sizePolicy2.setHorizontalStretch(0);
        sizePolicy2.setVerticalStretch(0);
        sizePolicy2.setHeightForWidth(label->sizePolicy().hasHeightForWidth());
        label->setSizePolicy(sizePolicy2);

        horizontalLayout->addWidget(label);

        combo_quality = new QComboBox(OrbitalWidget);
        combo_quality->addItem(QString());
        combo_quality->addItem(QString());
        combo_quality->addItem(QString());
        combo_quality->addItem(QString());
        combo_quality->addItem(QString());
        combo_quality->setObjectName(QString::fromUtf8("combo_quality"));

        horizontalLayout->addWidget(combo_quality);

        push_render = new QPushButton(OrbitalWidget);
        push_render->setObjectName(QString::fromUtf8("push_render"));

        horizontalLayout->addWidget(push_render);


        verticalLayout->addLayout(horizontalLayout);

        horizontalLayout_2 = new QHBoxLayout();
        horizontalLayout_2->setObjectName(QString::fromUtf8("horizontalLayout_2"));
        horizontalSpacer = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_2->addItem(horizontalSpacer);

        push_configure = new QPushButton(OrbitalWidget);
        push_configure->setObjectName(QString::fromUtf8("push_configure"));

        horizontalLayout_2->addWidget(push_configure);


        verticalLayout->addLayout(horizontalLayout_2);


        retranslateUi(OrbitalWidget);

        combo_quality->setCurrentIndex(0);


        QMetaObject::connectSlotsByName(OrbitalWidget);
    } // setupUi

    void retranslateUi(QWidget *OrbitalWidget)
    {
        OrbitalWidget->setWindowTitle(QCoreApplication::translate("OrbitalWidget", "Form", nullptr));
        label->setText(QCoreApplication::translate("OrbitalWidget", "Quality: ", nullptr));
        combo_quality->setItemText(0, QCoreApplication::translate("OrbitalWidget", "Very Low", nullptr));
        combo_quality->setItemText(1, QCoreApplication::translate("OrbitalWidget", "Low", nullptr));
        combo_quality->setItemText(2, QCoreApplication::translate("OrbitalWidget", "Medium", nullptr));
        combo_quality->setItemText(3, QCoreApplication::translate("OrbitalWidget", "High", nullptr));
        combo_quality->setItemText(4, QCoreApplication::translate("OrbitalWidget", "Very High", nullptr));

        push_render->setText(QCoreApplication::translate("OrbitalWidget", "Render", nullptr));
        push_configure->setText(QCoreApplication::translate("OrbitalWidget", "Configure", nullptr));
    } // retranslateUi

};

namespace Ui {
    class OrbitalWidget: public Ui_OrbitalWidget {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_ORBITALWIDGET_H
