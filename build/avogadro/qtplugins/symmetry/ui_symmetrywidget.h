/********************************************************************************
** Form generated from reading UI file 'symmetrywidget.ui'
**
** Created by: Qt User Interface Compiler version 5.15.17
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_SYMMETRYWIDGET_H
#define UI_SYMMETRYWIDGET_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLabel>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QTabWidget>
#include <QtWidgets/QTableView>
#include <QtWidgets/QTreeView>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>

namespace Avogadro {
namespace QtPlugins {

class Ui_SymmetryWidget
{
public:
    QVBoxLayout *verticalLayout;
    QLabel *pointGroupLabel;
    QTabWidget *tabWidget;
    QWidget *esTab;
    QVBoxLayout *verticalLayout_2;
    QLabel *esLabel;
    QTreeView *equivalenceTree;
    QHBoxLayout *horizontalLayoutMolecule;
    QCheckBox *lockSymmetryCheckBox;
    QSpacerItem *horizontalSpacerMolecule;
    QPushButton *symmetrizeMoleculeButton;
    QWidget *operationsTab;
    QVBoxLayout *verticalLayout_3;
    QLabel *operationsLabel;
    QTableView *operationsTable;
    QWidget *subgroupsTab;
    QVBoxLayout *verticalLayout_4;
    QLabel *subgroupsLabel;
    QTreeView *subgroupsTree;
    QHBoxLayout *horizontalLayoutSubgroups;
    QSpacerItem *horizontalSpacerSubgroups;
    QPushButton *selectSubgroupButton;
    QHBoxLayout *horizontalLayout;
    QSpacerItem *horizontalSpacer;
    QLabel *toleranceLabel;
    QComboBox *toleranceCombo;
    QPushButton *detectSymmetryButton;

    void setupUi(QWidget *Avogadro__QtPlugins__SymmetryWidget)
    {
        if (Avogadro__QtPlugins__SymmetryWidget->objectName().isEmpty())
            Avogadro__QtPlugins__SymmetryWidget->setObjectName(QString::fromUtf8("Avogadro__QtPlugins__SymmetryWidget"));
        Avogadro__QtPlugins__SymmetryWidget->resize(412, 584);
        verticalLayout = new QVBoxLayout(Avogadro__QtPlugins__SymmetryWidget);
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        pointGroupLabel = new QLabel(Avogadro__QtPlugins__SymmetryWidget);
        pointGroupLabel->setObjectName(QString::fromUtf8("pointGroupLabel"));
        QFont font;
        font.setPointSize(18);
        font.setBold(true);
        font.setWeight(75);
        font.setKerning(true);
        pointGroupLabel->setFont(font);

        verticalLayout->addWidget(pointGroupLabel);

        tabWidget = new QTabWidget(Avogadro__QtPlugins__SymmetryWidget);
        tabWidget->setObjectName(QString::fromUtf8("tabWidget"));
        tabWidget->setEnabled(true);
        esTab = new QWidget();
        esTab->setObjectName(QString::fromUtf8("esTab"));
        verticalLayout_2 = new QVBoxLayout(esTab);
        verticalLayout_2->setObjectName(QString::fromUtf8("verticalLayout_2"));
        esLabel = new QLabel(esTab);
        esLabel->setObjectName(QString::fromUtf8("esLabel"));

        verticalLayout_2->addWidget(esLabel);

        equivalenceTree = new QTreeView(esTab);
        equivalenceTree->setObjectName(QString::fromUtf8("equivalenceTree"));
        QSizePolicy sizePolicy(QSizePolicy::MinimumExpanding, QSizePolicy::Expanding);
        sizePolicy.setHorizontalStretch(0);
        sizePolicy.setVerticalStretch(0);
        sizePolicy.setHeightForWidth(equivalenceTree->sizePolicy().hasHeightForWidth());
        equivalenceTree->setSizePolicy(sizePolicy);
        equivalenceTree->setSelectionMode(QAbstractItemView::SingleSelection);
        equivalenceTree->setSelectionBehavior(QAbstractItemView::SelectRows);
        equivalenceTree->header()->setVisible(false);

        verticalLayout_2->addWidget(equivalenceTree);

        horizontalLayoutMolecule = new QHBoxLayout();
        horizontalLayoutMolecule->setObjectName(QString::fromUtf8("horizontalLayoutMolecule"));
        lockSymmetryCheckBox = new QCheckBox(esTab);
        lockSymmetryCheckBox->setObjectName(QString::fromUtf8("lockSymmetryCheckBox"));
        lockSymmetryCheckBox->setEnabled(false);

        horizontalLayoutMolecule->addWidget(lockSymmetryCheckBox);

        horizontalSpacerMolecule = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayoutMolecule->addItem(horizontalSpacerMolecule);

        symmetrizeMoleculeButton = new QPushButton(esTab);
        symmetrizeMoleculeButton->setObjectName(QString::fromUtf8("symmetrizeMoleculeButton"));

        horizontalLayoutMolecule->addWidget(symmetrizeMoleculeButton);


        verticalLayout_2->addLayout(horizontalLayoutMolecule);

        tabWidget->addTab(esTab, QString());
        operationsTab = new QWidget();
        operationsTab->setObjectName(QString::fromUtf8("operationsTab"));
        verticalLayout_3 = new QVBoxLayout(operationsTab);
        verticalLayout_3->setObjectName(QString::fromUtf8("verticalLayout_3"));
        operationsLabel = new QLabel(operationsTab);
        operationsLabel->setObjectName(QString::fromUtf8("operationsLabel"));

        verticalLayout_3->addWidget(operationsLabel);

        operationsTable = new QTableView(operationsTab);
        operationsTable->setObjectName(QString::fromUtf8("operationsTable"));
        sizePolicy.setHeightForWidth(operationsTable->sizePolicy().hasHeightForWidth());
        operationsTable->setSizePolicy(sizePolicy);
        operationsTable->setSelectionMode(QAbstractItemView::MultiSelection);
        operationsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
        operationsTable->horizontalHeader()->setStretchLastSection(true);
        operationsTable->verticalHeader()->setCascadingSectionResizes(true);

        verticalLayout_3->addWidget(operationsTable);

        tabWidget->addTab(operationsTab, QString());
        subgroupsTab = new QWidget();
        subgroupsTab->setObjectName(QString::fromUtf8("subgroupsTab"));
        verticalLayout_4 = new QVBoxLayout(subgroupsTab);
        verticalLayout_4->setObjectName(QString::fromUtf8("verticalLayout_4"));
        subgroupsLabel = new QLabel(subgroupsTab);
        subgroupsLabel->setObjectName(QString::fromUtf8("subgroupsLabel"));

        verticalLayout_4->addWidget(subgroupsLabel);

        subgroupsTree = new QTreeView(subgroupsTab);
        subgroupsTree->setObjectName(QString::fromUtf8("subgroupsTree"));
        subgroupsTree->setEditTriggers(QAbstractItemView::NoEditTriggers);
        subgroupsTree->setSelectionBehavior(QAbstractItemView::SelectRows);
        subgroupsTree->header()->setVisible(false);

        verticalLayout_4->addWidget(subgroupsTree);

        horizontalLayoutSubgroups = new QHBoxLayout();
        horizontalLayoutSubgroups->setObjectName(QString::fromUtf8("horizontalLayoutSubgroups"));
        horizontalSpacerSubgroups = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayoutSubgroups->addItem(horizontalSpacerSubgroups);

        selectSubgroupButton = new QPushButton(subgroupsTab);
        selectSubgroupButton->setObjectName(QString::fromUtf8("selectSubgroupButton"));

        horizontalLayoutSubgroups->addWidget(selectSubgroupButton);


        verticalLayout_4->addLayout(horizontalLayoutSubgroups);

        tabWidget->addTab(subgroupsTab, QString());

        verticalLayout->addWidget(tabWidget);

        horizontalLayout = new QHBoxLayout();
        horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));
        horizontalSpacer = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout->addItem(horizontalSpacer);

        toleranceLabel = new QLabel(Avogadro__QtPlugins__SymmetryWidget);
        toleranceLabel->setObjectName(QString::fromUtf8("toleranceLabel"));

        horizontalLayout->addWidget(toleranceLabel);

        toleranceCombo = new QComboBox(Avogadro__QtPlugins__SymmetryWidget);
        toleranceCombo->addItem(QString());
        toleranceCombo->addItem(QString());
        toleranceCombo->addItem(QString());
        toleranceCombo->addItem(QString());
        toleranceCombo->setObjectName(QString::fromUtf8("toleranceCombo"));

        horizontalLayout->addWidget(toleranceCombo);

        detectSymmetryButton = new QPushButton(Avogadro__QtPlugins__SymmetryWidget);
        detectSymmetryButton->setObjectName(QString::fromUtf8("detectSymmetryButton"));

        horizontalLayout->addWidget(detectSymmetryButton);


        verticalLayout->addLayout(horizontalLayout);


        retranslateUi(Avogadro__QtPlugins__SymmetryWidget);

        tabWidget->setCurrentIndex(0);
        toleranceCombo->setCurrentIndex(1);
        detectSymmetryButton->setDefault(true);


        QMetaObject::connectSlotsByName(Avogadro__QtPlugins__SymmetryWidget);
    } // setupUi

    void retranslateUi(QWidget *Avogadro__QtPlugins__SymmetryWidget)
    {
        Avogadro__QtPlugins__SymmetryWidget->setWindowTitle(QCoreApplication::translate("Avogadro::QtPlugins::SymmetryWidget", "Symmetry", nullptr));
        pointGroupLabel->setText(QCoreApplication::translate("Avogadro::QtPlugins::SymmetryWidget", "C<sub>1", nullptr));
        esLabel->setText(QCoreApplication::translate("Avogadro::QtPlugins::SymmetryWidget", "Symmetrically equivalent atoms:", nullptr));
        lockSymmetryCheckBox->setText(QCoreApplication::translate("Avogadro::QtPlugins::SymmetryWidget", "Lock Symmetry", nullptr));
        symmetrizeMoleculeButton->setText(QCoreApplication::translate("Avogadro::QtPlugins::SymmetryWidget", "Symmetrize", nullptr));
        tabWidget->setTabText(tabWidget->indexOf(esTab), QCoreApplication::translate("Avogadro::QtPlugins::SymmetryWidget", "Molecule", nullptr));
        operationsLabel->setText(QCoreApplication::translate("Avogadro::QtPlugins::SymmetryWidget", "Symmetry elements:", nullptr));
        tabWidget->setTabText(tabWidget->indexOf(operationsTab), QCoreApplication::translate("Avogadro::QtPlugins::SymmetryWidget", "Operations", nullptr));
        subgroupsLabel->setText(QCoreApplication::translate("Avogadro::QtPlugins::SymmetryWidget", "Subgroups:", nullptr));
        selectSubgroupButton->setText(QCoreApplication::translate("Avogadro::QtPlugins::SymmetryWidget", "Select", nullptr));
        tabWidget->setTabText(tabWidget->indexOf(subgroupsTab), QCoreApplication::translate("Avogadro::QtPlugins::SymmetryWidget", "Subgroups", nullptr));
        toleranceLabel->setText(QCoreApplication::translate("Avogadro::QtPlugins::SymmetryWidget", "Tolerance:", nullptr));
        toleranceCombo->setItemText(0, QCoreApplication::translate("Avogadro::QtPlugins::SymmetryWidget", "Tight", nullptr));
        toleranceCombo->setItemText(1, QCoreApplication::translate("Avogadro::QtPlugins::SymmetryWidget", "Normal", nullptr));
        toleranceCombo->setItemText(2, QCoreApplication::translate("Avogadro::QtPlugins::SymmetryWidget", "Loose", nullptr));
        toleranceCombo->setItemText(3, QCoreApplication::translate("Avogadro::QtPlugins::SymmetryWidget", "Very Loose", nullptr));

        detectSymmetryButton->setText(QCoreApplication::translate("Avogadro::QtPlugins::SymmetryWidget", "Detect Symmetry", nullptr));
    } // retranslateUi

};

} // namespace QtPlugins
} // namespace Avogadro

namespace Avogadro {
namespace QtPlugins {
namespace Ui {
    class SymmetryWidget: public Ui_SymmetryWidget {};
} // namespace Ui
} // namespace QtPlugins
} // namespace Avogadro

#endif // UI_SYMMETRYWIDGET_H
