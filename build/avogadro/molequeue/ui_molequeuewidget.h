/********************************************************************************
** Form generated from reading UI file 'molequeuewidget.ui'
**
** Created by: Qt User Interface Compiler version 5.15.17
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_MOLEQUEUEWIDGET_H
#define UI_MOLEQUEUEWIDGET_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QFormLayout>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLabel>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QSpinBox>
#include <QtWidgets/QToolButton>
#include <QtWidgets/QTreeView>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>

namespace Avogadro {
namespace MoleQueue {

class Ui_MoleQueueWidget
{
public:
    QHBoxLayout *horizontalLayout;
    QVBoxLayout *verticalLayout_3;
    QHBoxLayout *horizontalLayout_2;
    QLabel *label_4;
    QSpacerItem *horizontalSpacer_2;
    QToolButton *refreshProgramsButton;
    QTreeView *queueListView;
    QFormLayout *formLayout_2;
    QLabel *label_7;
    QHBoxLayout *horizontalLayout_3;
    QSpinBox *numberOfCores;
    QSpacerItem *horizontalSpacer_3;
    QLabel *label;
    QCheckBox *cleanRemoteFiles;
    QLabel *label_2;
    QLabel *label_3;
    QCheckBox *hideFromGui;
    QCheckBox *popupOnStateChange;
    QCheckBox *openOutput;
    QLabel *openOutputLabel;

    void setupUi(QWidget *Avogadro__MoleQueue__MoleQueueWidget)
    {
        if (Avogadro__MoleQueue__MoleQueueWidget->objectName().isEmpty())
            Avogadro__MoleQueue__MoleQueueWidget->setObjectName(QString::fromUtf8("Avogadro__MoleQueue__MoleQueueWidget"));
        Avogadro__MoleQueue__MoleQueueWidget->resize(618, 300);
        horizontalLayout = new QHBoxLayout(Avogadro__MoleQueue__MoleQueueWidget);
        horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));
        verticalLayout_3 = new QVBoxLayout();
        verticalLayout_3->setObjectName(QString::fromUtf8("verticalLayout_3"));
        horizontalLayout_2 = new QHBoxLayout();
        horizontalLayout_2->setObjectName(QString::fromUtf8("horizontalLayout_2"));
        label_4 = new QLabel(Avogadro__MoleQueue__MoleQueueWidget);
        label_4->setObjectName(QString::fromUtf8("label_4"));
        QSizePolicy sizePolicy(QSizePolicy::Maximum, QSizePolicy::Preferred);
        sizePolicy.setHorizontalStretch(0);
        sizePolicy.setVerticalStretch(0);
        sizePolicy.setHeightForWidth(label_4->sizePolicy().hasHeightForWidth());
        label_4->setSizePolicy(sizePolicy);

        horizontalLayout_2->addWidget(label_4);

        horizontalSpacer_2 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_2->addItem(horizontalSpacer_2);

        refreshProgramsButton = new QToolButton(Avogadro__MoleQueue__MoleQueueWidget);
        refreshProgramsButton->setObjectName(QString::fromUtf8("refreshProgramsButton"));

        horizontalLayout_2->addWidget(refreshProgramsButton);


        verticalLayout_3->addLayout(horizontalLayout_2);

        queueListView = new QTreeView(Avogadro__MoleQueue__MoleQueueWidget);
        queueListView->setObjectName(QString::fromUtf8("queueListView"));
        QSizePolicy sizePolicy1(QSizePolicy::Expanding, QSizePolicy::Expanding);
        sizePolicy1.setHorizontalStretch(0);
        sizePolicy1.setVerticalStretch(0);
        sizePolicy1.setHeightForWidth(queueListView->sizePolicy().hasHeightForWidth());
        queueListView->setSizePolicy(sizePolicy1);

        verticalLayout_3->addWidget(queueListView);


        horizontalLayout->addLayout(verticalLayout_3);

        formLayout_2 = new QFormLayout();
        formLayout_2->setObjectName(QString::fromUtf8("formLayout_2"));
        formLayout_2->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);
        formLayout_2->setLabelAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);
        label_7 = new QLabel(Avogadro__MoleQueue__MoleQueueWidget);
        label_7->setObjectName(QString::fromUtf8("label_7"));
        sizePolicy.setHeightForWidth(label_7->sizePolicy().hasHeightForWidth());
        label_7->setSizePolicy(sizePolicy);

        formLayout_2->setWidget(0, QFormLayout::LabelRole, label_7);

        horizontalLayout_3 = new QHBoxLayout();
        horizontalLayout_3->setObjectName(QString::fromUtf8("horizontalLayout_3"));
        numberOfCores = new QSpinBox(Avogadro__MoleQueue__MoleQueueWidget);
        numberOfCores->setObjectName(QString::fromUtf8("numberOfCores"));
        numberOfCores->setMinimum(1);
        numberOfCores->setMaximum(65536);

        horizontalLayout_3->addWidget(numberOfCores);

        horizontalSpacer_3 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_3->addItem(horizontalSpacer_3);


        formLayout_2->setLayout(0, QFormLayout::FieldRole, horizontalLayout_3);

        label = new QLabel(Avogadro__MoleQueue__MoleQueueWidget);
        label->setObjectName(QString::fromUtf8("label"));

        formLayout_2->setWidget(1, QFormLayout::LabelRole, label);

        cleanRemoteFiles = new QCheckBox(Avogadro__MoleQueue__MoleQueueWidget);
        cleanRemoteFiles->setObjectName(QString::fromUtf8("cleanRemoteFiles"));

        formLayout_2->setWidget(1, QFormLayout::FieldRole, cleanRemoteFiles);

        label_2 = new QLabel(Avogadro__MoleQueue__MoleQueueWidget);
        label_2->setObjectName(QString::fromUtf8("label_2"));

        formLayout_2->setWidget(2, QFormLayout::LabelRole, label_2);

        label_3 = new QLabel(Avogadro__MoleQueue__MoleQueueWidget);
        label_3->setObjectName(QString::fromUtf8("label_3"));

        formLayout_2->setWidget(3, QFormLayout::LabelRole, label_3);

        hideFromGui = new QCheckBox(Avogadro__MoleQueue__MoleQueueWidget);
        hideFromGui->setObjectName(QString::fromUtf8("hideFromGui"));

        formLayout_2->setWidget(2, QFormLayout::FieldRole, hideFromGui);

        popupOnStateChange = new QCheckBox(Avogadro__MoleQueue__MoleQueueWidget);
        popupOnStateChange->setObjectName(QString::fromUtf8("popupOnStateChange"));

        formLayout_2->setWidget(3, QFormLayout::FieldRole, popupOnStateChange);

        openOutput = new QCheckBox(Avogadro__MoleQueue__MoleQueueWidget);
        openOutput->setObjectName(QString::fromUtf8("openOutput"));

        formLayout_2->setWidget(4, QFormLayout::FieldRole, openOutput);

        openOutputLabel = new QLabel(Avogadro__MoleQueue__MoleQueueWidget);
        openOutputLabel->setObjectName(QString::fromUtf8("openOutputLabel"));

        formLayout_2->setWidget(4, QFormLayout::LabelRole, openOutputLabel);


        horizontalLayout->addLayout(formLayout_2);

#if QT_CONFIG(shortcut)
        label_7->setBuddy(numberOfCores);
        label->setBuddy(cleanRemoteFiles);
        label_2->setBuddy(hideFromGui);
        label_3->setBuddy(popupOnStateChange);
        openOutputLabel->setBuddy(openOutput);
#endif // QT_CONFIG(shortcut)
        QWidget::setTabOrder(refreshProgramsButton, queueListView);
        QWidget::setTabOrder(queueListView, numberOfCores);
        QWidget::setTabOrder(numberOfCores, cleanRemoteFiles);
        QWidget::setTabOrder(cleanRemoteFiles, hideFromGui);
        QWidget::setTabOrder(hideFromGui, popupOnStateChange);
        QWidget::setTabOrder(popupOnStateChange, openOutput);

        retranslateUi(Avogadro__MoleQueue__MoleQueueWidget);

        QMetaObject::connectSlotsByName(Avogadro__MoleQueue__MoleQueueWidget);
    } // setupUi

    void retranslateUi(QWidget *Avogadro__MoleQueue__MoleQueueWidget)
    {
        Avogadro__MoleQueue__MoleQueueWidget->setWindowTitle(QCoreApplication::translate("Avogadro::MoleQueue::MoleQueueWidget", "Form", nullptr));
        label_4->setText(QCoreApplication::translate("Avogadro::MoleQueue::MoleQueueWidget", "Queue and Program:", nullptr));
        refreshProgramsButton->setText(QCoreApplication::translate("Avogadro::MoleQueue::MoleQueueWidget", "Refresh", nullptr));
#if QT_CONFIG(tooltip)
        label_7->setToolTip(QCoreApplication::translate("Avogadro::MoleQueue::MoleQueueWidget", "<html><head/><body><p>Number of processor cores to reserve for this job.</p></body></html>", nullptr));
#endif // QT_CONFIG(tooltip)
        label_7->setText(QCoreApplication::translate("Avogadro::MoleQueue::MoleQueueWidget", "Processor cores:", nullptr));
#if QT_CONFIG(tooltip)
        label->setToolTip(QCoreApplication::translate("Avogadro::MoleQueue::MoleQueueWidget", "<html><head/><body><p>Delete remote working files upon job completion. Results will still be copied to the local MoleQueue job cache first.</p></body></html>", nullptr));
#endif // QT_CONFIG(tooltip)
        label->setText(QCoreApplication::translate("Avogadro::MoleQueue::MoleQueueWidget", "Delete remote files when finished:", nullptr));
        cleanRemoteFiles->setText(QString());
#if QT_CONFIG(tooltip)
        label_2->setToolTip(QCoreApplication::translate("Avogadro::MoleQueue::MoleQueueWidget", "<html><head/><body><p>Check to prevent this job from showing up in the MoleQueue GUI by default.</p></body></html>", nullptr));
#endif // QT_CONFIG(tooltip)
        label_2->setText(QCoreApplication::translate("Avogadro::MoleQueue::MoleQueueWidget", "Hide job in MoleQueue:", nullptr));
#if QT_CONFIG(tooltip)
        label_3->setToolTip(QCoreApplication::translate("Avogadro::MoleQueue::MoleQueueWidget", "<html><head/><body><p>Show a system popup notification when the job's status changes.</p></body></html>", nullptr));
#endif // QT_CONFIG(tooltip)
        label_3->setText(QCoreApplication::translate("Avogadro::MoleQueue::MoleQueueWidget", "Show progress notifications:", nullptr));
        hideFromGui->setText(QString());
        popupOnStateChange->setText(QString());
        openOutput->setText(QString());
        openOutputLabel->setText(QCoreApplication::translate("Avogadro::MoleQueue::MoleQueueWidget", "Open output when finished:", nullptr));
    } // retranslateUi

};

} // namespace MoleQueue
} // namespace Avogadro

namespace Avogadro {
namespace MoleQueue {
namespace Ui {
    class MoleQueueWidget: public Ui_MoleQueueWidget {};
} // namespace Ui
} // namespace MoleQueue
} // namespace Avogadro

#endif // UI_MOLEQUEUEWIDGET_H
