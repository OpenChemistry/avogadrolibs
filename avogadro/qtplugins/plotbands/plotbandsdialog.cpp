/*
 * Copyright 2007 Sandia Corporation.
 * Under the terms of Contract DE-AC04-94AL85000, there is a non-exclusive
 * license for use of this work by or on behalf of the
 * U.S. Government. Redistribution and use in source and binary forms, with
 * or without modification, are permitted provided that this Notice and any
 * statement of authorship are reproduced on all copies.
 */


#include "ui_plotbandsdialog.h"
#include "plotbandsdialog.h"

#include <vtkDataObjectToTable.h>
#include <vtkElevationFilter.h>
#include <vtkPolyDataMapper.h>
#include <vtkQtTableView.h>
#include <vtkRenderer.h>
#include <vtkRenderWindow.h>
#include <vtkVectorText.h>
#include <vtkPen.h>
#include </home/carlos/Qt-Projects/Avogadro2OShared/build-openchemistry-Desktop-Default/prefix/include/vtk-6.3/vtkContextView.h>
//#include <vtkContextView.h>
#include <vtkWindowToImageFilter.h>
#include <vtkPNGWriter.h>
#include <vtkJPEGWriter.h>
#include <vtkRenderWindowInteractor.h>
#include <vtkRendererCollection.h>
#include <vtkSmartPointer.h>
#include <vtkActor.h>
#include <vtkDoubleArray.h>
#include <vtkStringArray.h>
#include <vtkTextProperty.h>
#include <vtkArray.h>

#include "vtkAxis.h"
#include "vtkBrush.h"
#include "vtkCharArray.h"
#include "vtkChartXY.h"
#include "vtkAxis.h"
#include "vtkContextScene.h"
#include "vtkFloatArray.h"
#include "vtkNew.h"
#include "vtkPlotArea.h"
#include "vtkPlot.h"
//#include "vtkRenderWindow.h"
#include "vtkRenderWindowInteractor.h"
//#include "vtkSmartPointer.h"
#include "vtkTable.h"

//#include "vtkSmartPointer.h"

#include <algorithm>

#include <QApplication>
#include <QWidget>
#include <QMainWindow>
#include <QHBoxLayout>
#include <QDebug>
#include <QVector>
#include <QList>
#include <QChar>
//#include <QtCore/QMath>
#include <QtMath>
#include <QItemSelection>
#include <QItemSelectionModel>
#include <math.h>

#include "QVTKWidget.h"
#include "vtkQtTableView.h"

#define VTK_CREATE(type, name) \
  vtkSmartPointer<type> name = vtkSmartPointer<type>::New()

//------  NEW INCLUDES IN AVOGADRO2 --------
#include <avogadro/core/atom.h>
#include <avogadro/core/bond.h>
#include <avogadro/core/elements.h>

#include <avogadro/qtgui/molecule.h>
#include <avogadro/core/avogadrocore.h>
#include <avogadro/core/coordinateblockgenerator.h>
#include <avogadro/core/crystaltools.h>
#include <avogadro/core/vector.h>

#include <avogadro/qtgui/molecule.h>
#include <avogadro/molequeue/molequeuedialog.h>
#include <avogadro/molequeue/molequeuemanager.h>

#include <molequeue/client/jobobject.h>
#include <qjsonarray.h>
#include <qjsonobject.h>
#include <qjsonvalue.h>

#include <QtCore/QFile>
#include <QtCore/QSettings>
#include <QtCore/QString>
#include <QtCore/QTimer>
#include <QLabel>

//--- END OF NEW INCLUDES IN AVOGADRO2 -----

using Avogadro::MoleQueue::MoleQueueDialog;
using Avogadro::MoleQueue::MoleQueueManager;
using MoleQueue::JobObject;

//-------------------------------------------------------------------------------
//-------- I TAKE THIS PART FROM COORDINATEEDITORDIALOG.CPP ---------------------
//-------- TO USE "QVector<Atomstruc> atoms" IN THE SAME MANNER -----------------
//-------- USED IN AVOGADRO-QT4 -------------------------------------------------
//-------------------------------------------------------------------------------
using Avogadro::QtGui::Molecule;
using Avogadro::Core::Atom;
using Avogadro::Core::Elements;
using Avogadro::Vector3;

namespace Avogadro {
namespace QtPlugins {

// Constructor
//PlotBandsDialog::PlotBandsDialog()
PlotBandsDialog::PlotBandsDialog(QWidget *parent_, Qt::WindowFlags f)
    : QDialog( parent_, f )
{
  //this->ui = new Ui_PlotBandsDialog;
  //this->ui.setupUi(this);
  ui.setupUi(this);

  // Set up action signals and slots
  //connect(this->ui.actionOpenFile, SIGNAL(triggered()), this, SLOT(slotOpenFile()));
  //connect(this->ui.actionExit, SIGNAL(triggered()), this, SLOT(slotExit()));
  connect(ui.actionOpenFile, SIGNAL(triggered()), this, SLOT(slotOpenFile()));
  connect(ui.actionOpenBandsFile, SIGNAL(triggered()), this, SLOT(slotOpenBandsFile()));
  connect(ui.actionExit, SIGNAL(triggered()), this, SLOT(slotExit()));

    //createMenus();
    connectActions();
    createActions();

    infoLabel = new QLabel(tr("<i>Choose a menu option, or right-click to "
                              "invoke a context menu</i>"));
    infoLabel->setFrameStyle(QFrame::StyledPanel | QFrame::Sunken);
    infoLabel->setAlignment(Qt::AlignCenter);

    //ui.label_2->setPixmap(":simune-s.png")

    //-------------------------------------------------------------------------------------------------------
    //------------------- BANDS PLOT CREATE VIEW -------------------------------------------------------------
    //-------------------------------------------------------------------------------------------------------
    // Set up a 2D scene, add an XY chart to it
    VTK_CREATE(vtkContextView, viewBands);
    //vtkSmartPointer<vtkContextView> viewBands =
    //    vtkSmartPointer<vtkContextView>::New();
    //vtkNew<vtkContextView> view;
    viewBands->GetRenderWindow()->SetSize(400, 300);

    //vtkNew<vtkChartXY> chart;
    //vtkNew<vtkChartXY> chartBands =
    //        vtkSmartPointer<vtkChartXY>::New();
    chartBands = vtkSmartPointer<vtkChartXY>::New();

    qDebug()<<"PlotBandsDialog::PlotBandsBandsDialog() 2a";
    //viewBands->GetScene()->RemoveItem(chartBands.GetPointer());
    qDebug()<<"PlotBandsDialog::PlotBandsBandsDialog() 2b";
    viewBands->GetScene()->AddItem(chartBands.GetPointer());

    qDebug()<<"PlotBandsDialog::PlotBandsBandsDialog() 2c";



    // Graph View needs to get my render window
    qDebug()<<"PlotBandsDialog::on_plotBandsButton_clicked() 5a";
    //ui.qvtkWidget3->GetInteractor()->ReInitialize();
    //viewBands->SetInteractor(this->ui.qvtkWidget3->GetInteractor());
    viewBands->SetInteractor(ui.qvtkWidgetBands->GetInteractor());
    ui.qvtkWidgetBands->SetRenderWindow(viewBands->GetRenderWindow());

    qDebug()<<"PlotBandsDialog::on_plotBandsButton_clicked() 6";

    //view->GetInteractor()->Initialize();
    //viewBands->GetInteractor()->ReInitialize();
    viewBands->GetInteractor()->Start();
    viewBands->Render();

    connect(ui.horizontalSliderqvtkWidgetBands, SIGNAL(valueChanged(int)), this, SLOT(setBandsXRange(int)));
    connect(ui.verticalSliderqvtkWidgetBands, SIGNAL(valueChanged(int)), this, SLOT(setBandsYRange(int)));

    //connect(ui.outBandsAlphaTableView->selectionModel(),SIGNAL(selectionChanged(QItemSelection selected,QItemSelection deselected)),this,SLOT(on_outputBandsColumn_selected(QItemSelection selected, QItemSelection deselected)));
    connect(ui.outBandsAlphaTableView->selectionModel(),SIGNAL(selectionChanged(QItemSelection selected,QItemSelection deselected)),this,SLOT(on_outputBandsColumn_selected()));
    //connect(ui.outBandsAlphaTableView->selectionModel(),SIGNAL()

    connect(ui.outBandsAlphaTableView->selectionModel(), SIGNAL(currentChanged(const QModelIndex &, const QModelIndex &)), this, SLOT(on_outputBandsColumn_selected()));

    //ui.outBandsAlphaTableView->selectionModel()->

    //-------------------------------------------------------------------------------------------------------
    //------------------- END BANDS PLOT CREATE VIEW ---------------------------------------------------------
    //-------------------------------------------------------------------------------------------------------

}

PlotBandsDialog::~PlotBandsDialog()
{
  // The smart pointers should clean up for up

}

void PlotBandsDialog::createMenus()
{
    //fileMenu = menuBar()->addMenu(tr("&File"));
    fileMenu = new QMenu(tr("&File"));
    //fileMenu = ui.menubar()->addMenu(tr("&File"));
    ui.menubar->addMenu(fileMenu);
    //fileMenu->addAction(newAct);
    //fileMenu->addAction(actionOpenFile);
    fileMenu->addAction(openAct);
    fileMenu->addAction(saveAct);
    fileMenu->addAction(printAct);
    fileMenu->addAction(exportAct);
    fileMenu->addAction(helpAct);
    fileMenu->addSeparator();
    fileMenu->addAction(exitAct);
}

void PlotBandsDialog::createActions()
{
  openAct = new QAction(tr("&Open..."), this);
  openAct->setShortcuts(QKeySequence::Open);
  openAct->setStatusTip(tr("Open an existing file"));
  connect(openAct, &QAction::triggered, this, &PlotBandsDialog::open);

  saveAct = new QAction(tr("&Save"), this);
  saveAct->setShortcuts(QKeySequence::Save);
  saveAct->setStatusTip(tr("Save the document to disk"));
  connect(saveAct, &QAction::triggered, this, &PlotBandsDialog::save);

  printAct = new QAction(tr("&Print..."), this);
  printAct->setShortcuts(QKeySequence::Print);
  printAct->setStatusTip(tr("Print the document"));
  connect(printAct, &QAction::triggered, this, &PlotBandsDialog::print);

  exitAct = new QAction(tr("E&xit"), this);
  exitAct->setShortcuts(QKeySequence::Quit);
  exitAct->setStatusTip(tr("Exit the application"));
  //connect(exitAct, &QAction::triggered, this, &QDialog::close);
}

void PlotBandsDialog::connectActions()
{
  connect(ui.actionOpenFile, &QAction::triggered, this, &PlotBandsDialog::open);
  connect(ui.actionSave, &QAction::triggered, this, &PlotBandsDialog::save);
  connect(ui.actionPrint, &QAction::triggered, this, &PlotBandsDialog::print);

//  connect(ui.actionExportDos, &QAction::triggered, this, &PlotBandsDialog::exportPlotDos);
//  connect(ui.actionExportBands, &QAction::triggered, this, &PlotBandsDialog::exportPlotBands);
  //connect(ui.actionExit, &QAction::triggered, this, &QDialog::close);

  connect(ui.actionOpenBandsFile, &QAction::triggered, this, &PlotBandsDialog::openBands);
  connect(ui.actionExportBands, &QAction::triggered, this, &PlotBandsDialog::exportPlotBands);
}

void PlotBandsDialog::open()
{
    infoLabel->setText(tr("Invoked <b>File|Open</b>"));
    on_outputBandsButton_clicked();
}

void PlotBandsDialog::openDos()
{
    infoLabel->setText(tr("Invoked <b>File|Open DOS</b>"));
    //on_outputDosButton_clicked();
}

void PlotBandsDialog::openPDos()
{
    infoLabel->setText(tr("Invoked <b>File|Open PDOS</b>"));
    //on_outputPDosButton_clicked();
}

void PlotBandsDialog::openBands()
{
    infoLabel->setText(tr("Invoked <b>File|Open fullBands</b>"));
    on_outputBandsButton_clicked();
}

void PlotBandsDialog::save()
{
    infoLabel->setText(tr("Invoked <b>File|Save</b>"));
}

void PlotBandsDialog::print()
{
    infoLabel->setText(tr("Invoked <b>File|Print</b>"));
}

void PlotBandsDialog::exportPlotBands()
{
//    QString fileName = QFileDialog::getSaveFileName(this,
//                                                    tr("Export Bitmap Graphics"),
//                                                    "",
//                                                    "Images (*.png *.jpg)");
    QString fileName = QFileDialog::getSaveFileName (this,
                                                     tr("Export Image File"),
                                                     QDir::currentPath(),
                                                     tr("png (*.png);; jpeg (*.jpg);; All Files (*)"));

    if (fileName.isEmpty())
      return;
    if (QFileInfo(fileName).suffix().isEmpty()){
      fileName += ".png";
      pngWriter(fileName, 4);
    }else if(QString::compare(QFileInfo(fileName).suffix().toLatin1(),"png", Qt::CaseInsensitive)==0){
      pngWriter(fileName, 4);
    }else if(QString::compare(QFileInfo(fileName).suffix().toLatin1(),"jpg", Qt::CaseInsensitive)==0){
      jpegWriter(fileName, 4);
    }else{
      fileName += ".png";
      pngWriter(fileName, 4);
    }
}

void PlotBandsDialog::close()
{
    infoLabel->setText(tr("Invoked <b>File|Close</b>"));
}

void PlotBandsDialog::clearPlotBandsItems(){
    //ui.outBandsTableView->model()->disconnect();
    ui.outBandsAlphaTableView->reset();
    qDebug()<<"PlotBandsDialog::clearPlotDosItems() 1";
    originalBandsXsize=10.0;
    originalBandsYsize=10.0;
    newBandsXsize=10.0;
    newBandsYsize=10.0;
    //model->removeColumns(0,model->columnCount());
    //model->removeRows(0,model->rowCount());
    //model->invisibleRootItem()->removeRows(0,model->rowCount());
    //model->rem
    qDebug()<<"PlotBandsDialog::clearPlotBandsItems() 2";
    //auxmodel->removeColumns(0,auxmodel->columnCount());
    //auxmodel->invisibleRootItem()->removeRows(0,auxmodel->rowCount());
    //modelBrillouin->removeColumns(0,modelBrillouin->columnCount());
    //ui.outBrillouinBandsTableView->model()->removeRows(0,ui.outBrillouinBandsTableView->model()->rowCount());

    qDebug()<<"PlotBandsDialog::clearPlotBandsItems() 3";
    standardItemListBandsAlpha.clear();
    standardItemListBandsBeta.clear();
    standardItemListBrillouin.clear();
    standardItemListBrillouinLabels.clear();
    qDebug()<<"PlotBandsDialog::clearPlotBandsItems() 4";
    fullBandsAlpha.clear();
    fullBandsBeta.clear();
    qDebug()<<"PlotBandsDialog::clearPlotBandsItems() 5";
    enerfullBands.clear();
    qDebug()<<"PlotBandsDialog::clearPlotBandsItems() 6";
    singlespinfullBands.clear();
    qDebug()<<"PlotBandsDialog::clearPlotBandsItems() 7";
    //viewDos->Delete();
    qDebug()<<"PlotBandsDialog::clearPlotBandsItems() 8";
    chartBands->ClearPlots();
    qDebug()<<"PlotBandsDialog::clearPlotBandsItems() 9";
    //chartDos->ClearItems();
    qDebug()<<"PlotBandsDialog::clearPlotBandsItems() 10";
    //lineDosAlpha->ClearItems();
    qDebug()<<"PlotBandsDialog::clearPlotBandsItems() 11";
    //lineDosBeta->ClearItems();
    qDebug()<<"PlotBandsDialog::clearPlotBandsItems() 12";
    //renderer->Clear();
    qDebug()<<"PlotBandsDialog::clearPlotBandsItems() 13";
    //renderWindow->RemoveRenderer(renderer);
    qDebug()<<"PlotBandsDialog::clearPlotBandsItems() 14";
    //renderWindow->Delete();
    qDebug()<<"PlotBandsDialog::clearPlotBandsItems() 15";
    //renderWindowInteractor->Delete();
    qDebug()<<"PlotBandsDialog::clearPlotBandsItems() 16";
    ui.qvtkWidgetBands->clearMask();
    qDebug()<<"PlotBandsDialog::clearPlotBandsItems() 17";
    //viewDos->GetScene()->ClearItems();
    qDebug()<<"PlotBandsDialog::clearPlotBandsItems() 18";

}

// Action to be taken upon file open
void PlotBandsDialog::slotOpenFile()
{

}

void PlotBandsDialog::slotExit() {
  //qApp->exit();
}

void PlotBandsDialog::on_autoScaleButton_clicked()
{
  //autoScalePlot();
}

void PlotBandsDialog::setBandsXRange( int i ) {
  qDebug()<<"setXRange Start.";
  //qApp->exit();
  //double d = (double) ((100-i)/100.0);
  double d = (double) pow(10.0,(double)(i/10.0));

  qDebug()<<"setXRange d = "<<d;
  double center = (double)(chartBands->GetAxis(1)->GetMinimum() + chartBands->GetAxis(1)->GetMaximum())/2.0;
  qDebug()<<"setXRange center = "<<center;
  //double newsize = (double)(d*(chart->GetAxis(1)->GetMaximum() - chart->GetAxis(1)->GetMinimum())/2.0);
  newBandsXsize = (double)(d*originalBandsXsize);
  qDebug()<<"setXRange old GetScalingFactor = "<<chartBands->GetAxis(1)->GetScalingFactor();
  qDebug()<<"setXRange newsize = "<<newBandsXsize;
  chartBands->GetAxis(1)->SetUnscaledRange((double)(center-newBandsXsize/2.0), (double)(center+newBandsXsize/2.0));

  //chart->GetAxis(1)->SetUnscaledRange(center-d, center+d);
  //chart->GetAxis(1)->SetRange(-d, d);
  //chart->GetAxis(1)->SetScalingFactor( d );
  qDebug()<<"setXRange 1.";
  chartBands->GetAxis(1)->Update(); // WORKS WITH DELAY.
  //areaDos->Update();
  //lineDosAlpha->Update();
  //lineDosBeta->Update();
  qDebug()<<"setXRange 2.";
  //view->Update();
  //view->GetInteractor()->Render();
  //view->Render();
  //std::cout << "Clicked." << std::endl;
  chartBands->Update();
  qDebug()<<"setXRange 3.";
  ui.qvtkWidgetBands->update();
  qDebug()<<"setXRange Finish.";
}

void PlotBandsDialog::setBandsYRange( int i ) {
  qDebug()<<"setYRange Start.";
  //qApp->exit();
  //double d = (double) ((100-i)/100.0);
  double d = (double) pow(10.0,(double)(i/10.0));

  qDebug()<<"setYRange d = "<<d;
  double center = (double)(chartBands->GetAxis(0)->GetMinimum() + chartBands->GetAxis(0)->GetMaximum())/2.0;
  qDebug()<<"setYRange center = "<<center;
  newBandsYsize = (double)(d*originalBandsYsize);
  qDebug()<<"setYRange old GetScalingFactor = "<<chartBands->GetAxis(0)->GetScalingFactor();
  qDebug()<<"setYRange newsize = "<<newBandsYsize;
  chartBands->GetAxis(0)->SetUnscaledRange((double)(center-newBandsYsize/2.0), (double)(center+newBandsYsize/2.0));

  //chart->GetAxis(0)->SetUnscaledRange(center-d, center+d);
  //chart->GetAxis(0)->SetRange(-d, d);
  //chart->GetAxis(0)->SetScalingFactor( d );
  qDebug()<<"setYRange 1.";
  chartBands->GetAxis(0)->Update(); // WORKS WITH DELAY.
  //areaDos->Update();
  //lineDosAlpha->Update();
  //lineDosBeta->Update();
  qDebug()<<"setYRange 2.";
  //view->Update();
  //view->GetInteractor()->Render();
  //view->Render();
  //std::cout << "Clicked." << std::endl;
  chartBands->Update();
  qDebug()<<"setYRange 3.";
  ui.qvtkWidgetBands->update();
  qDebug()<<"setYRange Finish.";
}

//------------ BANDS SIESTA ----------------------------------------------------
int PlotBandsDialog::modcheckStringBandsData(QString &temp, QChar character)
{
    int count = 0;
    if(temp.count("\"")%2 == 0) {
        //if (temp.size() == 0 && character != ',') //problem with line endings
        //    return;
        if (temp.startsWith( QChar('\"')) && temp.endsWith( QChar('\"') ) ) {
             temp.remove( QRegExp("^\"") );
             temp.remove( QRegExp("\"$") );
        }
        //FIXME: will possibly fail if there are 4 or more reapeating double quotes
        temp.replace("\"\"", "\"");
        QStandardItem *item = new QStandardItem(temp);
        datastandardItemList.append(item);
        //qDebug()<<"item->data(item->index(0,0)) = "<<item->data(item->index());
        qDebug()<<"item->data(0) = "<<item->data(0);
        //qDebug()<<"datastandardItemList[datastandardItemList.count()-1]->data(0) = "
        //       <<datastandardItemList[datastandardItemList.count()-1]->data(datastandardItemList[datastandardItemList.count()-1]->index(0,0));
        count = datastandardItemList.count();
        if (character != QChar(',') && character != QChar(' ')) {
            //datamodel->appendRow(datastandardItemList);
            datamodel->appendColumn(datastandardItemList);
            datastandardItemList.clear();
        }
        temp.clear();
    } else {
        temp.append(character);
    }
    qDebug()<<"count = "<<count;
    return count;
}

int PlotBandsDialog::modcheckStringBandsBrillouin(QString &temp, QChar character)
{
    int count = 0;
    if(temp.count("\"")%2 == 0) {
        //if (temp.size() == 0 && character != ',') //problem with line endings
        //    return;
        if (temp.startsWith( QChar('\"')) && temp.endsWith( QChar('\"') ) ) {
             temp.remove( QRegExp("^\"") );
             temp.remove( QRegExp("\"$") );
        }
        //FIXME: will possibly fail if there are 4 or more reapeating double quotes
        temp.replace("\"\"", "\"");
        QStandardItem *item = new QStandardItem(temp);
        //qDebug()<<"item->data(item->index(0,0)) = "<<item->data(item->index());
//        qDebug()<<"item->data(0) = "<<item->data(0);
        //qDebug()<<"datastandardItemList[datastandardItemList.count()-1]->data(0) = "
        //       <<datastandardItemList[datastandardItemList.count()-1]->data(datastandardItemList[datastandardItemList.count()-1]->index(0,0));
        //count = standardItemListBrillouin.count();
        //if (character != QChar(',') && character != QChar(' ')) {
        item->data(0).toString().remove(QChar(' '));
        //item->data(0).toString().isEmpty()
        if (character != QChar(',') && (item->data(0).toByteArray() != QChar(' ')) && !(item->data(0).toString().isEmpty())) {
          if (brillouinitemcount % 2) {
            standardItemListBrillouinLabels.append(item);
          }else{
            standardItemListBrillouin.append(item);
          }
//          qDebug()<<"standardItemListBrillouinLabels.size() = "<<standardItemListBrillouinLabels.size();
          //qDebug()<<"standardItemListBrillouinLabels["<<standardItemListBrillouinLabels.size()<<"].rowCount() = "<<standardItemListBrillouinLabels[standardItemListBrillouinLabels.size()-1]->rowCount();
          //qDebug()<<"standardItemListBrillouinLabels["<<standardItemListBrillouinLabels.size()<<"].rowCount() = "<<standardItemListBrillouinLabels[0]->rowCount();
          //standardItemListBrillouinLabels[0]->rowCount()
          //qDebug()<<"standardItemListBrillouin["<<standardItemListBrillouin.size()<<"].columnCount() = "<<standardItemListBrillouin[standardItemListBrillouin.size()-1]->columnCount();
          //qDebug()<<"standardItemListBrillouin["<<standardItemListBrillouin.size()<<"].columnCount() = "<<standardItemListBrillouin[0]->columnCount();
//          qDebug()<<"standardItemListBrillouin.size() = "<<standardItemListBrillouin.size();
          brillouinitemcount++;
//          qDebug()<<"brillouinitemcount = "<<brillouinitemcount;
        }

        count = brillouinitemcount;
        //if (character != QChar(',') && character != QChar(' ')) {
        if (character != QChar(',')) {
            if (brillouinitemcount % 2) {
              //modelBrillouin->appendRow(standardItemListBrillouinLabels);
              //modelBrillouin->appendColumn(standardItemListBrillouin);
              //standardItemListBrillouinLabels.clear();
            }else{
              //modelBrillouin->appendRow(standardItemListBrillouin);
              //modelBrillouin->appendColumn(standardItemListBrillouin);
              //standardItemListBrillouin.clear();
            }
        }
        temp.clear();
    } else {
        temp.append(character);
    }
    qDebug()<<"count = "<<count;
    return count;
}

int PlotBandsDialog::modcheckStringBands(QString &temp, QChar character, int bandsnumspin, int bandsnumcol)
{
    int rowCount = 0;
    if(temp.count("\"")%2 == 0) {
        //if (temp.size() == 0 && character != ',') //problem with line endings
        //    return;
        if (temp.startsWith( QChar('\"')) && temp.endsWith( QChar('\"') ) ) {
             temp.remove( QRegExp("^\"") );
             temp.remove( QRegExp("\"$") );
        }
        //FIXME: will possibly fail if there are 4 or more reapeating double quotes
        temp.replace("\"\"", "\"");
        QStandardItem *item = new QStandardItem(temp);
        standardItemList.append(item);
        //qDebug()<<"item->data(item->index(0)).toDouble() = "<<item->data(item->index(0)).toDouble();
//        qDebug()<<"item->data(0).toDouble() = "<<item->data(0).toDouble();
//        qDebug()<<"((standardItemList.count()-1)/10)"<<(int)((standardItemList.count()-1)/10);
//        qDebug()<<"(int)((standardItemList.count()-1)/10)"<<((standardItemList.count()-1)/10);
//        qDebug()<<"((float)(standardItemList.count()-1)/10.0)-(float)((int)((standardItemList.count()-1)/10))";
//        qDebug()<<((float)(standardItemList.count()-1)/10.0)-(float)((int)((standardItemList.count()-1)/10));
        //getchar();
        //if (character != QChar(',') && character != QChar(' ')) { // COMMENTED BY C.SALGADO TO READ BANDS.
        if ((character != QChar(',')) && (character != QChar(' ')) && (bandsnumspin==1) && (standardItemList.count()-1==bandsnumcol)) {
            qDebug()<<"COMPLETED OPTION A!!!";

            //getchar();

            modelBandsAlpha->appendRow(standardItemList);
            standardItemList.clear();
            rowCount = modelBandsAlpha->rowCount();
        }else if ((character != QChar(',')) && (character != QChar(' ')) && (bandsnumspin==2) && (standardItemList.count()-1==2*bandsnumcol)) {
//            qDebug()<<"COMPLETED OPTION B!!!";

            //getchar();

            modelBandsAlpha->appendRow(standardItemList.mid(0,bandsnumcol+1));

            //modelBandsBeta->appendRow(standardItemList.mid(0,1)); // APPEND ENERGY ELEMENT ALSO TO BETA.
            QList<QStandardItem*> tempList;// = new QStandardItem();
            //tempList.append(standardItemList.mid(0,1));
            //tempList[0] = standardItemList.mid(0,1);
            //tempList<<standardItemList.mid(0,1);
            tempList.append(standardItemList[0]->clone());
            tempList.append(standardItemList.mid(bandsnumcol+1,bandsnumcol));
            //standardItemList.mid(0,1)
            //modelBandsBeta->appendRow(standardItemList.mid(bandsnumcol+1,bandsnumcol));
            modelBandsBeta->appendRow(tempList);
            standardItemList.clear();
            rowCount = modelBandsAlpha->rowCount();
        //}else if ((character == QChar('\n') && (standardItemList.count()==bandsnumcol+1) && (((float)(standardItemList.count()-1)/10.0)-(float)((int)((standardItemList.count()-1)/10))>0.0))){
        }else if ((character == QChar('\n') && (((float)(standardItemList.count()-1)/10.0)-(float)((int)((standardItemList.count()-1)/10))>0.0))){
//            qDebug()<<"COMPLETED OPTION C!!!";

//            qDebug()<<"(standardItemList.count()-1) = "<<(standardItemList.count()-1);

            //getchar();
            modelBandsAlpha->appendRow(standardItemList);
            standardItemList.clear();
            rowCount = modelBandsAlpha->rowCount();
        }
        temp.clear();
    } else {
        temp.append(character);
    }
    return rowCount;
}

void PlotBandsDialog::on_outputBandsButton_clicked_old()
{
    //QString fileName =
    QString fullpathfileName =
        QFileDialog::getOpenFileName(
                this,
                tr("Open File"),
                "C:/TEST",
                //tr("videoss (*.mp4 *.mov *.avi)"));
                //tr("(*.mp4 *.mov *.avi)"));
                tr("(*.bands)"));
    QFileInfo fi(fullpathfileName);
    QString bandsfileName = fi.fileName();
//    qDebug() << "bandsfileName" << bandsfileName;
    QString fileName = fi.baseName();
    //MyClass dataTransmission = new MyClass();
    //MyClass::jobname = fileName;
    jobname = fileName;
//    qDebug() << "fileName" << fileName;
    //QFileInfo::basename().toStdString()
    if (!fileName.isEmpty()) {
        //ui->bandsLineEdit->setText(bandsfileName);
        //ui->iniLineEdit->setText(fileName + ".ini");
        //ui->toLineEdit->setText(fileName + ".log");
        //loadIniFile(fileName + ".ini");
        //loadBandsFile(bandsfileName);
    }
}

// Browse... button clicked - this is for input file
//void Dialog::on_fileOpenButton_clicked()
//void OpenTransmWidget::on_opentransmOpenButton_clicked()
//void OpenTransmWidget::on_opentransmOpenButton_clicked()
//void MainWindow::on_outtransmpushButton_clicked()
void PlotBandsDialog::on_outputBandsButton_clicked()
{
//    qDebug() <<"PlotBandsDialog::on_outputBandsButton_clicked() 1";
    clearPlotBandsItems();

//    //widget_2
//    QString fileName =
//        QFileDialog::getOpenFileName(
//                this,
//                tr("Open File"),
//                "C:/TEST",
//                //tr("videoss (*.mp4 *.mov *.avi)"));
//                //tr("(*.mp4 *.mov *.avi)"));
//                tr("(*.csv)"));
//    if (!fileName.isEmpty()) {
//        ui->outbandslineEdit->setText(fileName);
//    }

    datamodel = new QStandardItemModel(this);
    //ui->outdatabandstableView->setModel(datamodel);
    modelBrillouin = new QStandardItemModel(this);
    ui.outBrillouinBandsTableView->setModel(modelBrillouin);

    modelBandsAlpha = new QStandardItemModel(this);
    ui.outBandsAlphaTableView->setModel(modelBandsAlpha);
    modelBandsBeta = new QStandardItemModel(this);
    ui.outBandsBetaTableView->setModel(modelBandsBeta);

    // ADDED BY C.SALGADO TO READ SIESTA BANDS.
    //QString line1 = file.readLine()
    int dataelemcount = 0;
    int newlinecount = 0;
    bandsnumspin = 1;
    int bandsnumrow = 1;
    int bandsnumcol = 1;
    int rowCountBands = 0;
    int brillouinelemcount = 0;
    int numBrillouinSegments = 1;

    //QString fileName = QFileDialog::getOpenFileName (this, "Open CSV file",
    //                                                 QDir::currentPath(), "CSV (*.csv)");
    QString fileName = QFileDialog::getOpenFileName (this, "Open BANDS file",
                                                     QDir::currentPath(), "BANDS (*.bands *.BANDS)");
  if (!fileName.isEmpty()){
    QFile file (fileName);
    if (file.open(QIODevice::ReadOnly)) {
        QString data = file.readAll();
        data.remove( QRegExp("\r") ); //remove all ocurrences of CR (Carriage Return)
        QString temp;
        QChar character;
        QTextStream textStream(&data);
        textStream.skipWhiteSpace();


        //while (!textStream.atEnd()) {
        while ((dataelemcount < 9) & (newlinecount < 1) & (!textStream.atEnd())){
            textStream >> character;
//            qDebug()<<"character = "<<character;
            if (character == ',') {
                dataelemcount = modcheckStringBandsData(temp, character);
            } else if (character == '\0') {
                dataelemcount = modcheckStringBandsData(temp, character);
            } else if (character == QChar(' ')) {
                //textStream >> character;
                //textStream >> character;
                textStream.skipWhiteSpace();
                dataelemcount = modcheckStringBandsData(temp, character);
            } else if (character == QChar('\n')) {
                newlinecount++;
                textStream.skipWhiteSpace();
                dataelemcount = modcheckStringBandsData(temp, character);
            } else if (character == QChar('\r')) {
                newlinecount++;
                textStream.skipWhiteSpace();
                dataelemcount = modcheckStringBandsData(temp, character);
            } else if ((newlinecount >= 100) | (textStream.atEnd())) {
                temp.append(character);
                dataelemcount = modcheckStringBandsData(temp);
            } else {
                temp.append(character);
            }
        }
        bandsnumrow = datamodel->data(datamodel->index(7,0)).toInt();
        bandsnumspin = datamodel->data(datamodel->index(6,0)).toInt();
        bandsnumcol = datamodel->data(datamodel->index(5,0)).toInt();

        int linesPerRow = (int)(bandsnumcol/10)+1;
        //datamodel->item(0,0);
        qDebug()<<"datamodel->itemData(datamodel->index(0,0)) = "<<datamodel->itemData(datamodel->index(0,0));
        qDebug()<<"datamodel->data(datamodel->index(0,0)).toDouble() ="<<datamodel->data(datamodel->index(0,0)).toDouble();
        //qDebug()<<"datamodel->data(datamodel->index(7,0)).toInt() ="<<datamodel->data(datamodel->index(8,1)).toInt();
        qDebug()<<"datamodel->data(datamodel->index(0,7)).toInt() ="<<datamodel->data(datamodel->index(0,7)).toInt();
        qDebug()<<"dataelemcount = "<<dataelemcount;
        qDebug()<<"bandsnumrow = "<<bandsnumrow<<"; bandsnumcol = "<<bandsnumcol<<";";
        // END SIESTA BANDS.
        //while (!textStream.atEnd()) {
        newlinecount = 0;
        //while ((newlinecount<bandsnumrow) & (!textStream.atEnd())) {
        while ((rowCountBands<bandsnumrow) & (!textStream.atEnd())) {
            textStream >> character;
            if (character == ',') {
                rowCountBands = modcheckStringBands(temp, character, bandsnumspin , bandsnumcol);
            //} else if (character == '\0') {
            //    modcheckString(temp, character);
            } else if (character == QChar(' ')) {
                //textStream >> character;
                //textStream >> character;
                textStream.skipWhiteSpace();
                rowCountBands = modcheckStringBands(temp, character, bandsnumspin, bandsnumcol);
            } else if (character == QChar('\n')) {
                newlinecount++;
                textStream.skipWhiteSpace();
                rowCountBands = modcheckStringBands(temp, character, bandsnumspin, bandsnumcol);
            } else if (textStream.atEnd()) {
                temp.append(character);
                character = QChar('\n');  // ADDED BY C.SALGADO TO READ BANDS.
                //bandscheckString(temp); // COMMENTED BY C.SALGADO TO READ BANDS.
                rowCountBands = modcheckStringBands(temp, character, bandsnumspin, bandsnumcol); // ADDED BY C.SALGADO TO READ BANDS.
            } else {
                temp.append(character);
            }
        }
        dataelemcount = 0;
        newlinecount = 0;
        while ((dataelemcount < 1) & (newlinecount < 1) & (!textStream.atEnd())){
            textStream >> character;
//            qDebug()<<"character = "<<character;
            if (character == ',') {
                dataelemcount = modcheckStringBandsData(temp, character);
            } else if (character == '\0') {
                dataelemcount = modcheckStringBandsData(temp, character);
            } else if (character == QChar(' ')) {
                //textStream >> character;
                //textStream >> character;
                textStream.skipWhiteSpace();
                dataelemcount = modcheckStringBandsData(temp, character);
            } else if (character == QChar('\n')) {
                newlinecount++;
                textStream.skipWhiteSpace();
                dataelemcount = modcheckStringBandsData(temp, character);
            } else if (character == QChar('\r')) {
                newlinecount++;
                textStream.skipWhiteSpace();
                dataelemcount = modcheckStringBandsData(temp, character);
            } else if ((newlinecount >= 100) | (textStream.atEnd())) {
                temp.append(character);
                dataelemcount = modcheckStringBandsData(temp);
            } else {
                temp.append(character);
            }
        }

        // AVOID STOPPING. NOT NECESSARY ANYMORE.
        //system("pause");
//        qDebug()<<"dataelemcount = "<<dataelemcount;
//        qDebug()<<"datamodel->data(datamodel->index(0,1)).toInt() = "<<
                  datamodel->data(datamodel->index(0,1)).toInt();
        numBrillouinSegments = datamodel->data(datamodel->index(0,1)).toInt();
//        qDebug()<<"numBrillouinSegments = "<<numBrillouinSegments;
        //getchar();
        //while ((brillouinelemcount < 2*numBrillouinSegments) && (!textStream.atEnd())){
        while ((!textStream.atEnd())){
            textStream >> character;
//            qDebug()<<"character = "<<character;
            if (character == ',') {
                brillouinelemcount = modcheckStringBandsBrillouin(temp, character);
            } else if (character == '\0') {
                brillouinelemcount = modcheckStringBandsBrillouin(temp, character);
            } else if (character == QChar(' ')) {
                //textStream >> character;
                //textStream >> character;
                textStream.skipWhiteSpace();
                brillouinelemcount = modcheckStringBandsBrillouin(temp, character);
            } else if (character == QChar('\n')) {
                newlinecount++;
                textStream.skipWhiteSpace();
                brillouinelemcount = modcheckStringBandsBrillouin(temp, character);
            } else if (character == QChar('\r')) {
                newlinecount++;
                textStream.skipWhiteSpace();
                brillouinelemcount = modcheckStringBandsBrillouin(temp, character);
            } else if ((newlinecount >= 100) | (textStream.atEnd())) {
                temp.append(character);
                brillouinelemcount = modcheckStringBandsBrillouin(temp);
            } else {
                temp.append(character);
            }
//            qDebug()<<"standardItemListBrillouinLabels.count() = "<<standardItemListBrillouinLabels.count();
//            qDebug()<<"standardItemListBrillouin.count() = "<<standardItemListBrillouin.count();
          }
        modelBrillouin->appendColumn(standardItemListBrillouinLabels);
        modelBrillouin->appendColumn(standardItemListBrillouin);
//        qDebug()<<"modelBrillouin->(rowcount,columncount) = "<<modelBrillouin->rowCount()<<","<<modelBrillouin->columnCount();
        // AVOID STOPPING. NOT NECESSARY ANYMORE.
        //getchar();

    }
    //MyClass::*modelTransmission = *model;
//    qDebug() << modelBandsAlpha->item(1,1);
    //qDebug() << MyClass::s_count;




    qint32 n = modelBandsAlpha->rowCount();
    qint32 m = modelBandsAlpha->columnCount();
    //int n = model->rowCount();
    //int m = model->columnCount();
    qDebug() << "n" << n << "m" << m ;

    //MyClass dataTransmission = new MyClass();
    //QList<float> dataTransmission = MyClass::colTransmission;
    //QList<double> dataBands = MyClass::fullBands;
    QList<double> pivdataBandsAlpha;
    QList<double> pivdataBandsBeta;
    QList<QList<double> > dataBandsAlpha;
    QList<QList<double> > dataBandsBeta;
    //QList<double> energyBands = MyClass::enerfullBands;
    QList<double> energyBands;
    //MyClass:: dataBands;

    //QStandardItem *item = new QStandardItem(dataBands[0]);
    //QList< QStandardItem * > items;

    //bool isMagneticBands = false;
    //int numcolDataTransmission = 1;
    for (int jcol=0; jcol<m; ++jcol){
      for (int i=0; i<n; ++i){
          if(jcol==0){
            energyBands << modelBandsAlpha->data(modelBandsAlpha->index(i,0)).toDouble();
          }else if(jcol>0){
//            qDebug() << "modelBandsAlpha->index(i,0);" << modelBandsAlpha->index(i,0);
//            qDebug() << "modelBandsAlpha->index(i,1);" << modelBandsAlpha->index(i,jcol);
            //qDebug() << "model->data(model->index(i,2)).toString();" << modelBandsAlpha->data(modelBandsAlpha->index(i,jcol)).toString();
//            qDebug() << "modelBandsAlpha->data(modelBandsAlpha->index(i,2)).toFloat();" << modelBandsAlpha->data(modelBandsAlpha->index(i,jcol)).toDouble();
            //MyClass::dataBands << model->data(model->index(i,1)).toFloat();
            //dataBands << model->data(model->index(i,1)).toFloat();
            pivdataBandsAlpha << modelBandsAlpha->data(modelBandsAlpha->index(i,jcol)).toDouble();
//            qDebug() << "pivdataBandsAlpha["<<i<<"]"<< pivdataBandsAlpha[i];
            if(bandsnumspin==2){
              pivdataBandsBeta << modelBandsBeta->data(modelBandsBeta->index(i,jcol)).toDouble();
//              qDebug() << "pivdataBandsBeta["<<i<<"]" << pivdataBandsBeta[i];
            }
          }
      }
      dataBandsAlpha.append(pivdataBandsAlpha);
      pivdataBandsAlpha.clear();
      if(bandsnumspin==2){
        dataBandsBeta.append(pivdataBandsBeta);
        pivdataBandsBeta.clear();
      }
    }

    //qDebug() << "item" << item;
    //model->appendColumn(standardItemList);
    /*
    float f = 0;
    for (int i=0; i<n; ++i){
        f = dataBands[i];
        qDebug() << "f" << f;
        QStandardItem *item = new QStandardItem(f);
        qDebug() << "item" << item;
        standardItemList.append(item);
        //model->appendRow(standardItemList);
        //model->setItem(i,2,item);
    }
    */
    /*
    for (int jcol=0; jcol<dataBandsAlpha.size(); ++jcol){
      for (int i=0; i<n; ++i){
        QVariant varBandsAlpha(dataBandsAlpha[jcol][i]);
        //QStandardItem *elemBands = new QStandardItem(dataBands[i]);
        QStandardItem *elemBands = new QStandardItem(varBands.toString());
        standardItemList.append(elemBands);
        //model->setItem(i,0,elemBands);
        if(bandsnumspin==2){

        }
      }
      //model->appendColumn(standardItemList);
      //model->insertColumn(2,standardItemList); // COMMENTED ON 2016-08-10 TO AVOID PROBLEMS IN BANDS.
      standardItemList.clear(); // ADDED ON 2016-08-10 TO AVOID PROBLEMS IN BANDS.
    }
    */

    //standardItemList.clear();
    //model->appendColumn(dataBands);
    //MyClass::fullBands = dataBands;
    enerfullBands = energyBands;

    fullBandsAlpha = dataBandsAlpha;
    fullBandsAlpha[0] = enerfullBands;
    if(bandsnumspin==2){
      fullBandsBeta = dataBandsBeta;
      fullBandsBeta[0] = enerfullBands;
    }
      //MyClass::enerfullBands = energyBands;

    for (int jcol=0; jcol<fullBandsAlpha.size(); ++jcol){
      for (int i=0; i<fullBandsAlpha[jcol].size(); ++i){
//        qDebug()<<"fullBandsAlpha["<<jcol<<"]["<<i<<"]"<<fullBandsAlpha[jcol][i];
        if(bandsnumspin==2){
//          qDebug()<<"fullBandsBeta["<<jcol<<"]["<<i<<"]"<<fullBandsBeta[jcol][i];
        }
      }
    }
    //----- PLOT THE BANDS AFTER READING THESE ---------------------------------
    on_plotBandsButton_clicked(); // VERY IMPORTANT TO START PLOTTING THE BANDS.
    //--------------------------------------------------------------------------
  }
}
//---------- END BANDS SIESTA --------------------------------------------------


void PlotBandsDialog::on_plotBandsButton_clicked_old(){

    int currentColumn = 3;
//    qDebug()<<"PlotBandsDialog::on_plotBandsButton_clicked() 0";
    //chartBands->RemovePlot(0);
    //chartBands->RemovePlot(1);
    //chartBands->RecalculateBounds();
    //chartBands->RecalculatePlotBounds();
    //chartBands->RecalculatePlotTransforms();
    qDebug()<<"PlotBandsDialog::on_plotBandsButton_clicked() 0a";
    chartBands->ClearPlots();
    qDebug()<<"PlotBandsDialog::on_plotBandsButton_clicked() 0b";
    //for (int i = 0; i < viewBands->GetScene()->GetNumberOfItems(); ++i){
    //  viewBands->GetScene()->GetItem(i)->ClearItems();
    //}
    qDebug()<<"PlotBandsDialog::on_plotBandsButton_clicked() 0c";
    for (int i = 0; i < chartBands->GetNumberOfAxes(); ++i){
      chartBands->GetAxis(i)->ClearItems();
    }
    qDebug()<<"PlotBandsDialog::on_plotBandsButton_clicked() 0d";
    for (int i = 0; i < chartBands->GetNumberOfPlots(); ++i){
      chartBands->RemovePlot(i);
    }
    qDebug()<<"PlotBandsDialog::on_plotBandsButton_clicked() 0e";


// Bands PLOT.
qDebug()<<"PlotBandsDialog::on_plotBandsButton_clicked() 1";
QList<QList<double>> dataBandsAlpha = fullBandsAlpha;
QList<QList<double>> dataBandsBeta = fullBandsBeta;
QList<double> enerdataBands = enerfullBands;



//if(bandsnumspin==2){
//  for (int col=0; col<dataBandsBeta.size(); ++col){
//    for (int row=0; row<dataBandsBeta[col].size(); ++row){
//      qDebug()<<"dataBandsAlpha["<<col<<"]["<<row<<"] = "<<dataBandsAlpha[col][row];
//      qDebug()<<"dataBandsBeta["<<col<<"]["<<row<<"] = "<<dataBandsBeta[col][row];
//    }
//  }
//}else{
//  for (int col=0; col<dataBandsAlpha.size(); ++col){
//    for (int row=0; row<dataBandsAlpha[col].size(); ++row){
//      qDebug()<<"dataBandsAlpha["<<col<<"]["<<row<<"] = "<<dataBandsAlpha[col][row];
//    }
//  }
//}

qint32 numcolDataBandsAlpha = dataBandsAlpha.size();
//int n = dataBandsAlpha[currentColumn].size();
//QVector<float> x(enerdataBands.size()), y1(n);
//QVector<QVector<float>> y0(numcolDataBandsAlpha);
//QVector<QVector<float>> y0(2);
QVector<float> x(enerdataBands.size());
QVector<QVector<float>> y0(dataBandsAlpha.size());
QVector<QVector<float>> y1(dataBandsBeta.size());

y0[0].resize(dataBandsAlpha[1].size());
for (int col=1; col<dataBandsAlpha.size(); ++col){
//for (int col=0; col<2; ++col){
  y0[col].resize(dataBandsAlpha[col].size());
}
if(bandsnumspin==2){
  y1[0].resize(dataBandsBeta[1].size());
  for (int col=1; col<dataBandsBeta.size(); ++col){
    y1[col].resize(dataBandsBeta[col].size());
  }
}

/*
qint32 numcolDataBandsBeta = dataBandsBeta.size();
int nBeta = dataBandsBeta[0].size();
QVector<float> y1Beta(nBeta);
QVector<QVector<float>> y0Beta(numcolDataBandsBeta);
for (int col=0; col<numcolDataBandsBeta; ++col){
  y0Beta[col].resize(nBeta);
}
*/

//vtkNew<vtkFloatArray> xvtkfloat;
//vtkNew<vtkFloatArray> y0vtkfloat;
qDebug()<<"PlotBandsDialog::on_plotBandsButton_clicked() 2. dataBandsAlpha.size() = "<<dataBandsAlpha.size();
//xvtkfloat->SetNumberOfComponents(n);
//y0vtkfloat->SetNumberOfComponents(n);
for (int i=0; i<enerdataBands.size(); ++i)        {
  x[i] = (float)enerdataBands[i];
  qDebug()<<"enerdataBands["<<i<<"]"<<enerdataBands[i];
  //xvtkfloat->SetValue(i,(float)enerdataBands[i]);
}
/*
for (int col=0; col<dataBandsAlpha.size(); ++col){
  for (int row=0; row<dataBandsAlpha[col].size(); ++row){
    y0[col][row] = (float)dataBandsAlpha[col][row];
    qDebug()<<"dataBands["<<col<<"]["<<row<<"] = "<< dataBandsAlpha[col][row];
  }
}
*/
qDebug()<<"dataBandsAlpha.size() = "<<dataBandsAlpha.size();
qDebug()<<"dataBandsAlpha[0].size() = "<<dataBandsAlpha[0].size();
for (int col=1; col<dataBandsAlpha.size(); ++col){
//  qDebug()<<"dataBandsAlpha["<<col<<"].size() = "<<dataBandsAlpha[col].size();
  for (int row=0; row<dataBandsAlpha[col].size(); ++row){
    y0[col][row] = (float)dataBandsAlpha[col][row];
    //y0[1][row] = (float)dataBandsBeta[currentColumn][row];
//    qDebug()<<"y0[0:"<<col<<"]["<<row<<"] = ["<< y0[0][row]<<","<<y0[col][row]<<"]";
    if(bandsnumspin==2){
      y1[col][row] = (float)dataBandsBeta[col][row];
//      qDebug()<<"y1[0:"<<col<<"]["<<row<<"] = ["<< y1[0][row]<<","<<y1[col][row]<<"]";
    }
  }
}

  //-----------------------------------------------------------------
  //-----------------------------------------------------------------

  qDebug()<<"PlotBandsDialog::PlotBandsBandsDialog() 3";

  // Create a table with some points in it...
  //vtkNew<vtkTable> table;
  //vtkSmartPointer<vtkTable> table =
  //    vtkSmartPointer<vtkTable>::New();
  //vtkNew<vtkTable> tableBands;
  vtkSmartPointer<vtkTable> tableAlpha =
        vtkSmartPointer<vtkTable>::New();
  vtkSmartPointer<vtkTable> tableBeta =
        vtkSmartPointer<vtkTable>::New();

  vtkSmartPointer<vtkTable> tableFermi =
      vtkSmartPointer<vtkTable>::New();

  vtkSmartPointer<vtkTable> tableMask =
      vtkSmartPointer<vtkTable>::New();

  vtkNew<vtkFloatArray> arrFermiX;
  arrFermiX->SetName("X Fermi");
  tableFermi->AddColumn(arrFermiX.GetPointer());

  vtkNew<vtkFloatArray> arrFermiY;
  arrFermiY->SetName("Y Fermi");
  tableFermi->AddColumn(arrFermiY.GetPointer());

  vtkNew<vtkFloatArray> arrBandsAlphaX;
  arrBandsAlphaX->SetName("X Axis");
  tableAlpha->AddColumn(arrBandsAlphaX.GetPointer());
  //tableBeta->AddColumn(arrBandsX.GetPointer());

  vtkNew<vtkFloatArray> arrBandsBetaX;
  arrBandsBetaX->SetName("X Axis");
  //tableAlpha->AddColumn(arrBandsX.GetPointer());
  tableBeta->AddColumn(arrBandsBetaX.GetPointer());

  vtkNew<vtkFloatArray> alphaBands;
  //vtkNew<vtkDataArray> alphaBands;
  alphaBands->SetName("AlphaBands");
  alphaBands->SetNumberOfTuples(dataBandsAlpha.size());
  //tableAlpha->AddColumn(alphaBands.GetPointer());

  vtkNew<vtkFloatArray> betaBands;
  betaBands->SetName("BetaBands");
  //tableBeta->AddColumn(betaBands.GetPointer());

  for (int col=0; col<dataBandsAlpha.size(); ++col){
    vtkNew<vtkFloatArray> pivotBands;
    tableAlpha->AddColumn(pivotBands.GetPointer());
    tableAlpha->GetColumn(col)->SetName((QString("AlphaBands%1").arg(col)).toLatin1());
  }

  for (int col=0; col<dataBandsBeta.size(); ++col){
    vtkNew<vtkFloatArray> pivotBands;
    tableBeta->AddColumn(pivotBands.GetPointer());
    tableBeta->GetColumn(col)->SetName((QString("BetaBands%1").arg(col)).toLatin1());
  }

  vtkNew<vtkCharArray> validMask;
  validMask->SetName("ValidMask");
  //table->AddColumn(validMask.GetPointer());
  //tableAlpha->AddColumn(validMask.GetPointer());
  //tableBeta->AddColumn(validMask.GetPointer());
  tableMask->AddColumn(validMask.GetPointer());


  qDebug()<<"PlotBandsDialog::PlotBandsBandsDialog() 4";

  // Test charting with a few more points...
  //float inc = 7.5 / (n-1);


  tableAlpha->SetNumberOfRows(enerdataBands.size());
  tableBeta->SetNumberOfRows(enerdataBands.size());
  tableMask->SetNumberOfRows(enerdataBands.size());

  qDebug()<<"PlotBandsDialog::PlotBandsBandsDialog() 4a";
  // col=0
  qDebug()<<"dataBandsAlpha[1].size() = "<<dataBandsAlpha[1].size();
  qDebug()<<"enerdataBands.size() = "<<enerdataBands.size();
  if(bandsnumspin==2){
      //tableAlpha->AddColumn(arrBandsAlphaX.GetPointer());
      //tableBeta->AddColumn(arrBandsBetaX.GetPointer());
    for (int row = 0; row < enerdataBands.size(); ++row){
      qDebug()<<"x["<<row<<"] = "<<x[row];
      tableAlpha->SetValue(row, 0, (float)(x[row]));
      //qDebug()<<"tableAlpha->GetValue("<<row<<",0) = "<<tableAlpha->GetValue(row,0).ToFloat();
      tableBeta->SetValue(row, 0, (float)(x[row]));
      //qDebug()<<"tableBeta->GetValue("<<row<<",0) = "<<tableBeta->GetValue(row,0).ToFloat();
      validMask->SetValue(row,1);
    }
  }else{
    //tableAlpha->AddColumn(arrBandsAlphaX.GetPointer());
    for (int row = 0; row < enerdataBands.size(); ++row){
      qDebug()<<"x["<<row<<"] = "<<x[row];
      tableAlpha->SetValue(row, 0, (float)(x[row]));
      //qDebug()<<"tableAlpha->GetValue("<<row<<",0) = "<<tableAlpha->GetValue(row,0).ToFloat();
      validMask->SetValue(row,1);
    }
  }
  qDebug()<<"PlotBandsDialog::PlotBandsBandsDialog() 4b";
  for (int col=1; col<dataBandsAlpha.size(); ++col){
      //vtkNew<vtkFloatArray> AlphaBands;
      //vtkSmartPointer<vtkFloatArray> AlphaBands =
      //    vtkSmartPointer<vtkFloatArray>::New();
      //  AlphaBands->SetName((QString("AlphaBands%1").arg(col)).toLatin1());
//      tableAlpha->AddColumn(alphaBands.GetPointer());
      //tableAlpha->SetNumberOfRows(enerdataBands.size());
      //vtkNew<vtkFloatArray> BetaBands;
      //vtkSmartPointer<vtkFloatArray> BetaBands =
      //    vtkSmartPointer<vtkFloatArray>::New();
      //  BetaBands->SetName((QString("BetaBands%1").arg(col)).toLatin1());
      if(bandsnumspin==2){
 //       tableBeta->AddColumn(betaBands.GetPointer());
        //tableBeta->SetNumberOfRows(enerdataBands.size());
      }

      for (int row = 0; row < dataBandsAlpha[col].size(); ++row){
        //table->SetValue(i, 0, i * inc + 0.01);
        //table->SetValue(row, 0, (float)(x[row]));
        //table->SetValue(i, 1, y0[0][i]);
        //table->SetValue(row, 1, y0[currentColumn][row]);
        qDebug()<<"y0["<<col<<"]["<<row<<"]"<<y0[col][row];
        tableAlpha->SetValue(row, col, (float)(y0[col][row]));
        //validMask->SetValue(row,1);
        //qDebug()<<"tableAlpha->GetValue("<<row<<","<<col<<") = "<<tableAlpha->GetValue(row,col).ToFloat();
        if(bandsnumspin==2){
          //table->SetValue(i, 2, y0[1][row]);
          qDebug()<<"y1["<<col<<"]["<<row<<"]"<<y1[col][row];
          tableBeta->SetValue(row, col, (float)(y1[col][row]));
          //qDebug()<<" tableBeta->GetValue("<<row<<","<<col<<") = "<<tableBeta->GetValue(row,col).ToFloat();
          //table->SetValue(row, 2, y0[currentColumn][row]);
          //BetaBandsUp->SetValue(i,-y0[1][i]);
          //table->SetValue(i, 4, -y0[1][i] - 0.01);
        }
        //qDebug()<<"tableAlpha->GetValue("<<row<<",2) = "<<tableAlpha->GetValue(row,col).ToFloat();
      }
      //AlphaBands->Reset();
      //AlphaBands->Delete();
      if(bandsnumspin==2){
        //BetaBands->Reset();
      }
      //BetaBands->Delete();
  }

  for (int col=0; col<dataBandsAlpha.size(); ++col){
    qDebug()<<"dataBandsAlpha["<<col<<"].size()"<<dataBandsAlpha[col].size();
    for (int row = 0; row < dataBandsAlpha[col].size(); ++row){
      qDebug()<<"tableAlpha->GetValue("<<row<<","<<col<<") = "<<tableAlpha->GetValue(row,col).ToFloat();
      if(bandsnumspin==2){
        qDebug()<<" tableBeta->GetValue("<<row<<","<<col<<") = "<<tableBeta->GetValue(row,col).ToFloat();
      }
    }
  }

  qDebug()<<"PlotBandsDialog::PlotBandsBandsDialog() 4c";

  //tableAlpha->AddColumn(validMask.GetPointer()); // COMES FROM UP
  //tableBeta->AddColumn(validMask.GetPointer()); // COMES FROM UP

  // Add multiple line plots, setting the colors etc
  //lineBands = vtkPlotLine::SafeDownCast(chartBands->AddPlot(vtkChart::LINE));
  //vtkPlot *line = chartBands->AddPlot(vtkChart::LINE);
  //vtkSmartPointer<vtkPlotLine> lineBandsAlpha =
  //    vtkSmartPointer<vtkPlotLine>::New();
  //chartBands->RemovePlot(0);
  //lineBandsAlpha = vtkPlotLine::SafeDownCast(chartBands->AddPlot(vtkChart::LINE));
  vtkPlot *lineBandsAlpha = chartBands->AddPlot(vtkChart::LINE);

  qDebug()<<"PlotBandsDialog::PlotBandsBandsDialog() 4d";
  //int col=2;
  for (int col=1; col<dataBandsAlpha.size(); ++col){

  if(col>2){
    lineBandsAlpha = chartBands->AddPlot(vtkChart::LINE);
  }

  qDebug()<<"PlotBandsDialog::PlotBandsBandsDialog() 4e";

  //line->SetInputData(table.GetPointer());
  //line->SetInputArray(1, "AlphaBandsUp");
#if VTK_MAJOR_VERSION <= 5
  lineBandsAlpha->SetInput(tableAlpha, 0, col);
#else
  lineBandsAlpha->SetInputData(tableAlpha, 0, col);
#endif
  qDebug()<<"PlotBandsDialog::PlotBandsBandsDialog() 4f";
  lineBandsAlpha->SetColor( 0, 0, 255, 255 );
  lineBandsAlpha->SetWidth(2.0);
  //vtkPlotLine::SafeDownCast(line)->SetMarkerStyle(vtkPlotLine::CROSS);

  qDebug()<<"PlotBandsDialog::PlotBandsBandsDialog() 4g";
  //lineBandsAlpha->SetValidPointMaskName("ValidMask");

  lineBandsAlpha->Update();
  qDebug()<<"Finish Alpha col = "<<col;
  }
  qDebug()<<"Finish Alpha Total ";

  //vtkSmartPointer<vtkPlotLine> lineBandsBeta =
  //    vtkSmartPointer<vtkPlotLine>::New();
  //lineBandsBeta = vtkPlotLine::SafeDownCast(chartBands->AddPlot(vtkChart::LINE));
  vtkPlot *lineBandsBeta = chartBands->AddPlot(vtkChart::LINE);
  if(bandsnumspin==2){
    //col=2;
    for (int col=1; col<dataBandsBeta.size(); ++col){
    if(col>2){
      lineBandsBeta = chartBands->AddPlot(vtkChart::LINE);
    }

#if VTK_MAJOR_VERSION <= 5
    lineBandsBeta->SetInput(tableBeta, 0, col);
#else
    lineBandsBeta->SetInputData(tableBeta, 0, col);
#endif
    lineBandsBeta->SetColor( 255, 0, 0, 255 );
    lineBandsBeta->SetWidth(2.0);

//#ifndef WIN32
//  line->GetPen()->SetLineType(vtkPen::DASH_LINE);
//#endif

    //lineBandsBeta->SetValidPointMaskName("ValidMask");
    //vtkPlotLine::SafeDownCast(line)->SetMarkerStyle(vtkPlotLine::CIRCLE);
    lineBandsBeta->Update();
    qDebug()<<"Finish Beta col = "<<col;

    }
    qDebug()<<"Finish Beta Total ";
  }

  qDebug()<<"PlotBandsDialog::on_plotBandsButton_clicked() 4 Fermi";
  //chartBands->GetAxis(0)->GetMaximum();
  tableFermi->SetNumberOfRows(2);

  double fermimin = 0.0;
  double fermimax = 0.0;

  fermimin = 1.5* (*std::min_element(x.begin(), x.end()));
  fermimax = 1.5* (*std::max_element(x.begin(), x.end()));

  tableFermi->SetValue(0, 0, fermimin);
  tableFermi->SetValue(1, 0, fermimax);

  qDebug()<<"datamodel->data(datamodel->index(0,0)).toDouble() = "<<datamodel->data(datamodel->index(0,0)).toDouble();
  double fermiLevelBands = datamodel->data(datamodel->index(0,0)).toDouble();
  qDebug()<<"fermiLevelBands"<<fermiLevelBands;
  tableFermi->SetValue(0, 1, fermiLevelBands);
  tableFermi->SetValue(1, 1, fermiLevelBands);
  //tableFermi->SetValue(0, 0, -0.0000001);
  //tableFermi->SetValue(1, 0, 0.0000001);
  qDebug()<<"PlotBandsBandsDialog::on_plotBandsButton_clicked() 4 Fermi a";
  //tableFermi->SetValue(0, 1, chartBands->GetAxis(0)->GetMinimum());
  //tableFermi->SetValue(1, 1, chartBands->GetAxis(0)->GetMaximum());
  //tableFermi->SetValue(0, 1, -10.0);
  //tableFermi->SetValue(1, 1, 10.0);
  //tableFermi->SetValue(0, 1, BetaBands->GetDataTypeMin());
  //tableFermi->SetValue(1, 1, AlphaBands->GetDataTypeMax());



  qDebug()<<"tableFermi->GetValue(0,0) = "<<tableFermi->GetValue(0,0).ToDouble();
  qDebug()<<"tableFermi->GetValue(0,1) = "<<tableFermi->GetValue(0,1).ToDouble();
  qDebug()<<"tableFermi->GetValue(1,0) = "<<tableFermi->GetValue(1,0).ToDouble();
  qDebug()<<"tableFermi->GetValue(1,1) = "<<tableFermi->GetValue(1,1).ToDouble();
  qDebug()<<"PlotBandsDialog::on_plotBandsButton_clicked() 4 Fermi b";
  vtkSmartPointer<vtkPlotLine> lineBandsFermi =
      vtkSmartPointer<vtkPlotLine>::New();
  //chartBands->RemovePlot(0);
  qDebug()<<"PlotBandsDialog::on_plotBandsButton_clicked() 4 Fermi c";
  lineBandsFermi = vtkPlotLine::SafeDownCast(chartBands->AddPlot(vtkChart::LINE));
  //line->SetInputData(table.GetPointer());
  //line->SetInputArray(1, "FermiBandsUp");
  qDebug()<<"PlotBandsDialog::on_plotBandsButton_clicked() 4 Fermi d";
#if VTK_MAJOR_VERSION <= 5
  lineBandsFermi->SetInput(tableFermi, 0, 1);
#else
  lineBandsFermi->SetInputData(tableFermi, 0, 1);
#endif
  qDebug()<<"PlotBandsDialog::on_plotBandsButton_clicked() 4 Fermi e";
  lineBandsFermi->SetColor( 0, 255, 0, 255 );
  lineBandsFermi->SetWidth(2.0);
  //vtkPlotLine::SafeDownCast(line)->SetMarkerStyle(vtkPlotLine::CROSS);

  //lineBandsFermi->SetValidPointMaskName("ValidMask");

  lineBandsFermi->Update();
  qDebug()<<"Finish Fermi";

  //chartBands->GetPlot(0)->GetXAxis()->SetTitle((QString("k (%1 ⁻¹)").arg(QChar(0xE2))).toStdString()); // TO WRITE ANGSTROM, BUT DOES NOT WORK.
  //chartBands->GetPlot(0)->GetXAxis()->SetTitle((QString("k (pm⁻¹)")).toStdString());
  chartBands->GetPlot(0)->GetXAxis()->SetTitle("");
  chartBands->GetPlot(0)->GetYAxis()->SetTitle("E(k) (eV)");

  vtkSmartPointer<vtkTextProperty> XaxisLabelProp =
      vtkSmartPointer<vtkTextProperty>::New();
  XaxisLabelProp = chartBands->GetPlot(0)->GetXAxis()->GetTitleProperties();
  XaxisLabelProp->SetFontSize(20);
  vtkSmartPointer<vtkTextProperty> YaxisLabelProp =
      vtkSmartPointer<vtkTextProperty>::New();
  YaxisLabelProp = chartBands->GetPlot(0)->GetYAxis()->GetTitleProperties();
  YaxisLabelProp->SetFontSize(20);


  qDebug()<<"PlotBandsDialog::on_plotBandsButton_clicked() 5";
  //viewBands->Update();
  //lineBandsAlpha->Update();
  //
  //view->Update();
  //view->GetInteractor()->Render();
  //view->Render();
  //std::cout << "Clicked." << std::endl;
  qDebug()<<"PlotBandsDialog::on_plotBandsButton_clicked() 6.";
  //chartBands->GetNumberOfAxes()

  qDebug()<<"PlotBandsDialog::on_plotBandsButton_clicked() 6a.";
  chartBands->Update();
  qDebug()<<"PlotBandsDialog::on_plotBandsButton_clicked() 6b.";
  //viewBands->GetScene()->AddItem(chartBands.GetPointer());
  qDebug()<<"PlotBandsDialog::on_plotBandsButton_clicked() 6c.";
  //viewBands->Update();
  qDebug()<<"PlotBandsDialog::on_plotBandsButton_clicked() 6d.";
  ui.qvtkWidgetBands->update();
  qDebug()<<"PlotBandsDialog::on_plotBandsButton_clicked() 6e.";

  //originalBandsXsize = (double)(chartBands->GetAxis(1)->GetMaximum() - chartBands->GetAxis(1)->GetMinimum());
  //originalBandsYsize = (double)(chartBands->GetAxis(0)->GetMaximum() - chartBands->GetAxis(0)->GetMinimum());
  originalBandsXsize = (double)(chartBands->GetAxis(0)->GetMaximum() - chartBands->GetAxis(0)->GetMinimum());
  originalBandsYsize = (double)(chartBands->GetAxis(1)->GetMaximum() - chartBands->GetAxis(1)->GetMinimum());

  /*
  connect(ui.horizontalSliderqvtkWidget3, SIGNAL(valueChanged(int)), this, SLOT(setBandsXRange(int)));
  connect(ui.verticalSliderqvtkWidget3, SIGNAL(valueChanged(int)), this, SLOT(setBandsYRange(int)));
  */ // COMMENTED BY C.SALGADO ON 2016-08-03 TO AVOID VTK CRASH WHEN RESTARTING INTERACTOR.

  qDebug()<<"PlotBandsDialog::on_plotBandsButton_clicked() 7";

}


void PlotBandsDialog::on_plotBandsButton_clicked(){

    qDebug()<<"PlotBandsDialog::on_plotBandsButton_clicked() 0";

    qDebug()<<"PlotBandsDialog::on_plotBandsButton_clicked() 0a";
    chartBands->ClearPlots();
    qDebug()<<"PlotBandsDialog::on_plotBandsButton_clicked() 0b";

    qDebug()<<"PlotBandsDialog::on_plotBandsButton_clicked() 0c";
    for (int i = 0; i < chartBands->GetNumberOfAxes(); ++i){
      chartBands->GetAxis(i)->ClearItems();
    }
    qDebug()<<"PlotBandsDialog::on_plotBandsButton_clicked() 0d";
    for (int i = 0; i < chartBands->GetNumberOfPlots(); ++i){
      chartBands->RemovePlot(i);
    }
    qDebug()<<"PlotBandsDialog::on_plotBandsButton_clicked() 0e";


// Bands PLOT.
qDebug()<<"PlotBandsDialog::on_plotBandsButton_clicked() 1";
QList<QList<double>> dataBandsAlpha = fullBandsAlpha;
QList<QList<double>> dataBandsBeta = fullBandsBeta;
QList<double> enerdataBands = enerfullBands;



//if(bandsnumspin==2){
//  for (int col=0; col<dataBandsBeta.size(); ++col){
//    for (int row=0; row<dataBandsBeta[col].size(); ++row){
//      qDebug()<<"dataBandsAlpha["<<col<<"]["<<row<<"] = "<<dataBandsAlpha[col][row];
//      qDebug()<<"dataBandsBeta["<<col<<"]["<<row<<"] = "<<dataBandsBeta[col][row];
//    }
//  }
//}else{
//  for (int col=0; col<dataBandsAlpha.size(); ++col){
//    for (int row=0; row<dataBandsAlpha[col].size(); ++row){
//      qDebug()<<"dataBandsAlpha["<<col<<"]["<<row<<"] = "<<dataBandsAlpha[col][row];
//    }
//  }
//}

qint32 numcolDataBandsAlpha = dataBandsAlpha.size();
QVector<float> x(enerdataBands.size());
QVector<QVector<float>> y0(dataBandsAlpha.size());
QVector<QVector<float>> y1(dataBandsBeta.size());

y0[0].resize(dataBandsAlpha[1].size());
for (int col=1; col<dataBandsAlpha.size(); ++col){
//for (int col=0; col<2; ++col){
  y0[col].resize(dataBandsAlpha[col].size());
}
if(bandsnumspin==2){
  y1[0].resize(dataBandsBeta[1].size());
  for (int col=1; col<dataBandsBeta.size(); ++col){
    y1[col].resize(dataBandsBeta[col].size());
  }
}

qDebug()<<"PlotBandsDialog::on_plotBandsButton_clicked() 2. dataBandsAlpha.size() = "<<dataBandsAlpha.size();

for (int i=0; i<enerdataBands.size(); ++i)        {
  x[i] = (float)enerdataBands[i];
//  qDebug()<<"enerdataBands["<<i<<"]"<<enerdataBands[i];
  //xvtkfloat->SetValue(i,(float)enerdataBands[i]);
}

qDebug()<<"dataBandsAlpha.size() = "<<dataBandsAlpha.size();
qDebug()<<"dataBandsAlpha[0].size() = "<<dataBandsAlpha[0].size();
for (int col=1; col<dataBandsAlpha.size(); ++col){
//  qDebug()<<"dataBandsAlpha["<<col<<"].size() = "<<dataBandsAlpha[col].size();
  for (int row=0; row<dataBandsAlpha[col].size(); ++row){
    y0[col][row] = (float)dataBandsAlpha[col][row];
    //y0[1][row] = (float)dataBandsBeta[currentColumn][row];
//    qDebug()<<"y0[0:"<<col<<"]["<<row<<"] = ["<< y0[0][row]<<","<<y0[col][row]<<"]";
    if(bandsnumspin==2){
      y1[col][row] = (float)dataBandsBeta[col][row];
//      qDebug()<<"y1[0:"<<col<<"]["<<row<<"] = ["<< y1[0][row]<<","<<y1[col][row]<<"]";
    }
  }
}

  //-----------------------------------------------------------------
  //-----------------------------------------------------------------

  qDebug()<<"PlotBandsDialog::PlotBandsBandsDialog() 3";

  vtkSmartPointer<vtkTable> tableAlpha =
        vtkSmartPointer<vtkTable>::New();
  vtkSmartPointer<vtkTable> tableBeta =
        vtkSmartPointer<vtkTable>::New();

  vtkSmartPointer<vtkTable> tableFermi =
      vtkSmartPointer<vtkTable>::New();

  vtkSmartPointer<vtkTable> tableBrillouin =
      vtkSmartPointer<vtkTable>::New();

  vtkSmartPointer<vtkTable> tableMask =
      vtkSmartPointer<vtkTable>::New();

  vtkNew<vtkFloatArray> arrFermiX;
  arrFermiX->SetName("X Fermi");
  tableFermi->AddColumn(arrFermiX.GetPointer());

  vtkNew<vtkFloatArray> arrFermiY;
  arrFermiY->SetName("Y Fermi");
  tableFermi->AddColumn(arrFermiY.GetPointer());

  vtkNew<vtkFloatArray> arrBrillouinX;
  arrBrillouinX->SetName("X Brillouin");
  tableBrillouin->AddColumn(arrBrillouinX.GetPointer());

  //vtkNew<vtkFloatArray> arrBrillouinY;
  //arrBrillouinY->SetName("Y Brillouin");
  //tableBrillouin->AddColumn(arrBrillouinY.GetPointer());

  vtkNew<vtkFloatArray> arrBandsAlphaX;
  arrBandsAlphaX->SetName("X Axis");
  tableAlpha->AddColumn(arrBandsAlphaX.GetPointer());
  //tableBeta->AddColumn(arrBandsX.GetPointer());

  vtkNew<vtkFloatArray> arrBandsBetaX;
  arrBandsBetaX->SetName("X Axis");
  //tableAlpha->AddColumn(arrBandsX.GetPointer());
  tableBeta->AddColumn(arrBandsBetaX.GetPointer());

  vtkNew<vtkFloatArray> alphaBands;
  //vtkNew<vtkDataArray> alphaBands;
  alphaBands->SetName("AlphaBands");
  alphaBands->SetNumberOfTuples(dataBandsAlpha.size());
  //tableAlpha->AddColumn(alphaBands.GetPointer());

  vtkNew<vtkFloatArray> betaBands;
  betaBands->SetName("BetaBands");
  //tableBeta->AddColumn(betaBands.GetPointer());

  for (int col=0; col<dataBandsAlpha.size(); ++col){
    vtkNew<vtkFloatArray> pivotBands;
    tableAlpha->AddColumn(pivotBands.GetPointer());
    tableAlpha->GetColumn(col)->SetName((QString("AlphaBands%1").arg(col)).toLatin1());
  }

  for (int col=0; col<dataBandsBeta.size(); ++col){
    vtkNew<vtkFloatArray> pivotBands;
    tableBeta->AddColumn(pivotBands.GetPointer());
    tableBeta->GetColumn(col)->SetName((QString("BetaBands%1").arg(col)).toLatin1());
  }

  vtkNew<vtkCharArray> validMask;
  validMask->SetName("ValidMask");
  //table->AddColumn(validMask.GetPointer());
  //tableAlpha->AddColumn(validMask.GetPointer());
  //tableBeta->AddColumn(validMask.GetPointer());
  tableMask->AddColumn(validMask.GetPointer());


  qDebug()<<"PlotBandsDialog::PlotBandsBandsDialog() 4";

  tableAlpha->SetNumberOfRows(enerdataBands.size());
  tableBeta->SetNumberOfRows(enerdataBands.size());
  tableMask->SetNumberOfRows(enerdataBands.size());

  qDebug()<<"PlotBandsDialog::PlotBandsBandsDialog() 4a";
  // col=0
  qDebug()<<"dataBandsAlpha[1].size() = "<<dataBandsAlpha[1].size();
  qDebug()<<"enerdataBands.size() = "<<enerdataBands.size();
  if(bandsnumspin==2){
    for (int row = 0; row < enerdataBands.size(); ++row){
//      qDebug()<<"x["<<row<<"] = "<<x[row];
      tableAlpha->SetValue(row, 0, (float)(x[row]));
      tableBeta->SetValue(row, 0, (float)(x[row]));
      validMask->SetValue(row,1);
    }
  }else{
    for (int row = 0; row < enerdataBands.size(); ++row){
//      qDebug()<<"x["<<row<<"] = "<<x[row];
      tableAlpha->SetValue(row, 0, (float)(x[row]));
      validMask->SetValue(row,1);
    }
  }


  // MAXIMUM AND MINIMUM Y FOR BRILLOUIN.
  double Brillouinmin = 0.0;
  double Brillouinmax = 0.0;
  double newBrillouinmin = 0.0;
  double newBrillouinmax = 0.0;
  qDebug()<<"PlotBandsDialog::PlotBandsBandsDialog() 4b";
  for (int col=1; col<dataBandsAlpha.size(); ++col){
    for (int row = 0; row < dataBandsAlpha[col].size(); ++row){
//      qDebug()<<"y0["<<col<<"]["<<row<<"]"<<y0[col][row];
      tableAlpha->SetValue(row, col, (float)(y0[col][row]));
    }
    newBrillouinmin = (*std::min_element(y0[col].begin(), y0[col].end()));
    if(newBrillouinmin<Brillouinmin){
      Brillouinmin = newBrillouinmin;
    }
    newBrillouinmax = (*std::max_element(y0[col].begin(), y0[col].end()));
    if(newBrillouinmax>Brillouinmax){
      Brillouinmax = newBrillouinmax;
    }
    qDebug()<<"(newBrillouinmin, newBrillouinmax) = ("<<newBrillouinmin<<","<<newBrillouinmax<<")";
  }
  if(bandsnumspin==2){
    for (int col=1; col<dataBandsBeta.size(); ++col){
      for (int row = 0; row < dataBandsBeta[col].size(); ++row){
//      qDebug()<<"y1["<<col<<"]["<<row<<"]"<<y1[col][row];
        tableBeta->SetValue(row, col, (float)(y1[col][row]));
      }
      newBrillouinmin = (*std::min_element(y1[col].begin(), y1[col].end()));
      if(newBrillouinmin<Brillouinmin){
        Brillouinmin = newBrillouinmin;
      }
      newBrillouinmax = (*std::max_element(y1[col].begin(), y1[col].end()));
      if(newBrillouinmax>Brillouinmax){
        Brillouinmax = newBrillouinmax;
      }
      qDebug()<<"(newBrillouinmin, newBrillouinmax) = ("<<newBrillouinmin<<","<<newBrillouinmax<<")";
    }
  }
  qDebug()<<"(Brillouinmin, Brillouinmax) = ("<<Brillouinmin<<","<<Brillouinmax<<")";


  qDebug()<<"PlotBandsDialog::PlotBandsBandsDialog() 4c";


  // Add multiple line plots, setting the colors etc
  //lineBands = vtkPlotLine::SafeDownCast(chartBands->AddPlot(vtkChart::LINE));
  //vtkPlot *line = chartBands->AddPlot(vtkChart::LINE);
  //vtkSmartPointer<vtkPlotLine> lineBandsAlpha =
  //    vtkSmartPointer<vtkPlotLine>::New();
  //chartBands->RemovePlot(0);
  //lineBandsAlpha = vtkPlotLine::SafeDownCast(chartBands->AddPlot(vtkChart::LINE));
  vtkPlot *lineBandsAlpha = chartBands->AddPlot(vtkChart::LINE);

  qDebug()<<"PlotBandsDialog::PlotBandsBandsDialog() 4d";

  for (int col=1; col<dataBandsAlpha.size(); ++col){
  if(col>2){
    lineBandsAlpha = chartBands->AddPlot(vtkChart::LINE);
  }
  qDebug()<<"PlotBandsDialog::PlotBandsBandsDialog() 4e";
#if VTK_MAJOR_VERSION <= 5
  lineBandsAlpha->SetInput(tableAlpha, 0, col);
#else
  lineBandsAlpha->SetInputData(tableAlpha, 0, col);
#endif
  qDebug()<<"PlotBandsDialog::PlotBandsBandsDialog() 4f";
  lineBandsAlpha->SetColor( 0, 0, 255, 255 );
  lineBandsAlpha->SetWidth(2.0);
  //vtkPlotLine::SafeDownCast(line)->SetMarkerStyle(vtkPlotLine::CROSS);

  qDebug()<<"PlotBandsDialog::PlotBandsBandsDialog() 4g";
  //lineBandsAlpha->SetValidPointMaskName("ValidMask");

  lineBandsAlpha->Update();
  qDebug()<<"Finish Alpha col = "<<col;
  }
  qDebug()<<"Finish Alpha Total ";

  //vtkSmartPointer<vtkPlotLine> lineBandsBeta =
  //    vtkSmartPointer<vtkPlotLine>::New();
  //lineBandsBeta = vtkPlotLine::SafeDownCast(chartBands->AddPlot(vtkChart::LINE));
  vtkPlot *lineBandsBeta = chartBands->AddPlot(vtkChart::LINE);
  if(bandsnumspin==2){
  for (int col=1; col<dataBandsBeta.size(); ++col){
    if(col>2){
      lineBandsBeta = chartBands->AddPlot(vtkChart::LINE);
    }

#if VTK_MAJOR_VERSION <= 5
    lineBandsBeta->SetInput(tableBeta, 0, col);
#else
    lineBandsBeta->SetInputData(tableBeta, 0, col);
#endif
    lineBandsBeta->SetColor( 255, 0, 0, 255 );
    lineBandsBeta->SetWidth(2.0);

//#ifndef WIN32
//  line->GetPen()->SetLineType(vtkPen::DASH_LINE);
//#endif

    //lineBandsBeta->SetValidPointMaskName("ValidMask");
    //vtkPlotLine::SafeDownCast(line)->SetMarkerStyle(vtkPlotLine::CIRCLE);
    lineBandsBeta->Update();
    qDebug()<<"Finish Beta col = "<<col;

    }
    qDebug()<<"Finish Beta Total ";
  }

  qDebug()<<"PlotBandsDialog::on_plotBandsButton_clicked() 4 Fermi";

  //-------------- FERMI -------------------------------------------------------------------------------------

  tableFermi->SetNumberOfRows(2);

  double fermimin = 0.0;
  double fermimax = 0.0;

  //fermimin = 1.5* (*std::min_element(x.begin(), x.end()));
  //fermimax = 1.5* (*std::max_element(x.begin(), x.end()));
  fermimin = (*std::min_element(x.begin(), x.end()));
  fermimax = (*std::max_element(x.begin(), x.end()));

  tableFermi->SetValue(0, 0, fermimin);
  tableFermi->SetValue(1, 0, fermimax);

  qDebug()<<"datamodel->data(datamodel->index(0,0)).toDouble() = "<<datamodel->data(datamodel->index(0,0)).toDouble();
  double fermiLevelBands = datamodel->data(datamodel->index(0,0)).toDouble();
  qDebug()<<"fermiLevelBands"<<fermiLevelBands;
  tableFermi->SetValue(0, 1, fermiLevelBands);
  tableFermi->SetValue(1, 1, fermiLevelBands);

  qDebug()<<"PlotBandsBandsDialog::on_plotBandsButton_clicked() 4 Fermi a";


  qDebug()<<"tableFermi->GetValue(0,0) = "<<tableFermi->GetValue(0,0).ToDouble();
  qDebug()<<"tableFermi->GetValue(0,1) = "<<tableFermi->GetValue(0,1).ToDouble();
  qDebug()<<"tableFermi->GetValue(1,0) = "<<tableFermi->GetValue(1,0).ToDouble();
  qDebug()<<"tableFermi->GetValue(1,1) = "<<tableFermi->GetValue(1,1).ToDouble();
  qDebug()<<"PlotBandsDialog::on_plotBandsButton_clicked() 4 Fermi b";
  vtkSmartPointer<vtkPlotLine> lineBandsFermi =
      vtkSmartPointer<vtkPlotLine>::New();
  //chartBands->RemovePlot(0);
  qDebug()<<"PlotBandsDialog::on_plotBandsButton_clicked() 4 Fermi c";
  lineBandsFermi = vtkPlotLine::SafeDownCast(chartBands->AddPlot(vtkChart::LINE));

  qDebug()<<"PlotBandsDialog::on_plotBandsButton_clicked() 4 Fermi d";
#if VTK_MAJOR_VERSION <= 5
  lineBandsFermi->SetInput(tableFermi, 0, 1);
#else
  lineBandsFermi->SetInputData(tableFermi, 0, 1);
#endif
  qDebug()<<"PlotBandsDialog::on_plotBandsButton_clicked() 4 Fermi e";
  lineBandsFermi->SetColor( 0, 255, 0, 255 );
  lineBandsFermi->SetWidth(2.0);
  //vtkPlotLine::SafeDownCast(line)->SetMarkerStyle(vtkPlotLine::CROSS);

  //lineBandsFermi->SetValidPointMaskName("ValidMask");

  lineBandsFermi->Update();
  qDebug()<<"Finish Fermi";

  //------------ END FERMI -----------------------------------------------------------------------------------
  //------------ BRILLOUIN -----------------------------------------------------------------------------------

  qDebug()<<"PlotBandsDialog::on_plotBandsButton_clicked() 4 Brillouin";
  int nBrillouinPoints = modelBrillouin->rowCount();
  qDebug()<<"nBrillouinPoints = "<<nBrillouinPoints;

  QVector<double> BrillouinPoints(nBrillouinPoints);

  for (int row=1; row<nBrillouinPoints+1; ++row){
    vtkNew<vtkFloatArray> pivotBrillouin;
    tableBrillouin->AddColumn(pivotBrillouin.GetPointer());
    //tableBrillouin->GetColumn(row)->SetName((QString("Brillouin%1").arg(row)).toLatin1());
    //tableBrillouin->GetColumn(row)->SetName((modelBrillouin->data(modelBrillouin->index(row-1,0)).toString()).toLatin1());
    tableBrillouin->GetColumn(row)->SetName((QString("%1 %2").arg(modelBrillouin->data(modelBrillouin->index(row-1,0)).toString(),QString("%1").arg(row))).toLatin1());
  }

  //tableBrillouin->SetNumberOfRows(nBrillouinPoints);
  tableBrillouin->SetNumberOfRows(2);

  tableBrillouin->SetValue(0, 0, (float)(Brillouinmin));
  tableBrillouin->SetValue(1, 0, (float)(Brillouinmax));

  for (int row=0; row<nBrillouinPoints; ++row){
    qDebug()<<"modelBrillouin->data(modelBrillouin->index("<<row<<",1)).toDouble() = "<<modelBrillouin->data(modelBrillouin->index(row,1)).toDouble();
    BrillouinPoints[row] = modelBrillouin->data(modelBrillouin->index(row,1)).toDouble();
    qDebug()<<"BrillouinPoints["<<row<<"] = "<<BrillouinPoints[row];
    tableBrillouin->SetValue(0, row+1, (float)(BrillouinPoints[row]));
    tableBrillouin->SetValue(1, row+1, (float)(BrillouinPoints[row]));
  }

  for (int row=0; row<nBrillouinPoints; ++row){
    qDebug()<<"tableBrillouin->GetValue(:,"<<row<<") = ("<<tableBrillouin->GetValue(0,row).ToDouble()<<","<<tableBrillouin->GetValue(1,row).ToDouble()<<")";
  }

  //double Brillouinmin = 0.0;
  //double Brillouinmax = 0.0;

  //Brillouinmin = 1.5* (*std::min_element(x.begin(), x.end()));
  //Brillouinmax = 1.5* (*std::max_element(x.begin(), x.end()));
  //Brillouinmin = (*std::min_element(x.begin(), x.end())); // BEEN OBTAINED BEFORE.
  //Brillouinmax = (*std::max_element(x.begin(), x.end())); // BEEN OBTAINED BEFORE.

  qDebug()<<"modelBrillouin->data(modelBrillouin->index(0,1)).toDouble() = "<<modelBrillouin->data(modelBrillouin->index(0,1)).toDouble();
  qDebug()<<"modelBrillouin->data(modelBrillouin->index(1,0)).toDouble() = "<<modelBrillouin->data(modelBrillouin->index(1,0)).toDouble();
  //double BrillouinPoint = datamodel->data(datamodel->index(0,0)).toDouble();
  //double BrillouinPoint = modelBrillouin->data(modelBrillouin->index(0,0)).toDouble();
  //qDebug()<<"BrillouinPoint"<<BrillouinPoint;
  /*
  tableBrillouin->SetValue(0, 0, BrillouinPoint);
  tableBrillouin->SetValue(1, 0, BrillouinPoint);

  qDebug()<<"(Brillouinmin, Brillouinmax) = ("<<Brillouinmin<<","<<Brillouinmax<<")";
  tableBrillouin->SetValue(0, 1, Brillouinmin);
  tableBrillouin->SetValue(1, 1, Brillouinmax);
  */

  qDebug()<<"PlotBandsBandsDialog::on_plotBandsButton_clicked() 4 Brillouin a";


  qDebug()<<"tableBrillouin->GetValue(0,0) = "<<tableBrillouin->GetValue(0,0).ToDouble();
  qDebug()<<"tableBrillouin->GetValue(0,1) = "<<tableBrillouin->GetValue(0,1).ToDouble();
  qDebug()<<"tableBrillouin->GetValue(1,0) = "<<tableBrillouin->GetValue(1,0).ToDouble();
  qDebug()<<"tableBrillouin->GetValue(1,1) = "<<tableBrillouin->GetValue(1,1).ToDouble();
  qDebug()<<"PlotBandsDialog::on_plotBandsButton_clicked() 4 Brillouin b";
  //vtkSmartPointer<vtkPlotLine> lineBrillouinPoint =
  //    vtkSmartPointer<vtkPlotLine>::New();
  vtkPlot *lineBrillouinPoint = chartBands->AddPlot(vtkChart::LINE);
  //chartBands->RemovePlot(0);
  qDebug()<<"PlotBandsDialog::on_plotBandsButton_clicked() 4 Brillouin c";
  //lineBrillouinPoint = vtkPlotLine::SafeDownCast(chartBands->AddPlot(vtkChart::LINE));
  lineBrillouinPoint = vtkPlotLine::SafeDownCast(chartBands->AddPlot(vtkChart::LINE));
  //lineBrillouinPoint = vtkPlotLine::SafeDownCast(chartBands-

  for (int row=0; row<nBrillouinPoints; ++row){

  if(row>0){
    lineBrillouinPoint = chartBands->AddPlot(vtkChart::LINE);
  }

  qDebug()<<"PlotBandsDialog::on_plotBandsButton_clicked() 4 Brillouin d";
#if VTK_MAJOR_VERSION <= 5
  lineBrillouinPoint->SetInput(tableBrillouin, row+1, 0);
#else
  lineBrillouinPoint->SetInputData(tableBrillouin, row+1, 0);
#endif
  qDebug()<<"PlotBandsDialog::on_plotBandsButton_clicked() 4 Brillouin e";
  lineBrillouinPoint->SetColor( 0, 0, 0, 255 );
  lineBrillouinPoint->SetWidth(2.0);
  //lineBrillouinPoint->SetLabel((modelBrillouin->data(modelBrillouin->index(row,0))).toStdString());
  lineBrillouinPoint->SetLabel((QString("%1 %2").arg(modelBrillouin->data(modelBrillouin->index(row,0)).toString(),QString("%1").arg(row))).toStdString());
  //lineBrillouinPoint->GetXAxis()->C
  //lineBrillouinPoint->SetLegendVisibility(true);
  //lineBrillouinPoint->SetLabels((modelBrillouin->data(modelBrillouin->index(row,0)).toString()).toStdString());
  //vtkPlotLine::SafeDownCast(line)->SetMarkerStyle(vtkPlotLine::CROSS);

  //lineBrillouinPoint->SetValidPointMaskName("ValidMask");

  lineBrillouinPoint->Update();
  qDebug()<<"Finish Brillouin row ="<<row;
  }
  qDebug()<<"Finish Brillouin";
  //---------- END BRILLOUIN ---------------------------------------------------------------------------------

  chartBands->GetPlot(0)->GetXAxis()->SetTitle("k (Å⁻¹)");
  chartBands->GetPlot(0)->GetYAxis()->SetTitle("E(k) (eV)");

  qDebug()<<"PlotBandsDialog::on_plotBandsButton_clicked() 5";
  //vtkNew<vtkDoubleArray> positionsBrillouin;
  //vtkNew<vtkStringArray> labelsBrillouin;
  //vtkDoubleArray *positionsBrillouin;
  //vtkStringArray *labelsBrillouin;
  vtkSmartPointer<vtkDoubleArray> positionsBrillouin =
      vtkSmartPointer<vtkDoubleArray>::New();
  positionsBrillouin->SetName("Brillouin Points");
  vtkSmartPointer<vtkStringArray> labelsBrillouin =
      vtkSmartPointer<vtkStringArray>::New();
  positionsBrillouin->SetName("Brillouin Labels");

  vtkSmartPointer<vtkTable> positionsBrillouinTable =
      vtkSmartPointer<vtkTable>::New();

  positionsBrillouinTable->AddColumn(positionsBrillouin);
  vtkSmartPointer<vtkTable> labelsBrillouinTable =
      vtkSmartPointer<vtkTable>::New();
  labelsBrillouinTable->AddColumn(labelsBrillouin);

  qDebug()<<"PlotBandsDialog::on_plotBandsButton_clicked() 5 a";
  //positionsBrillouin->SetNumberOfComponents(nBrillouinPoints);
  //labelsBrillouin->SetNumberOfComponents(nBrillouinPoints);
  positionsBrillouinTable->SetNumberOfRows(nBrillouinPoints);
  labelsBrillouinTable->SetNumberOfRows(nBrillouinPoints);
  qDebug()<<"PlotBandsDialog::on_plotBandsButton_clicked() 5 b";
  for (int row=0; row<nBrillouinPoints; ++row){
    positionsBrillouin->SetValue(row, modelBrillouin->data(modelBrillouin->index(row,1)).toDouble());
    //positionsBrillouin->SetValue(row, (modelBrillouin->data(modelBrillouin->index(row,0))).toDouble());
    labelsBrillouin->SetValue(row, modelBrillouin->data(modelBrillouin->index(row,0)).toString().toLatin1());
  }
  qDebug()<<"PlotBandsDialog::on_plotBandsButton_clicked() 5 c";
  for (int row=0; row<nBrillouinPoints; ++row){
    qDebug()<<"positionsBrillouin->GetValue("<<row<<") = "<<positionsBrillouin->GetValue(row);
    //positionsBrillouin->SetValue(row, (modelBrillouin->data(modelBrillouin->index(row,0))).toDouble());
    qDebug()<<"labelsBrillouin->GetValue("<<row<<")"<<labelsBrillouin->GetValue(row);
  }
  qDebug()<<"PlotBandsDialog::on_plotBandsButton_clicked() 5 d";

  chartBands->GetPlot(0)->GetXAxis()->SetCustomTickPositions(positionsBrillouin, labelsBrillouin);

  vtkSmartPointer<vtkTextProperty> XaxisLabelProp =
      vtkSmartPointer<vtkTextProperty>::New();
  XaxisLabelProp = chartBands->GetPlot(0)->GetXAxis()->GetTitleProperties();
  XaxisLabelProp->SetFontSize(20);
  vtkSmartPointer<vtkTextProperty> YaxisLabelProp =
      vtkSmartPointer<vtkTextProperty>::New();
  YaxisLabelProp = chartBands->GetPlot(0)->GetYAxis()->GetTitleProperties();
  YaxisLabelProp->SetFontSize(20);




  qDebug()<<"PlotBandsDialog::on_plotBandsButton_clicked() 6.";
  //chartBands->GetNumberOfAxes()

  chartBands->GetPlot(0)->Update();
  qDebug()<<"PlotBandsDialog::on_plotBandsButton_clicked() 6a.";
  chartBands->Update();
  qDebug()<<"PlotBandsDialog::on_plotBandsButton_clicked() 6b.";
  //viewBands->GetScene()->AddItem(chartBands.GetPointer());
  qDebug()<<"PlotBandsDialog::on_plotBandsButton_clicked() 6c.";
  //viewBands->Update();
  qDebug()<<"PlotBandsDialog::on_plotBandsButton_clicked() 6d.";
  ui.qvtkWidgetBands->update();
  qDebug()<<"PlotBandsDialog::on_plotBandsButton_clicked() 6e.";

  originalBandsXsize = (double)(chartBands->GetAxis(0)->GetMaximum() - chartBands->GetAxis(0)->GetMinimum());
  originalBandsYsize = (double)(chartBands->GetAxis(1)->GetMaximum() - chartBands->GetAxis(1)->GetMinimum());

  qDebug()<<"PlotBandsDialog::on_plotBandsButton_clicked() 7";

}


void PlotBandsDialog::on_exportRenderBandsButton_clicked()
{
  //pngWriter("screenshot2.png");
  pngWriter("screenshot2.png", 4);
}

//int main(int argc, char *argv[])
//void PlotBandsDialog::pngWriter(vtkRenderer renderer){
//void PlotBandsDialog::pngWriter(QWidget exportWidget, QString fileName)
void PlotBandsDialog::pngWriter(QString fileName, int widgetSelector)
{
  //-----------------------------------------------------------------
  //----------- EXPORT IMAGE ----------------------------------------
  //-----------------------------------------------------------------
  /*
  // Visualize
  vtkSmartPointer<vtkPolyDataMapper> mapper =
    vtkSmartPointer<vtkPolyDataMapper>::New();
  //mapper->SetInputConnection(sphereSource->GetOutputPort());

  vtkSmartPointer<vtkActor> actor =
    vtkSmartPointer<vtkActor>::New();
  actor->SetMapper(mapper);

  vtkSmartPointer<vtkRenderer> renderer =
    vtkSmartPointer<vtkRenderer>::New();
  vtkSmartPointer<vtkRenderWindow> renderWindow =
    vtkSmartPointer<vtkRenderWindow>::New();
  //renderWindow->AddRenderer(renderer);
  //renderWindow->SetAlphaBitPlanes(1); //enable usage of alpha channel
  ui.qvtkWidget3->GetRenderWindow()->SetAlphaBitPlanes(1);

  vtkSmartPointer<vtkRenderWindowInteractor> renderWindowInteractor =
    vtkSmartPointer<vtkRenderWindowInteractor>::New();
  //renderWindowInteractor->SetRenderWindow(renderWindow);
  renderWindowInteractor->SetRenderWindow(ui.qvtkWidget3->GetRenderWindow());

  //renderer->AddActor(actor);
  renderer->SetBackground(1,1,1); // Background color white
  */

  //renderWindow->Render();

  // Screenshot
    vtkSmartPointer<vtkWindowToImageFilter> windowToImageFilter =
      vtkSmartPointer<vtkWindowToImageFilter>::New();
    //windowToImageFilter->SetInput(renderWindow);
    if(widgetSelector == 1){
//      windowToImageFilter->SetInput(ui.qvtkWidget3->GetRenderWindow());
    }else if(widgetSelector == 2){
      //windowToImageFilter->SetInput(ui.qvtkWidgetDos->GetRenderWindow());
    }else if(widgetSelector == 3){
      //windowToImageFilter->SetInput(ui.qvtkWidgetPDos->GetRenderWindow());
    }else if(widgetSelector == 4){
      windowToImageFilter->SetInput(ui.qvtkWidgetBands->GetRenderWindow());
    }
    // IF SetMagnification(3); THE EXPORTED IMAGE SHOWS A WARHOLIAN
    //windowToImageFilter->SetMagnification(3); //set the resolution of the output image (3 times the current resolution of vtk render window)
    windowToImageFilter->SetInputBufferTypeToRGBA(); //also record the alpha (transparency) channel
    windowToImageFilter->ReadFrontBufferOff(); // read from the back buffer
    windowToImageFilter->Update();


    vtkSmartPointer<vtkPNGWriter> writer =
      vtkSmartPointer<vtkPNGWriter>::New();
    //writer->SetFileName("screenshot2.png");
    //writer->SetFileName(fileName);
    QByteArray ba = fileName.toLatin1();
    const char *c_str2 = ba.data();
    writer->SetFileName(c_str2);
    qDebug()<<"PlotBandsDialog::pngWriter() 5 *c_str2 = ba.data() ="<<c_str2;
    writer->SetInputConnection(windowToImageFilter->GetOutputPort());
    writer->Write();
    qDebug()<<"PlotBandsDialog::pngWriter() 5a FINISH EXPORT WRITE";

  //-----------------------------------------------------------------
  //-----------------------------------------------------------------

  //return EXIT_SUCCESS;
}

void PlotBandsDialog::jpegWriter(QString fileName, int widgetSelector)
{
  //-----------------------------------------------------------------
  //----------- EXPORT IMAGE ----------------------------------------
  //-----------------------------------------------------------------
  /*
  // Visualize
  vtkSmartPointer<vtkPolyDataMapper> mapper =
    vtkSmartPointer<vtkPolyDataMapper>::New();
  //mapper->SetInputConnection(sphereSource->GetOutputPort());

  vtkSmartPointer<vtkActor> actor =
    vtkSmartPointer<vtkActor>::New();
  actor->SetMapper(mapper);

  vtkSmartPointer<vtkRenderer> renderer =
    vtkSmartPointer<vtkRenderer>::New();
  vtkSmartPointer<vtkRenderWindow> renderWindow =
    vtkSmartPointer<vtkRenderWindow>::New();
  //renderWindow->AddRenderer(renderer);
  //renderWindow->SetAlphaBitPlanes(1); //enable usage of alpha channel
  ui.qvtkWidget3->GetRenderWindow()->SetAlphaBitPlanes(1);

  vtkSmartPointer<vtkRenderWindowInteractor> renderWindowInteractor =
    vtkSmartPointer<vtkRenderWindowInteractor>::New();
  //renderWindowInteractor->SetRenderWindow(renderWindow);
  renderWindowInteractor->SetRenderWindow(ui.qvtkWidget3->GetRenderWindow());

  //renderer->AddActor(actor);
  renderer->SetBackground(1,1,1); // Background color white
  */

  //renderWindow->Render();

  // Screenshot
    vtkSmartPointer<vtkWindowToImageFilter> windowToImageFilter =
      vtkSmartPointer<vtkWindowToImageFilter>::New();
    //windowToImageFilter->SetInput(renderWindow);
    if(widgetSelector == 1){
//      windowToImageFilter->SetInput(ui.qvtkWidget3->GetRenderWindow());
    }else if(widgetSelector == 2){
      //windowToImageFilter->SetInput(ui.qvtkWidgetDos->GetRenderWindow());
    }else if(widgetSelector == 3){
      //windowToImageFilter->SetInput(ui.qvtkWidgetPDos->GetRenderWindow());
    }else if(widgetSelector == 4){
        windowToImageFilter->SetInput(ui.qvtkWidgetBands->GetRenderWindow());
    }
    // IF SetMagnification(3); THE EXPORTED IMAGE SHOWS A WARHOLIAN
    //windowToImageFilter->SetMagnification(3); //set the resolution of the output image (3 times the current resolution of vtk render window)
    windowToImageFilter->SetInputBufferTypeToRGBA(); //also record the alpha (transparency) channel
    windowToImageFilter->ReadFrontBufferOff(); // read from the back buffer
    windowToImageFilter->Update();


    vtkSmartPointer<vtkJPEGWriter> writer =
      vtkSmartPointer<vtkJPEGWriter>::New();
    //writer->SetFileName("screenshot2.png");
    //writer->SetFileName(fileName);
    QByteArray ba = fileName.toLatin1();
    const char *c_str2 = ba.data();
    writer->SetFileName(c_str2);
    qDebug()<<"PlotBandsDialog::pngWriter() 5 *c_str2 = ba.data() ="<<c_str2;
    writer->SetInputConnection(windowToImageFilter->GetOutputPort());
    writer->Write();
    qDebug()<<"PlotBandsDialog::pngWriter() 5a FINISH EXPORT WRITE";

  //-----------------------------------------------------------------
  //-----------------------------------------------------------------

  //return EXIT_SUCCESS;
}

} // end namespace QtPlugins
} // end namespace Avogadro
