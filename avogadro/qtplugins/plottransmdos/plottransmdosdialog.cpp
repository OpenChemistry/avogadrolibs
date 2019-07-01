/*
 * Copyright 2007 Sandia Corporation.
 * Under the terms of Contract DE-AC04-94AL85000, there is a non-exclusive
 * license for use of this work by or on behalf of the
 * U.S. Government. Redistribution and use in source and binary forms, with
 * or without modification, are permitted provided that this Notice and any
 * statement of authorship are reproduced on all copies.
 */


#include "ui_plottransmdosdialog.h"
#include "plottransmdosdialog.h"

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
#include <vtkImageCast.h>
#include <vtkRenderWindowInteractor.h>
#include <vtkRendererCollection.h>
#include <vtkSmartPointer.h>
#include <vtkActor.h>
#include <vtkStringArray.h>
#include <vtkTextProperty.h>

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
//PlotTransmDosDialog::PlotTransmDosDialog()
PlotTransmDosDialog::PlotTransmDosDialog(QWidget *parent_, Qt::WindowFlags f)
    : QDialog( parent_, f )
{
  //this->ui = new Ui_PlotTransmDosDialog;
  //this->ui.setupUi(this);
  ui.setupUi(this);

  // Set up action signals and slots
  //connect(this->ui.actionOpenFile, SIGNAL(triggered()), this, SLOT(slotOpenFile()));
  //connect(this->ui.actionExit, SIGNAL(triggered()), this, SLOT(slotExit()));
  connect(ui.actionOpenFile, SIGNAL(triggered()), this, SLOT(slotOpenFile()));
  connect(ui.actionOpenTransmFile, SIGNAL(triggered()), this, SLOT(slotOpenTransmFile()));
  connect(ui.actionOpenDosFile, SIGNAL(triggered()), this, SLOT(slotOpenDosFile()));
  connect(ui.actionExit, SIGNAL(triggered()), this, SLOT(slotExit()));

    //createMenus();
    connectActions();
    createActions();

    infoLabel = new QLabel(tr("<i>Choose a menu option, or right-click to "
                              "invoke a context menu</i>"));
    infoLabel->setFrameStyle(QFrame::StyledPanel | QFrame::Sunken);
    infoLabel->setAlignment(Qt::AlignCenter);

    //-------------------------------------------------------------------------------------------------------
    //---------- TRANSMISSION PLOT CREATE VIEW --------------------------------------------------------------
    //-------------------------------------------------------------------------------------------------------
    // Set up a 2D scene, add an XY chart to it
    VTK_CREATE(vtkContextView, viewTransm);
    //vtkSmartPointer<vtkContextView> viewTransm =
    //    vtkSmartPointer<vtkContextView>::New();
    //vtkNew<vtkContextView> view;
    viewTransm->GetRenderWindow()->SetSize(400, 300);

    //vtkNew<vtkChartXY> chart;
    //vtkNew<vtkChartXY> chartTransm =
    //        vtkSmartPointer<vtkChartXY>::New();
    chartTransm = vtkSmartPointer<vtkChartXY>::New();

    qDebug()<<"PlotTransmDosDialog::PlotTransmDosDialog() 2a";
    //viewTransm->GetScene()->RemoveItem(chartTransm.GetPointer());
    qDebug()<<"PlotTransmDosDialog::PlotTransmDosDialog() 2b";
    viewTransm->GetScene()->AddItem(chartTransm.GetPointer());

    qDebug()<<"PlotTransmDosDialog::PlotTransmDosDialog() 2c";



    // Graph View needs to get my render window
    qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 5a";
    //ui.qvtkWidget3->GetInteractor()->ReInitialize();
    //viewTransm->SetInteractor(this->ui.qvtkWidget3->GetInteractor());
    viewTransm->SetInteractor(ui.qvtkWidget3->GetInteractor());
    ui.qvtkWidget3->SetRenderWindow(viewTransm->GetRenderWindow());

    qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 6";

    //view->GetInteractor()->Initialize();
    //viewTransm->GetInteractor()->ReInitialize();
    viewTransm->GetInteractor()->Start();
    viewTransm->Render();

    connect(ui.horizontalSliderqvtkWidget3, SIGNAL(valueChanged(int)), this, SLOT(setTransmXRange(int)));
    connect(ui.verticalSliderqvtkWidget3, SIGNAL(valueChanged(int)), this, SLOT(setTransmYRange(int)));
    //-------------------------------------------------------------------------------------------------------
    //---------- END TRANSMISSION PLOT CREATE VIEW ----------------------------------------------------------
    //-------------------------------------------------------------------------------------------------------

    //-------------------------------------------------------------------------------------------------------
    //------------------- DOS PLOT CREATE VIEW --------------------------------------------------------------
    //-------------------------------------------------------------------------------------------------------
    // Set up a 2D scene, add an XY chart to it
    VTK_CREATE(vtkContextView, viewDos);
    //vtkSmartPointer<vtkContextView> viewDos =
    //    vtkSmartPointer<vtkContextView>::New();
    //vtkNew<vtkContextView> view;
    viewDos->GetRenderWindow()->SetSize(400, 300);

    //vtkNew<vtkChartXY> chart;
    //vtkNew<vtkChartXY> chartDos =
    //        vtkSmartPointer<vtkChartXY>::New();
    chartDos = vtkSmartPointer<vtkChartXY>::New();

    qDebug()<<"PlotTransmDosDialog::PlotTransmDosDialog() 2a";
    //viewDos->GetScene()->RemoveItem(chartDos.GetPointer());
    qDebug()<<"PlotTransmDosDialog::PlotTransmDosDialog() 2b";
    viewDos->GetScene()->AddItem(chartDos.GetPointer());

    qDebug()<<"PlotTransmDosDialog::PlotTransmDosDialog() 2c";



    // Graph View needs to get my render window
    qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 5a";
    //ui.qvtkWidget3->GetInteractor()->ReInitialize();
    //viewTransm->SetInteractor(this->ui.qvtkWidget3->GetInteractor());
    viewDos->SetInteractor(ui.qvtkWidgetDos->GetInteractor());
    ui.qvtkWidgetDos->SetRenderWindow(viewDos->GetRenderWindow());

    qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 6";

    //view->GetInteractor()->Initialize();
    //viewDos->GetInteractor()->ReInitialize();
    viewDos->GetInteractor()->Start();
    viewDos->Render();

    connect(ui.horizontalSliderqvtkWidgetDos, SIGNAL(valueChanged(int)), this, SLOT(setDosXRange(int)));
    connect(ui.verticalSliderqvtkWidgetDos, SIGNAL(valueChanged(int)), this, SLOT(setDosYRange(int)));
    //-------------------------------------------------------------------------------------------------------
    //------------------- END DOS PLOT CREATE VIEW ----------------------------------------------------------
    //-------------------------------------------------------------------------------------------------------


    //-------------------------------------------------------------------------------------------------------
    //------------------- PDOS PLOT CREATE VIEW -------------------------------------------------------------
    //-------------------------------------------------------------------------------------------------------
    // Set up a 2D scene, add an XY chart to it
    VTK_CREATE(vtkContextView, viewPDos);
    //vtkSmartPointer<vtkContextView> viewPDos =
    //    vtkSmartPointer<vtkContextView>::New();
    //vtkNew<vtkContextView> view;
    viewPDos->GetRenderWindow()->SetSize(400, 300);

    //vtkNew<vtkChartXY> chart;
    //vtkNew<vtkChartXY> chartPDos =
    //        vtkSmartPointer<vtkChartXY>::New();
    chartPDos = vtkSmartPointer<vtkChartXY>::New();

    qDebug()<<"PlotTransmDosDialog::PlotTransmPDosDialog() 2a";
    //viewPDos->GetScene()->RemoveItem(chartPDos.GetPointer());
    qDebug()<<"PlotTransmDosDialog::PlotTransmPDosDialog() 2b";
    viewPDos->GetScene()->AddItem(chartPDos.GetPointer());

    qDebug()<<"PlotTransmDosDialog::PlotTransmPDosDialog() 2c";



    // Graph View needs to get my render window
    qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 5a";
    //ui.qvtkWidget3->GetInteractor()->ReInitialize();
    //viewTransm->SetInteractor(this->ui.qvtkWidget3->GetInteractor());
    viewPDos->SetInteractor(ui.qvtkWidgetPDos->GetInteractor());
    ui.qvtkWidgetPDos->SetRenderWindow(viewPDos->GetRenderWindow());

    qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 6";

    //view->GetInteractor()->Initialize();
    //viewPDos->GetInteractor()->ReInitialize();
    viewPDos->GetInteractor()->Start();
    viewPDos->Render();

    connect(ui.horizontalSliderqvtkWidgetPDos, SIGNAL(valueChanged(int)), this, SLOT(setPDosXRange(int)));
    connect(ui.verticalSliderqvtkWidgetPDos, SIGNAL(valueChanged(int)), this, SLOT(setPDosYRange(int)));

    //connect(ui.outPDosAlphaTableView->selectionModel(),SIGNAL(selectionChanged(QItemSelection selected,QItemSelection deselected)),this,SLOT(on_outputPDosAlphaColumn_selected(QItemSelection selected, QItemSelection deselected)));
    connect(ui.outPDosAlphaTableView->selectionModel(),SIGNAL(selectionChanged(QItemSelection selected,QItemSelection deselected)),this,SLOT(on_outputPDosAlphaColumn_selected()));
    //connect(ui.outPDosAlphaTableView->selectionModel(),SIGNAL()
    connect(ui.outPDosAlphaTableView->selectionModel(), SIGNAL(currentChanged(const QModelIndex &, const QModelIndex &)), this, SLOT(on_outputPDosAlphaColumn_selected()));

    connect(ui.outPDosBetaTableView->selectionModel(),SIGNAL(selectionChanged(QItemSelection selected,QItemSelection deselected)),this,SLOT(on_outputPDosBetaColumn_selected()));
    connect(ui.outPDosBetaTableView->selectionModel(), SIGNAL(currentChanged(const QModelIndex &, const QModelIndex &)), this, SLOT(on_outputPDosBetaColumn_selected()));

    //ui.outPDosAlphaTableView->selectionModel()->
    //-------------------------------------------------------------------------------------------------------
    //------------------- END PDOS PLOT CREATE VIEW ---------------------------------------------------------
    //-------------------------------------------------------------------------------------------------------
}

PlotTransmDosDialog::~PlotTransmDosDialog()
{
  // The smart pointers should clean up for up

}

void PlotTransmDosDialog::createMenus()
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

void PlotTransmDosDialog::createActions()
{
  openAct = new QAction(tr("&Open..."), this);
  openAct->setShortcuts(QKeySequence::Open);
  openAct->setStatusTip(tr("Open an existing file"));
  connect(openAct, &QAction::triggered, this, &PlotTransmDosDialog::open);

  saveAct = new QAction(tr("&Save"), this);
  saveAct->setShortcuts(QKeySequence::Save);
  saveAct->setStatusTip(tr("Save the document to disk"));
  connect(saveAct, &QAction::triggered, this, &PlotTransmDosDialog::save);

  printAct = new QAction(tr("&Print..."), this);
  printAct->setShortcuts(QKeySequence::Print);
  printAct->setStatusTip(tr("Print the document"));
  connect(printAct, &QAction::triggered, this, &PlotTransmDosDialog::print);

  exitAct = new QAction(tr("E&xit"), this);
  exitAct->setShortcuts(QKeySequence::Quit);
  exitAct->setStatusTip(tr("Exit the application"));
  //connect(exitAct, &QAction::triggered, this, &QDialog::close);
}

void PlotTransmDosDialog::connectActions()
{
  connect(ui.actionOpenFile, &QAction::triggered, this, &PlotTransmDosDialog::open);
  connect(ui.actionSave, &QAction::triggered, this, &PlotTransmDosDialog::save);
  connect(ui.actionPrint, &QAction::triggered, this, &PlotTransmDosDialog::print);
  connect(ui.actionExportTransm, &QAction::triggered, this, &PlotTransmDosDialog::exportPlotTransm);
  connect(ui.actionExportDos, &QAction::triggered, this, &PlotTransmDosDialog::exportPlotDos);
  connect(ui.actionExportPDos, &QAction::triggered, this, &PlotTransmDosDialog::exportPlotPDos);
  //connect(ui.actionExit, &QAction::triggered, this, &QDialog::close);
  connect(ui.actionOpenTransmFile, &QAction::triggered, this, &PlotTransmDosDialog::openTransm);
  connect(ui.actionOpenDosFile, &QAction::triggered, this, &PlotTransmDosDialog::openDos);
  connect(ui.actionOpenPDosFile, &QAction::triggered, this, &PlotTransmDosDialog::openPDos);
}

void PlotTransmDosDialog::open()
{
    infoLabel->setText(tr("Invoked <b>File|Open</b>"));
    on_outputTransmButton_clicked();
}

void PlotTransmDosDialog::openTransm()
{
    infoLabel->setText(tr("Invoked <b>File|Open Transmission</b>"));
    on_outputTransmButton_clicked();
}

void PlotTransmDosDialog::openDos()
{
    infoLabel->setText(tr("Invoked <b>File|Open DOS</b>"));
    on_outputDosButton_clicked();
}

void PlotTransmDosDialog::openPDos()
{
    infoLabel->setText(tr("Invoked <b>File|Open PDOS</b>"));
    on_outputPDosButton_clicked();
}

void PlotTransmDosDialog::save()
{
    infoLabel->setText(tr("Invoked <b>File|Save</b>"));
}

void PlotTransmDosDialog::print()
{
    infoLabel->setText(tr("Invoked <b>File|Print</b>"));
}

// Action to be taken upon file open
void PlotTransmDosDialog::exportPlotTransm()
{
    //QString fileName = QFileDialog::getSaveFileName(this,
    //                                                tr("Export Bitmap Graphics"),
    //                                                "",
    //                                                "Images (*.png *.jpg)");
    QString fileName = QFileDialog::getSaveFileName (this,
                                                     tr("Export Image File"),
                                                     QDir::currentPath(),
                                                     tr("png (*.png);; jpeg (*.jpg);; All Files (*)"));

    if (fileName.isEmpty())
      return;
    if (QFileInfo(fileName).suffix().isEmpty()){
      fileName += ".png";
      pngWriter(fileName, 1);
    }else if(QString::compare(QFileInfo(fileName).suffix().toLatin1(),"png", Qt::CaseInsensitive)==0){
      pngWriter(fileName, 1);
    }else if(QString::compare(QFileInfo(fileName).suffix().toLatin1(),"jpg", Qt::CaseInsensitive)==0){
      jpegWriter(fileName, 1);
    }else{
      fileName += ".png";
      pngWriter(fileName, 1);
    }
}

void PlotTransmDosDialog::exportPlotDos()
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
      pngWriter(fileName, 2);
    }else if(QString::compare(QFileInfo(fileName).suffix().toLatin1(),"png", Qt::CaseInsensitive)==0){
      pngWriter(fileName, 2);
    }else if(QString::compare(QFileInfo(fileName).suffix().toLatin1(),"jpg", Qt::CaseInsensitive)==0){
      jpegWriter(fileName, 2);
    }else{
      fileName += ".png";
      pngWriter(fileName, 2);
    }

}

void PlotTransmDosDialog::exportPlotPDos()
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
      pngWriter(fileName, 3);
    }else if(QString::compare(QFileInfo(fileName).suffix().toLatin1(),"png", Qt::CaseInsensitive)==0){
      pngWriter(fileName, 3);
    }else if(QString::compare(QFileInfo(fileName).suffix().toLatin1(),"jpg", Qt::CaseInsensitive)==0){
      jpegWriter(fileName, 3);
    }else{
      fileName += ".png";
      pngWriter(fileName, 3);
    }

}

void PlotTransmDosDialog::close()
{
    infoLabel->setText(tr("Invoked <b>File|Close</b>"));
}

void PlotTransmDosDialog::clearPlotTransmItems(){
    //ui.outTransmTableView->model()->disconnect();
    ui.outTransmTableView->reset();
    qDebug()<<"PlotTransmDosDialog::clearPlotTransmDosItems() 1";
    originalTransmXsize=10.0;
    originalTransmYsize=10.0;
    newTransmXsize=10.0;
    newTransmYsize=10.0;
    //model->removeColumns(0,model->columnCount());
    //model->removeRows(0,model->rowCount());
    //model->invisibleRootItem()->removeRows(0,model->rowCount());
    //model->rem
    qDebug()<<"PlotTransmDosDialog::clearPlotTransmDosItems() 2";
    //auxmodel->removeColumns(0,auxmodel->columnCount());
    //auxmodel->invisibleRootItem()->removeRows(0,auxmodel->rowCount());
    qDebug()<<"PlotTransmDosDialog::clearPlotTransmDosItems() 3";
    standardItemList.clear();
    qDebug()<<"PlotTransmDosDialog::clearPlotTransmDosItems() 4";
    colTransmission.clear();
    qDebug()<<"PlotTransmDosDialog::clearPlotTransmDosItems() 5";
    enercolTransmission.clear();
    qDebug()<<"PlotTransmDosDialog::clearPlotTransmDosItems() 6";
    singlespincolTransmission.clear();
    qDebug()<<"PlotTransmDosDialog::clearPlotTransmDosItems() 7";
    //viewTransm->Delete();
    qDebug()<<"PlotTransmDosDialog::clearPlotTransmDosItems() 8";
    chartTransm->ClearPlots();
    qDebug()<<"PlotTransmDosDialog::clearPlotTransmDosItems() 9";
    //chartTransm->ClearItems();
    qDebug()<<"PlotTransmDosDialog::clearPlotTransmDosItems() 10";
    //lineTransmAlpha->ClearItems();
    qDebug()<<"PlotTransmDosDialog::clearPlotTransmDosItems() 11";
    //lineTransmBeta->ClearItems();
    qDebug()<<"PlotTransmDosDialog::clearPlotTransmDosItems() 12";
    //renderer->Clear();
    qDebug()<<"PlotTransmDosDialog::clearPlotTransmDosItems() 13";
    //renderWindow->RemoveRenderer(renderer);
    qDebug()<<"PlotTransmDosDialog::clearPlotTransmDosItems() 14";
    //renderWindow->Delete();
    qDebug()<<"PlotTransmDosDialog::clearPlotTransmDosItems() 15";
    //renderWindowInteractor->Delete();
    qDebug()<<"PlotTransmDosDialog::clearPlotTransmDosItems() 16";
    ui.qvtkWidget3->clearMask();
    qDebug()<<"PlotTransmDosDialog::clearPlotTransmDosItems() 17";
    //viewTransm->GetScene()->ClearItems();
    qDebug()<<"PlotTransmDosDialog::clearPlotTransmDosItems() 18";

}

void PlotTransmDosDialog::clearPlotDosItems(){
    //ui.outTransmTableView->model()->disconnect();
    ui.outDosTableView->reset();
    qDebug()<<"PlotTransmDosDialog::clearPlotDosItems() 1";
    originalDosXsize=10.0;
    originalDosYsize=10.0;
    newDosXsize=10.0;
    newDosYsize=10.0;
    //model->removeColumns(0,model->columnCount());
    //model->removeRows(0,model->rowCount());
    //model->invisibleRootItem()->removeRows(0,model->rowCount());
    //model->rem
    qDebug()<<"PlotTransmDosDialog::clearPlotDosItems() 2";
    //auxmodel->removeColumns(0,auxmodel->columnCount());
    //auxmodel->invisibleRootItem()->removeRows(0,auxmodel->rowCount());
    qDebug()<<"PlotTransmDosDialog::clearPlotDosItems() 3";
    standardItemListDos.clear();
    qDebug()<<"PlotTransmDosDialog::clearPlotDosItems() 4";
    colDos.clear();
    qDebug()<<"PlotTransmDosDialog::clearPlotDosItems() 5";
    enercolDos.clear();
    qDebug()<<"PlotTransmDosDialog::clearPlotDosItems() 6";
    singlespincolDos.clear();
    qDebug()<<"PlotTransmDosDialog::clearPlotDosItems() 7";
    //viewDos->Delete();
    qDebug()<<"PlotTransmDosDialog::clearPlotDosItems() 8";
    chartDos->ClearPlots();
    qDebug()<<"PlotTransmDosDialog::clearPlotDosItems() 9";
    //chartDos->ClearItems();
    qDebug()<<"PlotTransmDosDialog::clearPlotDosItems() 10";
    //lineDosAlpha->ClearItems();
    qDebug()<<"PlotTransmDosDialog::clearPlotDosItems() 11";
    //lineDosBeta->ClearItems();
    qDebug()<<"PlotTransmDosDialog::clearPlotDosItems() 12";
    //renderer->Clear();
    qDebug()<<"PlotTransmDosDialog::clearPlotDosItems() 13";
    //renderWindow->RemoveRenderer(renderer);
    qDebug()<<"PlotTransmDosDialog::clearPlotDosItems() 14";
    //renderWindow->Delete();
    qDebug()<<"PlotTransmDosDialog::clearPlotDosItems() 15";
    //renderWindowInteractor->Delete();
    qDebug()<<"PlotTransmDosDialog::clearPlotDosItems() 16";
    ui.qvtkWidgetDos->clearMask();
    qDebug()<<"PlotTransmDosDialog::clearPlotDosItems() 17";
    //viewDos->GetScene()->ClearItems();
    qDebug()<<"PlotTransmDosDialog::clearPlotDosItems() 18";

}

void PlotTransmDosDialog::clearPlotPDosItems(){
    //ui.outTransmTableView->model()->disconnect();
    ui.outPDosAlphaTableView->reset();
    qDebug()<<"PlotTransmDosDialog::clearPlotDosItems() 1";
    originalPDosXsize=10.0;
    originalPDosYsize=10.0;
    newPDosXsize=10.0;
    newPDosYsize=10.0;
    //model->removeColumns(0,model->columnCount());
    //model->removeRows(0,model->rowCount());
    //model->invisibleRootItem()->removeRows(0,model->rowCount());
    //model->rem
    qDebug()<<"PlotTransmDosDialog::clearPlotPDosItems() 2";
    //auxmodel->removeColumns(0,auxmodel->columnCount());
    //auxmodel->invisibleRootItem()->removeRows(0,auxmodel->rowCount());
    qDebug()<<"PlotTransmDosDialog::clearPlotPDosItems() 3";
    standardItemListPDos.clear();
    qDebug()<<"PlotTransmDosDialog::clearPlotPDosItems() 4";
    colPDos.clear();
    qDebug()<<"PlotTransmDosDialog::clearPlotPDosItems() 5";
    enercolPDos.clear();
    qDebug()<<"PlotTransmDosDialog::clearPlotPDosItems() 6";
    singlespincolPDos.clear();
    qDebug()<<"PlotTransmDosDialog::clearPlotPDosItems() 7";
    //viewDos->Delete();
    qDebug()<<"PlotTransmDosDialog::clearPlotPDosItems() 8";
    chartPDos->ClearPlots();
    qDebug()<<"PlotTransmDosDialog::clearPlotPDosItems() 9";
    //chartDos->ClearItems();
    qDebug()<<"PlotTransmDosDialog::clearPlotPDosItems() 10";
    //lineDosAlpha->ClearItems();
    qDebug()<<"PlotTransmDosDialog::clearPlotPDosItems() 11";
    //lineDosBeta->ClearItems();
    qDebug()<<"PlotTransmDosDialog::clearPlotPDosItems() 12";
    //renderer->Clear();
    qDebug()<<"PlotTransmDosDialog::clearPlotPDosItems() 13";
    //renderWindow->RemoveRenderer(renderer);
    qDebug()<<"PlotTransmDosDialog::clearPlotPDosItems() 14";
    //renderWindow->Delete();
    qDebug()<<"PlotTransmDosDialog::clearPlotPDosItems() 15";
    //renderWindowInteractor->Delete();
    qDebug()<<"PlotTransmDosDialog::clearPlotPDosItems() 16";
    ui.qvtkWidgetPDos->clearMask();
    qDebug()<<"PlotTransmDosDialog::clearPlotPDosItems() 17";
    //viewDos->GetScene()->ClearItems();
    qDebug()<<"PlotTransmDosDialog::clearPlotPDosItems() 18";

}

// Action to be taken upon file open
void PlotTransmDosDialog::slotOpenFile()
{

}

void PlotTransmDosDialog::slotExit() {
  //qApp->exit();
}

void PlotTransmDosDialog::on_autoScaleButton_clicked()
{
  //autoScalePlot();
}

/*
void PlotTransmDosDialog::on_horizontalSliderqvtkWidget2_rangeChanged(int min, int max)
{
    double dmin = (double) min;
    double dmax = (double) max;
    //chart->GetAxis(0)->SetUnscaledRange(dmin, dmax);
}

void PlotTransmDosDialog::on_verticalSliderqvtkWidget2_rangeChanged(int min, int max)
{
    double dmin = (double) min;
    double dmax = (double) max;
    //chart->GetAxis(0)->SetUnscaledRange(dmin, dmax);
}
*/

void PlotTransmDosDialog::setTransmXRange( int i ) {
  qDebug()<<"setXRange Start.";
  //qApp->exit();
  //double d = (double) ((100-i)/100.0);
  double d = (double) pow(10.0,(double)(i/10.0));

  qDebug()<<"setXRange d = "<<d;
  double center = (double)(chartTransm->GetAxis(1)->GetMinimum() + chartTransm->GetAxis(1)->GetMaximum())/2.0;
  qDebug()<<"setXRange center = "<<center;
  //double newsize = (double)(d*(chart->GetAxis(1)->GetMaximum() - chart->GetAxis(1)->GetMinimum())/2.0);
  newTransmXsize = (double)(d*originalTransmXsize);
  qDebug()<<"setXRange old GetScalingFactor = "<<chartTransm->GetAxis(1)->GetScalingFactor();
  qDebug()<<"setXRange newsize = "<<newTransmXsize;
  chartTransm->GetAxis(1)->SetUnscaledRange((double)(center-newTransmXsize/2.0), (double)(center+newTransmXsize/2.0));

  //chart->GetAxis(1)->SetUnscaledRange(center-d, center+d);
  //chart->GetAxis(1)->SetRange(-d, d);
  //chart->GetAxis(1)->SetScalingFactor( d );
  qDebug()<<"setXRange 1.";
  chartTransm->GetAxis(1)->Update(); // WORKS WITH DELAY.
  //areaTransm->Update();
  //lineTransmAlpha->Update();
  //lineTransmBeta->Update();
  qDebug()<<"setXRange 2.";
  //view->Update();
  //view->GetInteractor()->Render();
  //view->Render();
  //std::cout << "Clicked." << std::endl;
  chartTransm->Update();
  qDebug()<<"setXRange 3.";
  ui.qvtkWidget3->update();
  qDebug()<<"setXRange Finish.";
}

void PlotTransmDosDialog::setTransmYRange( int i ) {
  qDebug()<<"setYRange Start.";
  //qApp->exit();
  //double d = (double) ((100-i)/100.0);
  double d = (double) pow(10.0,(double)(i/10.0));

  qDebug()<<"setYRange d = "<<d;
  double center = (double)(chartTransm->GetAxis(0)->GetMinimum() + chartTransm->GetAxis(0)->GetMaximum())/2.0;
  qDebug()<<"setYRange center = "<<center;
  newTransmYsize = (double)(d*originalTransmYsize);
  qDebug()<<"setYRange old GetScalingFactor = "<<chartTransm->GetAxis(0)->GetScalingFactor();
  qDebug()<<"setYRange newsize = "<<newTransmYsize;
  chartTransm->GetAxis(0)->SetUnscaledRange((double)(center-newTransmYsize/2.0), (double)(center+newTransmYsize/2.0));

  //chart->GetAxis(0)->SetUnscaledRange(center-d, center+d);
  //chart->GetAxis(0)->SetRange(-d, d);
  //chart->GetAxis(0)->SetScalingFactor( d );
  qDebug()<<"setYRange 1.";
  chartTransm->GetAxis(0)->Update(); // WORKS WITH DELAY.
  //areaTransm->Update();
  //lineTransmAlpha->Update();
  //lineTransmBeta->Update();
  qDebug()<<"setYRange 2.";
  //view->Update();
  //view->GetInteractor()->Render();
  //view->Render();
  //std::cout << "Clicked." << std::endl;
  chartTransm->Update();
  qDebug()<<"setYRange 3.";
  ui.qvtkWidget3->update();
  qDebug()<<"setYRange Finish.";
}

void PlotTransmDosDialog::setDosXRange( int i ) {
  qDebug()<<"setXRange Start.";
  //qApp->exit();
  //double d = (double) ((100-i)/100.0);
  double d = (double) pow(10.0,(double)(i/10.0));

  qDebug()<<"setXRange d = "<<d;
  double center = (double)(chartDos->GetAxis(1)->GetMinimum() + chartDos->GetAxis(1)->GetMaximum())/2.0;
  qDebug()<<"setXRange center = "<<center;
  //double newsize = (double)(d*(chart->GetAxis(1)->GetMaximum() - chart->GetAxis(1)->GetMinimum())/2.0);
  newDosXsize = (double)(d*originalDosXsize);
  qDebug()<<"setXRange old GetScalingFactor = "<<chartDos->GetAxis(1)->GetScalingFactor();
  qDebug()<<"setXRange newsize = "<<newDosXsize;
  chartDos->GetAxis(1)->SetUnscaledRange((double)(center-newDosXsize/2.0), (double)(center+newDosXsize/2.0));

  //chart->GetAxis(1)->SetUnscaledRange(center-d, center+d);
  //chart->GetAxis(1)->SetRange(-d, d);
  //chart->GetAxis(1)->SetScalingFactor( d );
  qDebug()<<"setXRange 1.";
  chartDos->GetAxis(1)->Update(); // WORKS WITH DELAY.
  //areaDos->Update();
  //lineDosAlpha->Update();
  //lineDosBeta->Update();
  qDebug()<<"setXRange 2.";
  //view->Update();
  //view->GetInteractor()->Render();
  //view->Render();
  //std::cout << "Clicked." << std::endl;
  chartDos->Update();
  qDebug()<<"setXRange 3.";
  ui.qvtkWidgetDos->update();
  qDebug()<<"setXRange Finish.";
}

void PlotTransmDosDialog::setDosYRange( int i ) {
  qDebug()<<"setYRange Start.";
  //qApp->exit();
  //double d = (double) ((100-i)/100.0);
  double d = (double) pow(10.0,(double)(i/10.0));

  qDebug()<<"setYRange d = "<<d;
  double center = (double)(chartDos->GetAxis(0)->GetMinimum() + chartDos->GetAxis(0)->GetMaximum())/2.0;
  qDebug()<<"setYRange center = "<<center;
  newDosYsize = (double)(d*originalDosYsize);
  qDebug()<<"setYRange old GetScalingFactor = "<<chartDos->GetAxis(0)->GetScalingFactor();
  qDebug()<<"setYRange newsize = "<<newDosYsize;
  chartDos->GetAxis(0)->SetUnscaledRange((double)(center-newDosYsize/2.0), (double)(center+newDosYsize/2.0));

  //chart->GetAxis(0)->SetUnscaledRange(center-d, center+d);
  //chart->GetAxis(0)->SetRange(-d, d);
  //chart->GetAxis(0)->SetScalingFactor( d );
  qDebug()<<"setYRange 1.";
  chartDos->GetAxis(0)->Update(); // WORKS WITH DELAY.
  //areaDos->Update();
  //lineDosAlpha->Update();
  //lineDosBeta->Update();
  qDebug()<<"setYRange 2.";
  //view->Update();
  //view->GetInteractor()->Render();
  //view->Render();
  //std::cout << "Clicked." << std::endl;
  chartDos->Update();
  qDebug()<<"setYRange 3.";
  ui.qvtkWidgetDos->update();
  qDebug()<<"setYRange Finish.";
}

void PlotTransmDosDialog::setPDosXRange( int i ) {
  qDebug()<<"setXRange Start.";
  //qApp->exit();
  //double d = (double) ((100-i)/100.0);
  double d = (double) pow(10.0,(double)(i/10.0));

  qDebug()<<"setXRange d = "<<d;
  double center = (double)(chartPDos->GetAxis(1)->GetMinimum() + chartPDos->GetAxis(1)->GetMaximum())/2.0;
  qDebug()<<"setXRange center = "<<center;
  //double newsize = (double)(d*(chart->GetAxis(1)->GetMaximum() - chart->GetAxis(1)->GetMinimum())/2.0);
  newPDosXsize = (double)(d*originalPDosXsize);
  qDebug()<<"setXRange old GetScalingFactor = "<<chartPDos->GetAxis(1)->GetScalingFactor();
  qDebug()<<"setXRange newsize = "<<newPDosXsize;
  chartPDos->GetAxis(1)->SetUnscaledRange((double)(center-newPDosXsize/2.0), (double)(center+newPDosXsize/2.0));

  //chart->GetAxis(1)->SetUnscaledRange(center-d, center+d);
  //chart->GetAxis(1)->SetRange(-d, d);
  //chart->GetAxis(1)->SetScalingFactor( d );
  qDebug()<<"setXRange 1.";
  chartPDos->GetAxis(1)->Update(); // WORKS WITH DELAY.
  //areaDos->Update();
  //lineDosAlpha->Update();
  //lineDosBeta->Update();
  qDebug()<<"setXRange 2.";
  //view->Update();
  //view->GetInteractor()->Render();
  //view->Render();
  //std::cout << "Clicked." << std::endl;
  chartPDos->Update();
  qDebug()<<"setXRange 3.";
  ui.qvtkWidgetPDos->update();
  qDebug()<<"setXRange Finish.";
}

void PlotTransmDosDialog::setPDosYRange( int i ) {
  qDebug()<<"setYRange Start.";
  //qApp->exit();
  //double d = (double) ((100-i)/100.0);
  double d = (double) pow(10.0,(double)(i/10.0));

  qDebug()<<"setYRange d = "<<d;
  double center = (double)(chartPDos->GetAxis(0)->GetMinimum() + chartPDos->GetAxis(0)->GetMaximum())/2.0;
  qDebug()<<"setYRange center = "<<center;
  newPDosYsize = (double)(d*originalPDosYsize);
  qDebug()<<"setYRange old GetScalingFactor = "<<chartPDos->GetAxis(0)->GetScalingFactor();
  qDebug()<<"setYRange newsize = "<<newPDosYsize;
  chartPDos->GetAxis(0)->SetUnscaledRange((double)(center-newPDosYsize/2.0), (double)(center+newPDosYsize/2.0));

  //chart->GetAxis(0)->SetUnscaledRange(center-d, center+d);
  //chart->GetAxis(0)->SetRange(-d, d);
  //chart->GetAxis(0)->SetScalingFactor( d );
  qDebug()<<"setYRange 1.";
  chartPDos->GetAxis(0)->Update(); // WORKS WITH DELAY.
  //areaDos->Update();
  //lineDosAlpha->Update();
  //lineDosBeta->Update();
  qDebug()<<"setYRange 2.";
  //view->Update();
  //view->GetInteractor()->Render();
  //view->Render();
  //std::cout << "Clicked." << std::endl;
  chartPDos->Update();
  qDebug()<<"setYRange 3.";
  ui.qvtkWidgetPDos->update();
  qDebug()<<"setYRange Finish.";
}

void PlotTransmDosDialog::on_action_Open_triggered()
{
    model = new QStandardItemModel(this);
    ui.outTransmTableView->setModel(model);
    QString fileName = QFileDialog::getOpenFileName (this, "Open CSV file",
                                                     QDir::currentPath(), "CSV (*.csv)");
    QFile file (fileName);
    if (file.open(QIODevice::ReadOnly)) {
        QString data = file.readAll();
        data.remove( QRegExp("\r") ); //remove all ocurrences of CR (Carriage Return)
        QString temp;
        QChar character;
        QTextStream textStream(&data);
        while (!textStream.atEnd()) {
            textStream >> character;
            if (character == ',') {
                checkString(temp, character);
            } else if (character == '\n') {
                checkString(temp, character);
            } else if (textStream.atEnd()) {
                temp.append(character);
                checkString(temp);
            } else {
                temp.append(character);
            }
        }
    }
}

//void PlotTransmDosDialog::auto_Open_triggered(QString &fileName)
void PlotTransmDosDialog::auto_Open_triggered()
{
    /**/
    model = new QStandardItemModel(this);
    ui.outTransmTableView->setModel(model);
    QString fileName = QFileDialog::getOpenFileName (this, "Open CSV file",
                                                     QDir::currentPath(), "CSV (*.csv)");
    /**/

    QFile file (fileName);
    if (file.open(QIODevice::ReadOnly)) {
        QString data = file.readAll();
        data.remove( QRegExp("\r") ); //remove all ocurrences of CR (Carriage Return)
        QString temp;
        QChar character;
        QTextStream textStream(&data);
        while (!textStream.atEnd()) {
            textStream >> character;
            if (character == ',') {
                checkString(temp, character);
            } else if (character == '\n') {
                checkString(temp, character);
            } else if (textStream.atEnd()) {
                temp.append(character);
                checkString(temp);
            } else {
                temp.append(character);
            }
        }
    }
}

void PlotTransmDosDialog::checkString(QString &temp, QChar character)
{
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
        //getchar();
        if (character != QChar(',')) {
            model->appendRow(standardItemList);
            standardItemList.clear();
        }
        temp.clear();
    } else {
        temp.append(character);
    }
}


//void PlotTransmDosDialog::modcheckString(QString &temp, QChar character)
void PlotTransmDosDialog::modcheckString(QString &temp, QChar character)
{
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
        if (character != QChar(',') && character != QChar(' ')) {
            //model->appendRow(standardItemList); // COMMENTED BY C.SALGADO ON 2016-08-03 TO AVOID CRASHES.
            auxmodel->appendRow(standardItemList); // COMMENTED BY C.SALGADO ON 2016-08-03 TO AVOID CRASHES.
            standardItemList.clear();
        }
        temp.clear();
    } else {
        temp.append(character);
    }
}

// Browse... button clicked - this is for input file
//void Dialog::on_fileOpenButton_clicked()
//void PlotTransmDosDialog::on_opentransmOpenButton_clicked()
//void PlotTransmDosDialog::on_opentransmOpenButton_clicked()
void PlotTransmDosDialog::on_outputTransmButton_clicked()
{
    qDebug() <<"PlotTransmDosDialog::on_outputTransmButton_clicked() 1";
    clearPlotTransmItems();

    /*widget_2
    QString fileName =
        QFileDialog::getOpenFileName(
                this,
                tr("Open File"),
                "C:/TEST",
                //tr("videoss (*.mp4 *.mov *.avi)"));
                //tr("(*.mp4 *.mov *.avi)"));
                tr("(*.csv)"));
    if (!fileName.isEmpty()) {
        ui.outTransmLineEdit->setText(fileName);
    }
    */

    //model = new QStandardItemModel(this); // COMMENTED BY C.SALGADO ON 2016-08-03 TO AVOID PRINTING TRANSMISSION TWICE.
    //ui.outTransmTableView->setModel(model); // COMMENTED BY C.SALGADO ON 2016-08-03 TO AVOID PRINTING TRANSMISSION TWICE.
    //QStandardItemModel *auxmodel = new QStandardItemModel(1,1,this); //1 Rows and 1 Columns
    auxmodel = new QStandardItemModel(this);
    model = new QStandardItemModel(this);

    //QString fileName = QFileDialog::getOpenFileName (this, "Open CSV file",
    //                                                 QDir::currentPath(), "CSV (*.csv)");
    qDebug() <<"PlotTransmDosDialog::on_outputTransmButton_clicked() 2";
    QString fileName = QFileDialog::getOpenFileName (this, "Open DAT file",
                                                     QDir::currentPath(),
                                                     tr("DAT (*.dat);; All Files (*)"));
//    QString fileName = QFileDialog::getOpenFileName (this, tr("Save Image File"),
//                                                     QDir::currentPath(),
//                                                     tr("png (*.png);; jpeg (*.jpg);; All Files (*)");
    QFile file (fileName);
    if (file.open(QIODevice::ReadOnly)) {
        QString data = file.readAll();
        data.remove( QRegExp("\r") ); //remove all ocurrences of CR (Carriage Return)
        QString temp;
        QChar character;
        QTextStream textStream(&data);
        textStream.skipWhiteSpace();
        while (!textStream.atEnd()) {
            textStream >> character;
                if (character == ',') {
                    modcheckString(temp, character);
                    //modcheckString(auxmodel, temp, character);
                //} else if (character == '\0') {
                //    modcheckString(temp, character);
                } else if (character == QChar(' ')) {
                    //textStream >> character;
                    //textStream >> character;
                    textStream.skipWhiteSpace();
                    modcheckString(temp, character);
                    //modcheckString(auxmodel, temp, character);
                } else if (character == QChar('\n')) {
                    //newlinecount++;
                    textStream.skipWhiteSpace();
                    modcheckString(temp, character);
                    //modcheckString(auxmodel, temp, character);
                } else if (textStream.atEnd()) {
                    temp.append(character);
                    modcheckString(temp);
                    //modcheckString(auxmodel, temp);
                } else {
                    temp.append(character);
                }
        }
    }
    //MyClass::*modelTransmission = *model;
    qDebug() <<"PlotTransmDosDialog::on_outputTransmButton_clicked() 3"<< auxmodel->item(1,1);
    //qDebug() << MyClass::s_count;
    qDebug() << s_count;



    qint32 n = auxmodel->rowCount();
    qint32 m = auxmodel->columnCount();
    //int n = model->rowCount();
    //int m = model->columnCount();
    qDebug() <<"PlotTransmDosDialog::on_outputTransmButton_clicked() 4 : "<< "n" << n << "m" << m ;

    //MyClass dataTransmission = new MyClass();
    //QList<float> dataTransmission = MyClass::colTransmission;
    //QList<double> dataTransmission = colTransmission;
    QList<QList<double>> dataTransmission;
    QList<double> alphadataTransmission = singlespincolTransmission;
    QList<double> betadataTransmission = singlespincolTransmission;
    QList<double> energyTransmission = enercolTransmission;
    int magneticNumberOfRows = 0;
    QList<double> pivotlist;
    //MyClass:: dataTransmission;

    qDebug() <<"PlotTransmDosDialog::on_outputTransmButton_clicked() 5";

    //QStandardItem *item = new QStandardItem(dataTransmission[0]);
    //QList< QStandardItem * > items;

    //stream << n << m;

    bool isMagneticTransm = false;
    //int numcolDataTransmission = 1;
    numcolDataTransmission = 1;
    for (int i=0; i<n; ++i){
    //    for (int j=0; j<m; j++){
            //model->item(i,j)->write(stream);
            //dataTransmission(i) = model->item(i,2);
            //dataTransmission[i] = model->item(i,2);
            //dataTransmission[i] = model->data(model->index(i,2)).toInt();
            //dataTransmission[i] = model->data(model->index(i,1)).toFloat();
        /*
        qDebug() << "model->item("<<i<<",0);" << model->item(i,0);
        qDebug() << "model->item("<<i<<",1);" << model->item(i,1);
        qDebug() << "model->item("<<i<<",2);" << model->item(i,2);
        qDebug() << "model->index("<<i<<",0);" << model->index(i,0);
        qDebug() << "model->index("<<i<<",1);" << model->index(i,1);
        qDebug() << "model->index("<<i<<",2);" << model->index(i,2);
        */
        //qDebug() << "model->data(model->index("<<i<<",2)).toString();" << model->data(model->index(i,0)).toString();
        qDebug() << "auxmodel->data(model->index("<<i<<",2)).toFloat();" << auxmodel->data(auxmodel->index(i,0)).toFloat();
        //qDebug() << "model->data(model->index("<<i<<",2)).toString();" << model->data(model->index(i,1)).toString();
        qDebug() << "auxmodel->data(auxmodel->index("<<i<<",2)).toFloat();" << auxmodel->data(auxmodel->index(i,1)).toDouble();
        //MyClass::dataTransmission << model->data(model->index(i,1)).toFloat();
        //dataTransmission << model->data(model->index(i,1)).toFloat();


        if(i==0){
          energyTransmission << auxmodel->data(auxmodel->index(i,0)).toDouble();
          //dataTransmission.append(pivotlist);
          alphadataTransmission << auxmodel->data(auxmodel->index(i,1)).toDouble();
//          qDebug()<<"alphdataTransmission["<<i<<"] = "<<alphadataTransmission[i];
        }else if ((i>0) & ((auxmodel->data(auxmodel->index(i,0)).toDouble() > auxmodel->data(auxmodel->index(i-1,0)).toDouble()) & ~(isMagneticTransm))){
          energyTransmission << auxmodel->data(auxmodel->index(i,0)).toDouble();
          //dataTransmission.append(pivotlist);
          alphadataTransmission << auxmodel->data(auxmodel->index(i,1)).toDouble();
//          qDebug()<<"alphdataTransmission["<<i<<"] = "<<alphadataTransmission[i];
        }else if((i>0) & (auxmodel->data(auxmodel->index(i,0)).toDouble() < auxmodel->data(auxmodel->index(i-1,0)).toDouble())){
          isMagneticTransm = true;
          numcolDataTransmission = 2;
          magneticNumberOfRows = i;
          qDebug()<<"magneticNumberOfRows = "<<magneticNumberOfRows;
          //qDebug()<<"numcolDataTransmission = "<<numcolDataTransmission;
          //dataTransmission y0[col].resize(n);
          //dataTransmission[1].reserve(1);
          //dataTransmission.append(pivotlist);
          //qDebug()<<"dataTransmission.size() = "<<dataTransmission.size();
          //dataTransmission[1].append(model->data(model->index(i,1)).toDouble());
          betadataTransmission << auxmodel->data(auxmodel->index(i,1)).toDouble();
          //qDebug()<<"betadataTransmission["<<0<<"] = "<<betadataTransmission[0];
//          qDebug()<<"betadataTransmission["<<i-magneticNumberOfRows<<"] = "<<betadataTransmission[i-magneticNumberOfRows];
        }else if ((i>0) & ((auxmodel->data(auxmodel->index(i,0)).toDouble() > auxmodel->data(auxmodel->index(i-1,0)).toDouble()) & (isMagneticTransm))){
          betadataTransmission << auxmodel->data(auxmodel->index(i,1)).toDouble();
//          qDebug()<<"betadataTransmission["<<i-magneticNumberOfRows<<"] = "<<betadataTransmission[i-magneticNumberOfRows];
        }

        //qDebug() << "model->data(model->index(i,2)).toFloat();" << dataTransmission[i];
            //qDebug() << "dataTransmission[i]" << dataTransmission[i];
    //    }

        //QStandardItem *item = new QStandardItem(dataTransmission[i]);
        //standardItemList.append(item);
        //QStandardItem *item = new QStandardItem(dataTransmission[i]);
        //items << new QStandardItem(dataTransmission[i]);
        //qDebug() << "items" << items[i];
    }

    qDebug() <<"PlotTransmDosDialog::on_outputTransmButton_clicked() 6";

    //if(~(isMagneticTransm)){
    if(numcolDataTransmission == 1){
      qDebug()<<"numcolDataTransmission = "<<numcolDataTransmission;
      //numcolDataTransmission = 1;
      //magneticNumberOfRows = n; // COMMENTED BY C.SALGADO 2016-08-04.
      magneticNumberOfRows = alphadataTransmission.size();
      //dataTransmission.append(alphadataTransmission);
      qDebug()<<"magneticNumberOfRows = "<<magneticNumberOfRows;
      qDebug()<<"numcolDataTransmission = "<<numcolDataTransmission;
      dataTransmission.append(alphadataTransmission);
      qDebug()<<"dataTransmission.size() = "<<dataTransmission.size();
      qDebug()<<"dataTransmission[0].size() = "<<dataTransmission[0].size();
    }else if(numcolDataTransmission == 2){
      //numcolDataTransmission = 2;
      //dataTransmission << alphadataTransmission<<betadataTransmission;
      //dataTransmission.append(alphadataTransmission);
      //dataTransmission.append(betadataTransmission);
        qDebug()<<"magneticNumberOfRows = "<<magneticNumberOfRows;
      qDebug()<<"numcolDataTransmission = "<<numcolDataTransmission;
      dataTransmission.append(alphadataTransmission);
      dataTransmission.append(betadataTransmission);
      qDebug()<<"dataTransmission.size() = "<<dataTransmission.size();
      qDebug()<<"dataTransmission[0].size() = "<<dataTransmission[0].size();
      qDebug()<<"dataTransmission[1].size() = "<<dataTransmission[1].size();
    }else{
      //numcolDataTransmission = 1;
      //magneticNumberOfRows = n; // COMMENTED BY C.SALGADO 2016-08-04.
      magneticNumberOfRows = alphadataTransmission.size();
      //dataTransmission.append(alphadataTransmission);
      qDebug()<<"magneticNumberOfRows = "<<magneticNumberOfRows;
      qDebug()<<"numcolDataTransmission = "<<numcolDataTransmission;
      dataTransmission.append(alphadataTransmission);
      qDebug()<<"dataTransmission.size() = "<<dataTransmission.size();
      qDebug()<<"dataTransmission[0].size() = "<<dataTransmission[0].size();
    }


    //qDebug() << "item" << item;
    //model->appendColumn(standardItemList);
    /*
    float f = 0;
    for (int i=0; i<n; ++i){
        f = dataTransmission[i];
        qDebug() << "f" << f;
        QStandardItem *item = new QStandardItem(f);
        qDebug() << "item" << item;
        standardItemList.append(item);
        //model->appendRow(standardItemList);
        //model->setItem(i,2,item);
    }
    */
    qDebug() <<"PlotTransmDosDialog::on_outputTransmButton_clicked() 7";
    qDebug()<<"PlotTransmDosDialog::on_outputTransmButton_clicked() Writing Energy column to model";
    for (int i=0; i<magneticNumberOfRows; ++i){
        qDebug()<<"i = "<<i;
        QVariant varEnerTransmission(energyTransmission[i]);
        QStandardItem *elemEnerTransm = new QStandardItem(varEnerTransmission.toString());
        standardItemList.append(elemEnerTransm);
    }
    //model->insertColumn(1,standardItemList); // COMMENTED BY C.SALGADO ON 2016-08-03 TO AVOID PRINTING TRANSMISSION TWICE.
    model->appendColumn(standardItemList); // ADDED BY C.SALGADO ON 2016-08-03 TO AVOID PRINTING TRANSMISSION TWICE.
    standardItemList.clear();
    qDebug() <<"PlotTransmDosDialog::on_outputTransmButton_clicked() 8";
    qDebug()<<"PlotTransmDosDialog::on_outputTransmButton_clicked() Writing Transmission columns to model";
    for (int col=0; col<numcolDataTransmission; ++col){
      //for (int i=0; i<n; ++i){
      for (int i=0; i<magneticNumberOfRows; ++i){
//        qDebug()<<"col"<<col<<"i = "<<i;
        QVariant varTransmission(dataTransmission[col][i]);
        //QStandardItem *elemTransm = new QStandardItem(dataTransmission[i]);
        QStandardItem *elemTransm = new QStandardItem(varTransmission.toString());
        standardItemList.append(elemTransm);
        //model->setItem(i,0,elemTransm);
      }

    //model->insertColumn(2,standardItemList);
      //model->insertColumn(col+2,standardItemList);
      //model->insertColumn(col+2,standardItemList);
      model->appendColumn(standardItemList); // ADDED BY C.SALGADO ON 2016-08-03 TO AVOID PRINTING TRANSMISSION TWICE.
      standardItemList.clear();
    }
    qDebug() <<"PlotTransmDosDialog::on_outputTransmButton_clicked() 9";

    //
    //model->appendColumn(dataTransmission);
    colTransmission = dataTransmission;
    enercolTransmission = energyTransmission;

    ui.outTransmTableView->setModel(model); // ADDED BY C.SALGADO ON 2016-08-03 TO AVOID PRINTING TRANSMISSION TWICE.

    //on_printTransmButton_clicked();
    qDebug() <<"PlotTransmDosDialog::on_outputTransmButton_clicked() 10";
    on_plotTransmButton_clicked();

}

void PlotTransmDosDialog::modcheckStringDos(QString &temp, QChar character)
{
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
        standardItemListDos.append(item);
        if (character != QChar(',') && character != QChar(' ')) {
            //model->appendRow(standardItemList); // COMMENTED BY C.SALGADO ON 2016-08-03 TO AVOID CRASHES.
            auxmodelDos->appendRow(standardItemListDos); // COMMENTED BY C.SALGADO ON 2016-08-03 TO AVOID CRASHES.
            standardItemListDos.clear();
        }
        temp.clear();
    } else {
        temp.append(character);
    }
}

void PlotTransmDosDialog::on_outputDosButton_clicked()
{
    qDebug() <<"PlotTransmDosDialog::on_outputDosButton_clicked() 1";
    clearPlotDosItems();

    //model = new QStandardItemModel(this); // COMMENTED BY C.SALGADO ON 2016-08-03 TO AVOID PRINTING TRANSMISSION TWICE.
    //ui.outDosTableView->setModel(model); // COMMENTED BY C.SALGADO ON 2016-08-03 TO AVOID PRINTING TRANSMISSION TWICE.
    //QStandardItemModel *auxmodel = new QStandardItemModel(1,1,this); //1 Rows and 1 Columns
    auxmodelDos = new QStandardItemModel(this);
    modelDos = new QStandardItemModel(this);

    //QString fileName = QFileDialog::getOpenFileName (this, "Open CSV file",
    //                                                 QDir::currentPath(), "CSV (*.csv)");
    qDebug() <<"PlotTransmDosDialog::on_outputDosButton_clicked() 2";
    QString fileName = QFileDialog::getOpenFileName (this, "Open DAT file",
                                                     QDir::currentPath(), "DAT (*)");
    QFile file (fileName);
    if (file.open(QIODevice::ReadOnly)) {
        QString data = file.readAll();
        data.remove( QRegExp("\r") ); //remove all ocurrences of CR (Carriage Return)
        QString temp;
        QChar character;
        QTextStream textStream(&data);
        textStream.skipWhiteSpace();
        while (!textStream.atEnd()) {
          textStream >> character;
          if (character == ',') {
            modcheckStringDos(temp, character);
            //modcheckString(auxmodel, temp, character);
            //} else if (character == '\0') {
            //    modcheckString(temp, character);
          } else if (character == QChar(' ')) {
            //textStream >> character;
            //textStream >> character;
            textStream.skipWhiteSpace();
            modcheckStringDos(temp, character);
            //modcheckString(auxmodel, temp, character);
          } else if (character == QChar('\n')) {
            //newlinecount++;
            textStream.skipWhiteSpace();
            modcheckStringDos(temp, character);
            //modcheckString(auxmodel, temp, character);
          } else if (textStream.atEnd()) {
            temp.append(character);
            modcheckStringDos(temp);
            //modcheckString(auxmodel, temp);
          } else {
            temp.append(character);
          }
        }
        qDebug() <<"PlotTransmDosDialog:: temp"<<temp.toLatin1();
    }
    //MyClass::*modelDos = *model;
    qDebug() <<"PlotTransmDosDialog::on_outputDosButton_clicked() 3"<< auxmodelDos->item(1,1);
    //qDebug() << MyClass::s_count;
    qDebug() << s_count;



    qint32 n = auxmodelDos->rowCount();
    qint32 m = auxmodelDos->columnCount();
    //int n = model->rowCount();
    //int m = model->columnCount();
    qDebug() <<"PlotTransmDosDialog::on_outputTransmButton_clicked() 4 : "<< "n" << n << "m" << m ;

    //MyClass dataTransmission = new MyClass();
    //QList<float> dataTransmission = MyClass::colTransmission;
    //QList<double> dataTransmission = colTransmission;
    QList<QList<double>> dataDos;
    QList<double> alphadataDos = singlespincolDos;
    QList<double> betadataDos = singlespincolDos;
    QList<double> energyDos = enercolDos;
    int magneticNumberOfRows = 0;
    QList<double> pivotlist;
    //MyClass:: dataTransmission;

    qDebug() <<"PlotTransmDosDialog::on_outputTransmButton_clicked() 5";

    //QStandardItem *item = new QStandardItem(dataTransmission[0]);
    //QList< QStandardItem * > items;

    //stream << n << m;

    bool isMagneticDos = false;
    //int numcolDataTransmission = 1;
    numcolDataDos = 1;
    for (int i=0; i<n; ++i){
        //qDebug() << "model->data(model->index("<<i<<",2)).toString();" << model->data(model->index(i,0)).toString();
//        qDebug() << "auxmodel->data(model->index("<<i<<",2)).toFloat();" << auxmodelDos->data(auxmodelDos->index(i,0)).toFloat();
        //qDebug() << "model->data(model->index("<<i<<",2)).toString();" << model->data(model->index(i,1)).toString();
//        qDebug() << "auxmodel->data(auxmodel->index("<<i<<",2)).toFloat();" << auxmodelDos->data(auxmodelDos->index(i,1)).toDouble();
        //MyClass::dataTransmission << model->data(model->index(i,1)).toFloat();
        //dataTransmission << model->data(model->index(i,1)).toFloat();


        if(i==0){
          energyDos << auxmodelDos->data(auxmodelDos->index(i,0)).toDouble();
          //dataTransmission.append(pivotlist);
          alphadataDos << auxmodelDos->data(auxmodelDos->index(i,1)).toDouble();
//          qDebug()<<"alphdataTransmission["<<i<<"] = "<<alphadataDos[i];
        }else if ((i>0) & ((auxmodelDos->data(auxmodelDos->index(i,0)).toDouble() > auxmodelDos->data(auxmodelDos->index(i-1,0)).toDouble()) & ~(isMagneticDos))){
          energyDos << auxmodelDos->data(auxmodelDos->index(i,0)).toDouble();
          //dataTransmission.append(pivotlist);
          alphadataDos << auxmodelDos->data(auxmodelDos->index(i,1)).toDouble();
//          qDebug()<<"alphdataTransmission["<<i<<"] = "<<alphadataDos[i];
        }else if((i>0) & (auxmodelDos->data(auxmodelDos->index(i,0)).toDouble() < auxmodelDos->data(auxmodelDos->index(i-1,0)).toDouble())){
          isMagneticDos = true;
          numcolDataDos = 2;
          magneticNumberOfRows = i;
          qDebug()<<"magneticNumberOfRows = "<<magneticNumberOfRows;
          //qDebug()<<"numcolDataTransmission = "<<numcolDataTransmission;
          //dataTransmission y0[col].resize(n);
          //dataTransmission[1].reserve(1);
          //dataTransmission.append(pivotlist);
          //qDebug()<<"dataTransmission.size() = "<<dataTransmission.size();
          //dataTransmission[1].append(model->data(model->index(i,1)).toDouble());
          betadataDos << auxmodelDos->data(auxmodelDos->index(i,1)).toDouble();
          //qDebug()<<"betadataTransmission["<<0<<"] = "<<betadataTransmission[0];
//          qDebug()<<"betadataTransmission["<<i-magneticNumberOfRows<<"] = "<<betadataDos[i-magneticNumberOfRows];
        }else if ((i>0) & ((auxmodelDos->data(auxmodelDos->index(i,0)).toDouble() > auxmodelDos->data(auxmodelDos->index(i-1,0)).toDouble()) & (isMagneticDos))){
          betadataDos << auxmodelDos->data(auxmodelDos->index(i,1)).toDouble();
//          qDebug()<<"betadataTransmission["<<i-magneticNumberOfRows<<"] = "<<betadataDos[i-magneticNumberOfRows];
        }
    }

    qDebug() <<"PlotTransmDosDialog::on_outputDosButton_clicked() 6";

    //if(~(isMagneticDos)){
    if(numcolDataDos == 1){
      qDebug()<<"numcolDataDos = "<<numcolDataDos;
      //numcolDataDos = 1;
      //magneticNumberOfRows = n; // COMMENTED BY C.SALGADO 2016-08-04.
      magneticNumberOfRows = alphadataDos.size();
      //dataDos.append(alphadataDos);
      qDebug()<<"magneticNumberOfRows = "<<magneticNumberOfRows;
      qDebug()<<"numcolDataDos = "<<numcolDataDos;
      dataDos.append(alphadataDos);
      qDebug()<<"dataDos.size() = "<<dataDos.size();
      qDebug()<<"dataDos[0].size() = "<<dataDos[0].size();
    }else if(numcolDataDos == 2){
      //numcolDataDos = 2;
      //dataDos << alphadataDos<<betadataDos;
      //dataDos.append(alphadataDos);
      //dataDos.append(betadataDos);
        qDebug()<<"magneticNumberOfRows = "<<magneticNumberOfRows;
      qDebug()<<"numcolDataDos = "<<numcolDataDos;
      dataDos.append(alphadataDos);
      dataDos.append(betadataDos);
      qDebug()<<"dataDos.size() = "<<dataDos.size();
      qDebug()<<"dataDos[0].size() = "<<dataDos[0].size();
      qDebug()<<"dataDos[1].size() = "<<dataDos[1].size();
    }else{
      //numcolDataDos = 1;
      //magneticNumberOfRows = n; // COMMENTED BY C.SALGADO 2016-08-04.
      magneticNumberOfRows = alphadataDos.size();
      //dataDos.append(alphadataDos);
      qDebug()<<"magneticNumberOfRows = "<<magneticNumberOfRows;
      qDebug()<<"numcolDataDos = "<<numcolDataDos;
      dataDos.append(alphadataDos);
      qDebug()<<"dataDos.size() = "<<dataDos.size();
      qDebug()<<"dataDos[0].size() = "<<dataDos[0].size();
    }

    qDebug() <<"PlotTransmDosDialog::on_outputDosButton_clicked() 7";
    qDebug()<<"PlotTransmDosDialog::on_outputDosButton_clicked() Writing Energy column to model";
    for (int i=0; i<magneticNumberOfRows; ++i){
        qDebug()<<"i = "<<i;
        QVariant varEnerDos(energyDos[i]);
        QStandardItem *elemEnerDos = new QStandardItem(varEnerDos.toString());
        standardItemListDos.append(elemEnerDos);
    }
    //model->insertColumn(1,standardItemList); // COMMENTED BY C.SALGADO ON 2016-08-03 TO AVOID PRINTING TRANSMISSION TWICE.
    modelDos->appendColumn(standardItemListDos); // ADDED BY C.SALGADO ON 2016-08-03 TO AVOID PRINTING TRANSMISSION TWICE.
    standardItemListDos.clear();
    qDebug() <<"PlotTransmDosDialog::on_outputDosButton_clicked() 8";
    qDebug()<<"PlotTransmDosDialog::on_outputDosButton_clicked() Writing Dos columns to model";
    for (int col=0; col<numcolDataDos; ++col){
      //for (int i=0; i<n; ++i){
      for (int i=0; i<magneticNumberOfRows; ++i){
        qDebug()<<"col"<<col<<"i = "<<i;
        QVariant varDos(dataDos[col][i]);
        //QStandardItem *elemTransm = new QStandardItem(dataTransmission[i]);
        QStandardItem *elemDos = new QStandardItem(varDos.toString());
        standardItemListDos.append(elemDos);
        //model->setItem(i,0,elemDos);
      }

    //modelDos->insertColumn(2,standardItemListDos);
      //modelDos->insertColumn(col+2,standardItemListDos);
      //modelDos->insertColumn(col+2,standardItemListDos);
      modelDos->appendColumn(standardItemListDos); // ADDED BY C.SALGADO ON 2016-08-03 TO AVOID PRINTING TRANSMISSION TWICE.
      standardItemListDos.clear();
    }
    qDebug() <<"PlotTransmDosDialog::on_outputDosButton_clicked() 9";

    //
    //model->appendColumn(dataTransmission);
    colDos = dataDos;
    enercolDos = energyDos;

    ui.outDosTableView->setModel(modelDos); // ADDED BY C.SALGADO ON 2016-08-03 TO AVOID PRINTING TRANSMISSION TWICE.

    //on_printDosButton_clicked();
    qDebug() <<"PlotTransmDosDialog::on_outputDosButton_clicked() 10";
    on_plotDosButton_clicked();

}


void PlotTransmDosDialog::modcheckStringPDos(QString &temp, QChar character)
{
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
        standardItemListPDos.append(item);
        if (character != QChar(',') && character != QChar(' ')) {
            //model->appendRow(standardItemList); // COMMENTED BY C.SALGADO ON 2016-08-03 TO AVOID CRASHES.
            auxmodelPDos->appendRow(standardItemListPDos); // COMMENTED BY C.SALGADO ON 2016-08-03 TO AVOID CRASHES.
            standardItemListPDos.clear();
        }
        temp.clear();
    } else {
        temp.append(character);
    }
}

void PlotTransmDosDialog::on_outputPDosButton_clicked()
{
    qDebug() <<"PlotTransmDosDialog::on_outputDosButton_clicked() 1";
    clearPlotPDosItems();

    //model = new QStandardItemModel(this); // COMMENTED BY C.SALGADO ON 2016-08-03 TO AVOID PRINTING TRANSMISSION TWICE.
    //ui.outDosTableView->setModel(model); // COMMENTED BY C.SALGADO ON 2016-08-03 TO AVOID PRINTING TRANSMISSION TWICE.
    //QStandardItemModel *auxmodel = new QStandardItemModel(1,1,this); //1 Rows and 1 Columns
    auxmodelPDos = new QStandardItemModel(this);
    //modelPDos = new QStandardItemModel(this);
    modelPDosAlpha = new QStandardItemModel();
    modelPDosBeta = new QStandardItemModel();

    //QString fileName = QFileDialog::getOpenFileName (this, "Open CSV file",
    //                                                 QDir::currentPath(), "CSV (*.csv)");
    qDebug() <<"PlotTransmDosDialog::on_outputPDosButton_clicked() 2";
    QString fileName = QFileDialog::getOpenFileName (this, "Open DAT file",
                                                     QDir::currentPath(), "DAT (*)");
    QFile file (fileName);
    if (file.open(QIODevice::ReadOnly)) {
        QString data = file.readAll();
        data.remove( QRegExp("\r") ); //remove all ocurrences of CR (Carriage Return)
        QString temp;
        QChar character;
        QTextStream textStream(&data);
        textStream.skipWhiteSpace();
        while (!textStream.atEnd()) {
          textStream >> character;
          if (character == ',') {
            modcheckStringPDos(temp, character);
            //modcheckString(auxmodel, temp, character);
            //} else if (character == '\0') {
            //    modcheckString(temp, character);
          } else if (character == QChar(' ')) {
            //textStream >> character;
            //textStream >> character;
            textStream.skipWhiteSpace();
            modcheckStringPDos(temp, character);
            //modcheckString(auxmodel, temp, character);
          } else if (character == QChar('\n')) {
            //newlinecount++;
            textStream.skipWhiteSpace();
            modcheckStringPDos(temp, character);
            //modcheckString(auxmodel, temp, character);
          } else if (textStream.atEnd()) {
            temp.append(character);
            modcheckStringPDos(temp);
            //modcheckString(auxmodel, temp);
          } else {
            temp.append(character);
          }
        }
        qDebug() <<"PlotTransmDosDialog:: temp"<<temp.toLatin1();
    }
    //MyClass::*modelDos = *model;
    qDebug() <<"PlotTransmDosDialog::on_outputPDosButton_clicked() 3"<< auxmodelPDos->item(1,1);
    //qDebug() << MyClass::s_count;
    qDebug() << s_count;



    qint32 n = auxmodelPDos->rowCount();
    qint32 m = auxmodelPDos->columnCount();
    //int n = model->rowCount();
    //int m = model->columnCount();
    qDebug() <<"PlotTransmDosDialog::on_outputPDosButton_clicked() 4 : "<< "n" << n << "m" << m ;

    //MyClass dataTransmission = new MyClass();
    //QList<float> dataTransmission = MyClass::colTransmission;
    //QList<double> dataTransmission = colTransmission;
    QList<QList<double>> dataPDos;
    QList<QList<double>> dataPDosAlpha;
    QList<QList<double>> dataPDosBeta;
    QList<double> alphadataPDos = singlespincolPDos;
    QList<double> betadataPDos = singlespincolPDos;
    QList<double> energyPDos = enercolPDos;
    int magneticNumberOfRows = 0;
    QList<QList<double>> pivotlist;

    //QList<bool> isMagneticPDos;
    //MyClass:: dataTransmission;

    qDebug() <<"PlotTransmDosDialog::on_outputTransmButton_clicked() 5";

    //QStandardItem *item = new QStandardItem(dataTransmission[0]);
    //QList< QStandardItem * > items;

    //stream << n << m;

    bool isMagneticPDos = false;
    //int numcolDataTransmission = 1;
    numcolDataPDos = 1;
    for (int jcol=0; jcol<m; ++jcol){
      isMagneticPDos = false;
      for (int i=0; i<n; ++i){
        //qDebug() << "model->data(model->index("<<i<<",0)).toString();" << model->data(model->index(i,0)).toString();
//        qDebug() << "auxmodel->data(model->index("<<i<<",0)).toFloat();" << auxmodelPDos->data(auxmodelPDos->index(i,0)).toFloat();
        //qDebug() << "model->data(model->index("<<i<<","<<jcol<<")).toString();" << model->data(model->index(i,1)).toString();
//        qDebug() << "auxmodel->data(auxmodel->index("<<i<<","<<jcol<<")).toFloat();" << auxmodelPDos->data(auxmodelPDos->index(i,jcol)).toDouble();
        //MyClass::dataTransmission << model->data(model->index(i,1)).toFloat();
        //dataTransmission << model->data(model->index(i,1)).toFloat();

        if(jcol==0){
          energyPDos << auxmodelPDos->data(auxmodelPDos->index(i,0)).toDouble();
        }else if(jcol>0){
          if(i==0){
            //dataTransmission.append(pivotlist);
            alphadataPDos << auxmodelPDos->data(auxmodelPDos->index(i,jcol)).toDouble();
//            qDebug()<<"alphdataTransmission["<<i<<"] = "<<alphadataPDos[i];
          }else if ((i>0) & ((auxmodelPDos->data(auxmodelPDos->index(i,0)).toDouble() > auxmodelPDos->data(auxmodelPDos->index(i-1,0)).toDouble()) & ~(isMagneticPDos))){
            //dataTransmission.append(pivotlist);
            alphadataPDos << auxmodelPDos->data(auxmodelPDos->index(i,jcol)).toDouble();
//            qDebug()<<"alphdataTransmission["<<i<<"] = "<<alphadataPDos[i];
          }else if((i>0) & (auxmodelPDos->data(auxmodelPDos->index(i,0)).toDouble() < auxmodelPDos->data(auxmodelPDos->index(i-1,0)).toDouble())){
            isMagneticPDos = true;
            numcolDataPDos = 2;
            magneticNumberOfRows = i;
            qDebug()<<"magneticNumberOfRows = "<<magneticNumberOfRows;
            //qDebug()<<"numcolDataTransmission = "<<numcolDataTransmission;
            //dataTransmission y0[col].resize(n);
            //dataTransmission[1].reserve(1);
            //dataTransmission.append(pivotlist);
            //qDebug()<<"dataTransmission.size() = "<<dataTransmission.size();
            //dataTransmission[1].append(model->data(model->index(i,1)).toDouble());
            betadataPDos << auxmodelPDos->data(auxmodelPDos->index(i,jcol)).toDouble();
            //qDebug()<<"betadataTransmission["<<0<<"] = "<<betadataTransmission[0];
//            qDebug()<<"betadataTransmission["<<i-magneticNumberOfRows<<"] = "<<betadataPDos[i-magneticNumberOfRows];
          }else if ((i>0) & ((auxmodelPDos->data(auxmodelPDos->index(i,0)).toDouble() > auxmodelPDos->data(auxmodelPDos->index(i-1,0)).toDouble()) & (isMagneticPDos))){
            betadataPDos << auxmodelPDos->data(auxmodelPDos->index(i,jcol)).toDouble();
//            qDebug()<<"betadataTransmission["<<i-magneticNumberOfRows<<"] = "<<betadataPDos[i-magneticNumberOfRows];
          }
        }
      }

      qDebug() <<"PlotTransmDosDialog::on_outputPDosButton_clicked() 6";

      if(jcol!=0){
        //if(~(isMagneticPDos)){
        if(numcolDataPDos == 1){
          qDebug()<<"numcolDataPDos = "<<numcolDataPDos;
          //numcolDataPDos = 1;
          //magneticNumberOfRows = n; // COMMENTED BY C.SALGADO 2016-08-04.
          magneticNumberOfRows = alphadataPDos.size();
          //dataPDos.append(alphadataPDos);
          qDebug()<<"magneticNumberOfRows = "<<magneticNumberOfRows;
          qDebug()<<"numcolDataPDos = "<<numcolDataPDos;
          dataPDos.append(alphadataPDos);
          dataPDosAlpha.append(alphadataPDos);
          qDebug()<<"dataPDos.size() = "<<dataPDos.size();
          qDebug()<<"dataPDos[0].size() = "<<dataPDos[0].size();
        }else if(numcolDataPDos == 2){
          //numcolDataPDos = 2;
          //dataPDos << alphadataPDos<<betadataPDos;
          //dataPDos.append(alphadataPDos);
          //dataPDos.append(betadataPDos);
          qDebug()<<"magneticNumberOfRows = "<<magneticNumberOfRows;
          qDebug()<<"numcolDataPDos = "<<numcolDataPDos;
          //dataPDos.append(alphadataPDos);
          //dataPDos.append(betadataPDos);
          dataPDosAlpha.append(alphadataPDos);
          dataPDosBeta.append(betadataPDos);
          //qDebug()<<"dataPDos.size() = "<<dataPDos.size();
          //qDebug()<<"dataPDos[0].size() = "<<dataPDos[0].size();
          //qDebug()<<"dataPDos[1].size() = "<<dataPDos[1].size();
        }else{
          //numcolDataPDos = 1;
          //magneticNumberOfRows = n; // COMMENTED BY C.SALGADO 2016-08-04.
          magneticNumberOfRows = alphadataPDos.size();
          //dataPDos.append(alphadataPDos);
          qDebug()<<"magneticNumberOfRows = "<<magneticNumberOfRows;
          qDebug()<<"numcolDataPDos = "<<numcolDataPDos;
          //dataPDos.append(alphadataPDos);
          //dataPDosAlpha.append(alphadataPDos); // COMMENTED ON 2016-08-09 TO MAINTAIN CORRECT NUMCOL IN DATAPDOSALPHA.
          //dataPDosBeta.append(betadataPDos); // COMMENTED ON 2016-08-09 TO MAINTAIN CORRECT NUMCOL IN DATAPDOSALPHA.
          qDebug()<<"dataPDos.size() = "<<dataPDos.size();
          qDebug()<<"dataPDos[0].size() = "<<dataPDos[0].size();
        }
        alphadataPDos.clear();
        betadataPDos.clear();
      }
    }


    qDebug() <<"PlotTransmPDosDialog::on_outputPDosButton_clicked() 7";
    qDebug()<<"PlotTransmPDosDialog::on_outputPDosButton_clicked() Writing Energy column to model";
    for (int i=0; i<magneticNumberOfRows; ++i){
//        qDebug()<<"i = "<<i;
        QVariant varEnerPDos(energyPDos[i]);
        QStandardItem *elemEnerPDos = new QStandardItem(varEnerPDos.toString());
        standardItemListPDos.append(elemEnerPDos);
        QStandardItem *elemEnerPDosAlpha = new QStandardItem(varEnerPDos.toString());
        standardItemListPDosAlpha.append(elemEnerPDosAlpha);
        if(numcolDataPDos == 2){
          QStandardItem *elemEnerPDosBeta = new QStandardItem(varEnerPDos.toString());
          standardItemListPDosBeta.append(elemEnerPDosBeta);
        }
    }
    //model->insertColumn(1,standardItemList); // COMMENTED BY C.SALGADO ON 2016-08-03 TO AVOID PRINTING TRANSMISSION TWICE.
    //modelPDos->appendColumn(standardItemListPDos); // ADDED BY C.SALGADO ON 2016-08-03 TO AVOID PRINTING TRANSMISSION TWICE.
    modelPDosAlpha->appendColumn(standardItemListPDosAlpha); // ADDED BY C.SALGADO ON 2016-08-03 TO AVOID PRINTING TRANSMISSION TWICE.
    if(numcolDataPDos == 2){
      modelPDosBeta->appendColumn(standardItemListPDosBeta); // ADDED BY C.SALGADO ON 2016-08-03 TO AVOID PRINTING TRANSMISSION TWICE.
    }
    standardItemListPDos.clear();
    standardItemListPDosAlpha.clear();
    standardItemListPDosBeta.clear();
    qDebug() <<"PlotTransmPDosDialog::on_outputPDosButton_clicked() 8";
    qDebug()<<"PlotTransmDosDialog::on_outputPDosButton_clicked() Writing PDos columns to model";

    //for (int col=0; col<numcolDataPDos; ++col){
    //for (int jcol=1; jcol<dataPDosAlpha.size(); ++jcol){
    for (int jcol=0; jcol<dataPDosAlpha.size(); ++jcol){
      //for (int i=0; i<n; ++i){
      for (int i=0; i<magneticNumberOfRows; ++i){
//        qDebug()<<"Alpha: jcol = "<<jcol<<"; i = "<<i;
//        qDebug()<<"dataPDosAlpha["<<jcol<<"].size() ="<<dataPDosAlpha[jcol].size();
//        qDebug()<<"dataPDosAlpha[jcol][i] ="<<dataPDosAlpha[jcol][i];
        QVariant varPDosAlpha(dataPDosAlpha[jcol][i]);
        //QVariant varPDos(dataPDos[i][jcol]);
        //QStandardItem *elemTransm = new QStandardItem(dataTransmission[i]);
        QStandardItem *elemPDosAlpha = new QStandardItem(varPDosAlpha.toString());

        standardItemListPDosAlpha.append(elemPDosAlpha);
        //model->setItem(i,0,elemPDos);
      }

    //modelPDos->insertColumn(2,standardItemListPDos);
      //modelPDos->insertColumn(col+2,standardItemListPDos);
      //modelPDos->insertColumn(col+2,standardItemListPDos);
      modelPDosAlpha->appendColumn(standardItemListPDosAlpha); // ADDED BY C.SALGADO ON 2016-08-03 TO AVOID PRINTING TRANSMISSION TWICE.
      standardItemListPDosAlpha.clear();
    }

    if(numcolDataPDos == 2){
      for (int jcol=0; jcol<dataPDosBeta.size(); ++jcol){
        for (int i=0; i<magneticNumberOfRows; ++i){
//          qDebug()<<"Beta: jcol = "<<jcol<<"; i = "<<i;
//          qDebug()<<"dataPDosBeta["<<jcol<<"].size() ="<<dataPDosBeta[jcol].size();
          QVariant varPDosBeta(dataPDosBeta[jcol][i]);
          //QVariant varPDos(dataPDos[i][jcol]);
          //QStandardItem *elemTransm = new QStandardItem(dataTransmission[i]);
          QStandardItem *elemPDosBeta = new QStandardItem(varPDosBeta.toString());
          standardItemListPDosBeta.append(elemPDosBeta);
          //model->setItem(i,0,elemPDos);
        }

        modelPDosBeta->appendColumn(standardItemListPDosBeta); // ADDED BY C.SALGADO ON 2016-08-03 TO AVOID PRINTING TRANSMISSION TWICE.
        standardItemListPDosBeta.clear();
      }
    }


    if(numcolDataPDos == 2){
      //ui.groupBoxPDosBeta->show();
      //ui.groupBoxPDosAlpha->setTitle("Spin Up");

      ui.outPDosAlphaTableView->setModel(modelPDosAlpha); // ADDED BY C.SALGADO ON 2016-08-03 TO AVOID PRINTING TRANSMISSION TWICE.
      ui.outPDosBetaTableView->setModel(modelPDosBeta); // ADDED BY C.SALGADO ON 2016-08-03 TO AVOID PRINTING TRANSMISSION TWICE.

      connect(ui.outPDosAlphaTableView->selectionModel(),SIGNAL(selectionChanged(QItemSelection selected,QItemSelection deselected)),this,SLOT(on_outputPDosAlphaColumn_selected()));
      //connect(ui.outPDosAlphaTableView->selectionModel(),SIGNAL()
      connect(ui.outPDosAlphaTableView->selectionModel(), SIGNAL(currentChanged(const QModelIndex &, const QModelIndex &)), this, SLOT(on_outputPDosAlphaColumn_selected()));

      connect(ui.outPDosBetaTableView->selectionModel(),SIGNAL(selectionChanged(QItemSelection selected,QItemSelection deselected)),this,SLOT(on_outputPDosBetaColumn_selected()));
      connect(ui.outPDosBetaTableView->selectionModel(), SIGNAL(currentChanged(const QModelIndex &, const QModelIndex &)), this, SLOT(on_outputPDosBetaColumn_selected()));


      colPDosAlpha = dataPDosAlpha;
      colPDosBeta = dataPDosBeta;
      enercolPDos = energyPDos;
    }else{
      //ui.groupBoxPDosBeta->hide();
      //ui.groupBoxPDosAlpha->setTitle("Spin Up+Down");

      ui.outPDosAlphaTableView->setModel(modelPDosAlpha); // ADDED BY C.SALGADO ON 2016-08-03 TO AVOID PRINTING TRANSMISSION TWICE.

      connect(ui.outPDosAlphaTableView->selectionModel(),SIGNAL(selectionChanged(QItemSelection selected,QItemSelection deselected)),this,SLOT(on_outputPDosAlphaColumn_selected()));
      //connect(ui.outPDosAlphaTableView->selectionModel(),SIGNAL()
      connect(ui.outPDosAlphaTableView->selectionModel(), SIGNAL(currentChanged(const QModelIndex &, const QModelIndex &)), this, SLOT(on_outputPDosAlphaColumn_selected()));

      colPDosAlpha = dataPDosAlpha;
      enercolPDos = energyPDos;
    }
    qDebug() <<"PlotTransmDosDialog::on_outputPDosButton_clicked() 9";

    //
    //model->appendColumn(dataTransmission);
    //colPDosAlpha = dataPDosAlpha;
    //enercolPDos = energyPDos;

    //ui.outPDosAlphaTableView->setModel(modelPDos); // ADDED BY C.SALGADO ON 2016-08-03 TO AVOID PRINTING TRANSMISSION TWICE.

    //on_printPDosButton_clicked();
    qDebug() <<"PlotTransmPDosDialog::on_outputPDosButton_clicked() 10";
    //on_plotPDosButton_clicked();
}

void PlotTransmDosDialog::on_printTransmButton_clicked()
{
    //------------------------------------------------------------
    QList<QList<double>> dataTransmission = colTransmission;
    //------------------------------------------------------------

    //QStandardItemModel *model = new QStandardItemModel(2,3,this); //2 Rows and 3 Columns
    //QStandardItemModel *model = new QStandardItemModel(1,1,this); //1 Rows and 1 Columns  // COMMENTED BY C.SALGADO ON 2016-08-03 TO AVOID PRINTING TRANSMISSION TWICE.

    model->setHorizontalHeaderItem(0, new QStandardItem(QString("Column1 Header")));
    //model->setHorizontalHeaderItem(1, new QStandardItem(QString("Column2 Header")));
    //model->setHorizontalHeaderItem(2, new QStandardItem(QString("Column3 Header")));

    /*
    QStandardItem *firstRow = new QStandardItem(QString("ColumnValue"));
    */

    qint32 numcolDataTransmission = dataTransmission.size();
    qint32 n = dataTransmission[0].size();
    //------------------------------------------------------------
    //QList<float> dataTransmission = MyClass::colTransmission;
    //QList<QVariant> varTransmission(dataTransmission);
    //QList<QString> strTransmission = varTransmission.toString();
//    QStandardItem *elemTransm = new QStandardItem(dataTransmission[0]);
    //QList<QStandardItem> *colTransm = new QStandardItem(dataTransmission);
    //------------------------------------------------------------
    for (int col=0; col<numcolDataTransmission; ++col){
      for (int i=0; i<n; ++i){
        QVariant varTransmission(dataTransmission[col][i]);
        //QStandardItem *elemTransm = new QStandardItem(dataTransmission[i]);
        QStandardItem *elemTransm = new QStandardItem(varTransmission.toString());
        //QStandardItem *elemTransm = new QStandardItem(varTransmission.toFloat()); // toFloat() does not work!!!
        //QStandardItem *elemTransm = new QStandardItem(varTransmission.toDouble());
        model->setItem(i,0,elemTransm);
      }

    }

    //model->setItem(0,0,firstRow);
    //model->insertColumn(1,colTransm);

    //ui.printTransmTableView->setModel(model); // COMMENTED BY C.SALGADO TO AVOID PRINTING TRANSMISSION TWICE.
    //ui.outTransmTableView->setModel(model);

}

void PlotTransmDosDialog::on_plotTransmButton_clicked_old(){
  qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 1";
  QList<QList<double>> dataTransmission = colTransmission;
  QList<double> enerdataTransmission = enercolTransmission;
  //QVariant varTransmission(dataTransmission[i]);
  qint32 numcolDataTransmission = dataTransmission.size();
  qint32 n = dataTransmission[0].size();
  QVector<double> x(n), y1(n);
  QVector<QVector<double>> y0(numcolDataTransmission);
  for (int col=0; col<numcolDataTransmission; ++col){
    y0[col].resize(n);
  }
  qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 2. dataTransmission.size() = "<<dataTransmission.size();


  for (int i=0; i<n; ++i){
    x[i] = enerdataTransmission[i];
    for (int col=0; i<numcolDataTransmission; ++col){
      y0[col][i] = dataTransmission[col][i];
      //y1[i] = qExp(-x[i]*x[i]*0.25)*5;
    }
  }


  // Set up a 2D scene, add an XY chart to it
  //VTK_CREATE(vtkContextView, viewTransm);
  vtkNew<vtkContextView> viewTransm;
    viewTransm->GetRenderWindow()->SetSize(400, 300);
  vtkNew<vtkChartXY> chartTransm;
    //vtkNew<vtkChartXY> chart;

    //chartTransm = vtkSmartPointer<vtkChartXY>::New();

    //this->

  viewTransm->GetScene()->AddItem(chartTransm.GetPointer());


    qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 3";

    // Create a table with some points in it...
    vtkNew<vtkTable> tableTransm;
    vtkNew<vtkFloatArray> arrTransmX;
    arrTransmX->SetName("X Axis");
    tableTransm->AddColumn(arrTransmX.GetPointer());
    vtkNew<vtkFloatArray> arrTransmC;
    arrTransmC->SetName("Transmission");
    tableTransm->AddColumn(arrTransmC.GetPointer());
    //vtkNew<vtkFloatArray> arrS;
    //arrS->SetName("Sine");
    //table->AddColumn(arrS.GetPointer());
    //vtkNew<vtkFloatArray> arrS2;
    //arrS2->SetName("Sine2");
    //table->AddColumn(arrS2.GetPointer());
    //vtkNew<vtkFloatArray> arrS3;
    //arrS3->SetName("Sine3");
    //table->AddColumn(arrS3.GetPointer());
    //vtkNew<vtkFloatArray> arr1;
    //arr1->SetName("One");
    //table->AddColumn(arr1.GetPointer());

    vtkNew<vtkCharArray> validMaskTransm;
    validMaskTransm->SetName("TransmMask");
    tableTransm->AddColumn(validMaskTransm.GetPointer());

    qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 4";

    // Test charting with a few more points...
    //int numPoints = 69;
    int numPoints = n;
    float inc = 7.5 / (numPoints-1);
    tableTransm->SetNumberOfRows(numPoints);
    for (int i = 0; i < numPoints; ++i){
      //table->SetValue(i, 0, i * inc + 0.01);
      //table->SetValue(i, 1, cos(i * inc) + 0.01);
      //table->SetValue(i, 2, sin(i * inc) + 0.01);
      //table->SetValue(i, 3, sin(i * inc) + 0.5);
      //table->SetValue(i, 4, sin(i * inc) * sin(i * inc) + 0.01);
      //table->SetValue(i, 5, 1.0);

      //validMask->SetValue(i, (i > 30 && i < 40) ? 0 : 1);

      tableTransm->SetValue(i, 0, x[i] + 0.01);
      tableTransm->SetValue(i, 1, y0[0][i] + 0.01);

      validMaskTransm->SetValue(i,1);

      qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() i=0,1,numPoints; i = "<<i;
      }

    // Add multiple line plots, setting the colors etc
    //vtkPlotArea* area = vtkPlotArea::SafeDownCast(chart->AddPlot(vtkChart::AREA));
    areaTransm = vtkPlotArea::SafeDownCast(chartTransm->AddPlot(vtkChart::AREA));
    areaTransm->SetInputData(tableTransm.GetPointer());
    areaTransm->SetInputArray(0, "X Axis");
    areaTransm->SetInputArray(1, "Transmission");
    //areaTransm->SetInputArray(2, "Sine2");
    areaTransm->SetValidPointMaskName("TransmMask");
    //area->GetBrush()->SetColorF(0.5, 0.5, 0.5, 0.5);
    areaTransm->GetBrush()->SetColorF(0.0, 0.0, 1.0, 1.0);
    //chartTransm->GetAxis(vtkAxis::LEFT)->SetLogScale(true); // COMMENT LOGARITHMIC SCALE BY C.SALGADO.
    //chartTransm->GetAxis(vtkAxis::RIGHT)->SetLogScale(true); // ORIGINALLY COMMENTED LOGARITHMIC SCALE BY C.SALGADO.


    qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 5";
    //vtkNew<vtkAxis> xAxis;

    //xAxis = chart->GetAxis(vtkAxis::LEFT);

    //chart->GetAxis(0)->SetUnscaledRange();

    // Render the scene and compare the image to a reference image
    viewTransm->GetRenderWindow()->SetMultiSamples(0);
    //view->GetInteractor()->Initialize();
    //view->GetInteractor()->Start();

    connect(ui.horizontalSliderqvtkWidget3, SIGNAL(valueChanged(int)), this, SLOT(setTransmXRange(int)));
    connect(ui.verticalSliderqvtkWidget3, SIGNAL(valueChanged(int)), this, SLOT(setTransmYRange(int)));
    //connect(ui.horizontalSliderqvtkWidget2, SIGNAL(sliderMoved(int)), this, SLOT(setXRange(int)));
    //connect(ui.verticalSliderqvtkWidget2, SIGNAL(sliderMoved(int)), this, SLOT(setYRange(int)));
    //connect(ui.horizontalSliderqvtkWidget2, SIGNAL(sliderMoved(int)), this, SLOT(view->Update()));
    //connect(ui.verticalSliderqvtkWidget2, SIGNAL(sliderMoved(int)), this, SLOT(view->Update()));
    //connect(ui.autoScaleButton3, SIGNAL(clicked()), this, SLOT(autoScalePlot(int)));

    // Graph View needs to get my render window
    //viewTransm->SetInteractor(ui.qvtkWidget3->GetInteractor());
    //ui.qvtkWidget3->SetRenderWindow(viewTransm->GetRenderWindow());

    //areaTransm->Update();
    //qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 6";
    //viewTransm->Update();
    //qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 7";
    //chartTransm->Update();
    //qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 8";
    //ui.qvtkWidget3->update();

    //viewTransm->Render();

    qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 9";

    //this->ui->qvtkWidget2->SetRenderWindow(view->GetRenderWindow());
    //this->ui->qvtkWidget2->Set
    viewTransm->GetInteractor()->Initialize();
    viewTransm->GetInteractor()->Start();
    viewTransm->Render();

    originalTransmXsize = (double)(chartTransm->GetAxis(0)->GetMaximum() - chartTransm->GetAxis(0)->GetMinimum());
    originalTransmYsize = (double)(chartTransm->GetAxis(1)->GetMaximum() - chartTransm->GetAxis(1)->GetMinimum());

    qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 10";
}


void PlotTransmDosDialog::on_plotAreaTransmButton_clicked(){
// TRANSMISSION PLOT.
qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 1";
QList<QList<double>> dataTransmission = colTransmission;
QList<double> enerdataTransmission = enercolTransmission;
//QVariant varTransmission(dataTransmission[i]);
qint32 numcolDataTransmission = dataTransmission.size();
int n = dataTransmission[0].size();
QVector<float> x(n), y1(n);
QVector<QVector<float>> y0(numcolDataTransmission);
for (int col=0; col<numcolDataTransmission; ++col){
  y0[col].resize(n);
}
//vtkNew<vtkFloatArray> xvtkfloat;
//vtkNew<vtkFloatArray> y0vtkfloat;
qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 2. dataTransmission.size() = "<<dataTransmission.size();
//xvtkfloat->SetNumberOfComponents(n);
//y0vtkfloat->SetNumberOfComponents(n);
for (int i=0; i<n; ++i)        {
  x[i] = (float)enerdataTransmission[i];
  //xvtkfloat->SetValue(i,(float)enerdataTransmission[i]);
  for (int col=0; col<numcolDataTransmission; ++col){
    y0[col][i] = (float)dataTransmission[col][i];
    qDebug()<<"dataTransmission["<<col<<"]["<<i<<"] = "<< dataTransmission[col][i];
  }
  /*
  if(fabs(dataTransmission[col][i])<10.0){
    y0[i] = (float)dataTransmission[i];
    //y0vtkfloat->SetValue(i,(float)dataTransmission[i]);
  }else{
    y0[i] = (float)0.0;
    //y0vtkfloat->SetValue(i,(float)0.0);
  }
  */

  //y1[i] = qExp(-x[i]*x[i]*0.25)*5;
}

// Set up a 2D scene, add an XY chart to it
VTK_CREATE(vtkContextView, viewTransm);
//vtkNew<vtkContextView> view;
  viewTransm->GetRenderWindow()->SetSize(400, 300);
  //vtkNew<vtkChartXY> chart;
  //vtkNew<vtkChartXY> chart;

  vtkSmartPointer<vtkChartXY> chartTransm =
          vtkSmartPointer<vtkChartXY>::New();

  //this->

  viewTransm->GetScene()->AddItem(chartTransm.GetPointer());

  qDebug()<<"PlotTransmDosDialog::PlotTransmDosDialog() 3";

  // Create a table with some points in it...
  vtkNew<vtkTable> table;
  //vtkNew<vtkTable> tableTransm;
  vtkNew<vtkFloatArray> arrTransmX;
  arrTransmX->SetName("X Axis");
  table->AddColumn(arrTransmX.GetPointer());

  vtkNew<vtkFloatArray> arrTransmC;
  arrTransmC->SetName("Cosine");
  table->AddColumn(arrTransmC.GetPointer());

  vtkNew<vtkFloatArray> AlphaTransmUp;
  AlphaTransmUp->SetName("AlphaTransmUp");
  table->AddColumn(AlphaTransmUp.GetPointer());

  vtkNew<vtkFloatArray> AlphaTransmDown;
  AlphaTransmDown->SetName("AlphaTransmDown");
  table->AddColumn(AlphaTransmDown.GetPointer());

  vtkNew<vtkFloatArray> BetaTransmUp;
  BetaTransmUp->SetName("BetaTransmUp");
  table->AddColumn(BetaTransmUp.GetPointer());

  vtkNew<vtkFloatArray> BetaTransmDown;
  BetaTransmDown->SetName("BetaTransmDown");
  table->AddColumn(BetaTransmDown.GetPointer());
  /*
  vtkNew<vtkFloatArray> arrS;
  arrS->SetName("Sine");
  table->AddColumn(arrS.GetPointer());
  vtkNew<vtkFloatArray> arrS2;
  arrS2->SetName("Sine2");
  table->AddColumn(arrS2.GetPointer());
  vtkNew<vtkFloatArray> arrS3;
  arrS3->SetName("Sine3");
  table->AddColumn(arrS3.GetPointer());
  vtkNew<vtkFloatArray> arr1;
  arr1->SetName("One");
  table->AddColumn(arr1.GetPointer());

  vtkNew<vtkFloatArray> Energy;
  Energy->SetName("Energy");
  table->AddColumn(Energy.GetPointer());
  */


  vtkNew<vtkCharArray> validMask;
  validMask->SetName("ValidMask");
  table->AddColumn(validMask.GetPointer());
  //tableTransm->AddColumn(validMaskTransm.GetPointer());

  qDebug()<<"PlotTransmDosDialog::PlotTransmDosDialog() 4";

  // Test charting with a few more points...
  int numPoints = 69;
  //int numPoints = n;
  float inc = 7.5 / (n-1);


  table->SetNumberOfRows(n);
  for (int i = 0; i < n; ++i){
    table->SetValue(i, 0, i * inc + 0.01);
    //table->SetValue(i, 1, (float)(x[i]));
    //table->SetValue(i, 1, cos(i * inc) + 0.01);
    //table->SetValue(i, 1, 0.01*cos(i * inc) + 0.01);
    //table->SetValue(i, 1, 0.0001 + 0.0001);
    table->SetValue(i, 1, y0[0][i] - 0.01);
    //table->SetValue(i, 6, sin(i * inc) + 0.01);
    //table->SetValue(i, 3, sin(i * inc) + 0.5);
    //table->SetValue(i, 4, sin(i * inc) * sin(i * inc) + 0.01);
    //table->SetValue(i, 5, 1.0);

    //validMask->SetValue(i, (i > 30 && i < 40) ? 0 : 1);

    //table->SetValue(i, 0, x[i] + 0.01);
    //table->SetValue(i, 2, (float)(y0[i]));
    table->SetValue(i, 2, y0[0][i]);
    /*
    if(fabs(y0[i])<10.0){
      table->SetValue(i, 1, (float)(y0[i]));
      //table->SetValue(i, 2, y0vtkfloat->GetValue(i));
    }else{
      table->SetValue(i, 1, 0.0);
    }
    */

    if(y0.size() == 2){
      table->SetValue(i, 3, -y0[1][i]);
      table->SetValue(i, 4, -y0[1][i] - 0.01);
    }

    //validMaskTransm->SetValue(i,1);
    //validMaskTransm->SetValue(i, (i > 3 && i < 4) ? 0 : 1);

    validMask->SetValue(i,1);

    //qDebug()<<"i=0,1,numPoints; i = "<<i;
    qDebug()<<"table->GetValue("<<i<<",2) = "<<table->GetValue(i,2).ToFloat();
    }

  // Add multiple line plots, setting the colors etc
  //vtkPlotArea* area = vtkPlotArea::SafeDownCast(chart->AddPlot(vtkChart::AREA));
  areaTransm = vtkPlotArea::SafeDownCast(chartTransm->AddPlot(vtkChart::AREA));
  areaTransm->SetInputData(table.GetPointer());
  //areaTransm->SetInputData(tableTransm.GetPointer());
  areaTransm->SetInputArray(0, "X Axis");
  //areaTransm->SetInputArray(1, "Energy");
  //areaTransm->SetInputArray(1, "Cosine");
  areaTransm->SetInputArray(1, "AlphaTransmUp");
  areaTransm->SetInputArray(2, "AlphaTransmDown");
  //areaTransm->SetInputArray(6, "Sine");
  //areaTransm->SetInputArray(3, "Sine2");
  //areaTransm->SetInputArray(4, "Sine3");
  //areaTransm->SetInputArray(5, "One");
  areaTransm->SetInputArray(3, "BetaTransmUp");
  areaTransm->SetInputArray(4, "BetaTransmDown");
  //areaTransm->SetInputArray(2, "Transm");

  areaTransm->SetValidPointMaskName("ValidMask");
  //area->GetBrush()->SetColorF(0.5, 0.5, 0.5, 0.5);
  areaTransm->GetBrush()->SetColorF(0.0, 0.0, 1.0, 1.0);
  //chart->GetAxis(vtkAxis::LEFT)->SetLogScale(true); // COMMENT LOGARITHMIC SCALE BY C.SALGADO.
  //chart->GetAxis(vtkAxis::RIGHT)->SetLogScale(true); // ORIGINALLY COMMENTED LOGARITHMIC SCALE BY C.SALGADO.



  qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 5";
  //vtkNew<vtkAxis> xAxis;

  //xAxis = chart->GetAxis(vtkAxis::LEFT);

  //chart->GetAxis(0)->SetUnscaledRange();

  // Render the scene and compare the image to a reference image
  viewTransm->GetRenderWindow()->SetMultiSamples(0);
  //view->GetInteractor()->Initialize();
  //view->GetInteractor()->Start();

  //connect(ui.horizontalSliderqvtkWidget3, SIGNAL(valueChanged(int)), this, SLOT(setTransmXRange(int)));
  //connect(ui.verticalSliderqvtkWidget3, SIGNAL(valueChanged(int)), this, SLOT(setTransmYRange(int)));
  //connect(ui.horizontalSliderqvtkWidget2, SIGNAL(sliderMoved(int)), this, SLOT(setXRange(int)));
  //connect(ui.verticalSliderqvtkWidget2, SIGNAL(sliderMoved(int)), this, SLOT(setYRange(int)));
  //connect(ui.horizontalSliderqvtkWidget2, SIGNAL(sliderMoved(int)), this, SLOT(view->Update()));
  //connect(ui.verticalSliderqvtkWidget2, SIGNAL(sliderMoved(int)), this, SLOT(view->Update()));
  //connect(ui.autoScaleButton3, SIGNAL(clicked()), this, SLOT(autoScalePlot(int)));

  // Graph View needs to get my render window
  //viewTransm->SetInteractor(this->ui.qvtkWidget3->GetInteractor());
  //this->ui.qvtkWidget3->SetRenderWindow(viewTransm->GetRenderWindow());
  viewTransm->SetInteractor(ui.qvtkWidget3->GetInteractor());
  ui.qvtkWidget3->SetRenderWindow(viewTransm->GetRenderWindow());

  qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 6";

  //this->ui->qvtkWidget2->SetRenderWindow(view->GetRenderWindow());
  //this->ui->qvtkWidget2->Set
  //view->GetInteractor()->Initialize();
  viewTransm->GetInteractor()->Start();
  viewTransm->Render();

  originalTransmXsize = (double)(chartTransm->GetAxis(1)->GetMaximum() - chartTransm->GetAxis(1)->GetMinimum());
  originalTransmYsize = (double)(chartTransm->GetAxis(0)->GetMaximum() - chartTransm->GetAxis(0)->GetMinimum());

  qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 7";

}

void PlotTransmDosDialog::on_plotLinesDirtyTransmButton_clicked(){
// TRANSMISSION PLOT.
qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 1";
QList<QList<double>> dataTransmission = colTransmission;
QList<double> enerdataTransmission = enercolTransmission;
//QVariant varTransmission(dataTransmission[i]);
qint32 numcolDataTransmission = dataTransmission.size();
int n = dataTransmission[0].size();
QVector<float> x(n), y1(n);
QVector<QVector<float>> y0(numcolDataTransmission);
for (int col=0; col<numcolDataTransmission; ++col){
  y0[col].resize(n);
}
//vtkNew<vtkFloatArray> xvtkfloat;
//vtkNew<vtkFloatArray> y0vtkfloat;
qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 2. dataTransmission.size() = "<<dataTransmission.size();
//xvtkfloat->SetNumberOfComponents(n);
//y0vtkfloat->SetNumberOfComponents(n);
for (int i=0; i<n; ++i)        {
  x[i] = (float)enerdataTransmission[i];
  //xvtkfloat->SetValue(i,(float)enerdataTransmission[i]);
  for (int col=0; col<numcolDataTransmission; ++col){
    y0[col][i] = (float)dataTransmission[col][i];
    qDebug()<<"dataTransmission["<<col<<"]["<<i<<"] = "<< dataTransmission[col][i];
  }
  /*
  if(fabs(dataTransmission[col][i])<10.0){
    y0[i] = (float)dataTransmission[i];
    //y0vtkfloat->SetValue(i,(float)dataTransmission[i]);
  }else{
    y0[i] = (float)0.0;
    //y0vtkfloat->SetValue(i,(float)0.0);
  }
  */

  //y1[i] = qExp(-x[i]*x[i]*0.25)*5;
}

// Set up a 2D scene, add an XY chart to it
VTK_CREATE(vtkContextView, viewTransm);
//vtkNew<vtkContextView> view;
  viewTransm->GetRenderWindow()->SetSize(400, 300);
  //vtkNew<vtkChartXY> chart;
  //vtkNew<vtkChartXY> chart;

  chartTransm = vtkSmartPointer<vtkChartXY>::New();

  //this->

  viewTransm->GetScene()->AddItem(chartTransm.GetPointer());

  qDebug()<<"PlotTransmDosDialog::PlotTransmDosDialog() 3";

  // Create a table with some points in it...
  //vtkNew<vtkTable> table;
  vtkSmartPointer<vtkTable> table =
      vtkSmartPointer<vtkTable>::New();
  //vtkNew<vtkTable> tableTransm;
  vtkNew<vtkFloatArray> arrTransmX;
  arrTransmX->SetName("X Axis");
  table->AddColumn(arrTransmX.GetPointer());

  vtkNew<vtkFloatArray> arrTransmC;
  arrTransmC->SetName("Cosine");
  table->AddColumn(arrTransmC.GetPointer());

  vtkNew<vtkFloatArray> AlphaTransmUp;
  AlphaTransmUp->SetName("AlphaTransmUp");
  table->AddColumn(AlphaTransmUp.GetPointer());

  vtkNew<vtkFloatArray> AlphaTransmDown;
  AlphaTransmDown->SetName("AlphaTransmDown");
  table->AddColumn(AlphaTransmDown.GetPointer());

  vtkNew<vtkFloatArray> BetaTransmUp;
  BetaTransmUp->SetName("BetaTransmUp");
  table->AddColumn(BetaTransmUp.GetPointer());

  vtkNew<vtkFloatArray> BetaTransmDown;
  BetaTransmDown->SetName("BetaTransmDown");
  table->AddColumn(BetaTransmDown.GetPointer());
  /*
  vtkNew<vtkFloatArray> arrS;
  arrS->SetName("Sine");
  table->AddColumn(arrS.GetPointer());
  vtkNew<vtkFloatArray> arrS2;
  arrS2->SetName("Sine2");
  table->AddColumn(arrS2.GetPointer());
  vtkNew<vtkFloatArray> arrS3;
  arrS3->SetName("Sine3");
  table->AddColumn(arrS3.GetPointer());
  vtkNew<vtkFloatArray> arr1;
  arr1->SetName("One");
  table->AddColumn(arr1.GetPointer());

  vtkNew<vtkFloatArray> Energy;
  Energy->SetName("Energy");
  table->AddColumn(Energy.GetPointer());
  */


  vtkNew<vtkCharArray> validMask;
  validMask->SetName("ValidMask");
  table->AddColumn(validMask.GetPointer());
  //tableTransm->AddColumn(validMaskTransm.GetPointer());

  qDebug()<<"PlotTransmDosDialog::PlotTransmDosDialog() 4";

  // Test charting with a few more points...
  int numPoints = 69;
  //int numPoints = n;
  float inc = 7.5 / (n-1);


  table->SetNumberOfRows(n);
  for (int i = 0; i < n; ++i){
    table->SetValue(i, 0, i * inc + 0.01);
    //table->SetValue(i, 1, (float)(x[i]));
    //table->SetValue(i, 1, cos(i * inc) + 0.01);
    //table->SetValue(i, 1, 0.01*cos(i * inc) + 0.01);
    //table->SetValue(i, 1, 0.0001 + 0.0001);
    table->SetValue(i, 1, y0[0][i] - 0.01);
    //AlphaTransmUp->SetValue(i,-y0[1][i]);
    //table->SetValue(i, 6, sin(i * inc) + 0.01);
    //table->SetValue(i, 3, sin(i * inc) + 0.5);
    //table->SetValue(i, 4, sin(i * inc) * sin(i * inc) + 0.01);
    //table->SetValue(i, 5, 1.0);

    //validMask->SetValue(i, (i > 30 && i < 40) ? 0 : 1);

    //table->SetValue(i, 0, x[i] + 0.01);
    //table->SetValue(i, 2, (float)(y0[i]));
    //table->SetValue(i, 2, y0[0][i]);
    /*
    if(fabs(y0[i])<10.0){
      table->SetValue(i, 1, (float)(y0[i]));
      //table->SetValue(i, 2, y0vtkfloat->GetValue(i));
    }else{
      table->SetValue(i, 1, 0.0);
    }
    */

    if(y0.size() == 2){
      table->SetValue(i, 2, -y0[1][i]);
      //BetaTransmUp->SetValue(i,-y0[1][i]);
      //table->SetValue(i, 4, -y0[1][i] - 0.01);
    }

    //validMaskTransm->SetValue(i,1);
    //validMaskTransm->SetValue(i, (i > 3 && i < 4) ? 0 : 1);

    validMask->SetValue(i,1);

    //qDebug()<<"i=0,1,numPoints; i = "<<i;
    qDebug()<<"table->GetValue("<<i<<",2) = "<<table->GetValue(i,2).ToFloat();
    }

  // Add multiple line plots, setting the colors etc
  //vtkPlotArea* area = vtkPlotArea::SafeDownCast(chart->AddPlot(vtkChart::AREA));
  //areaTransm = vtkPlotArea::SafeDownCast(chartTransm->AddPlot(vtkChart::AREA));
  //lineTransm = vtkPlotLine::SafeDownCast(chartTransm->AddPlot(vtkChart::LINE));
  //vtkPlot *lines = chartTransm->AddPlot(vtkChart::LINE);
  vtkPlot *line = chartTransm->AddPlot(vtkChart::LINE);

  //line->SetInputData(table.GetPointer());
  //lines->SetInput(table, 0, 1);

  //areaTransm->SetInputData(tableTransm.GetPointer());
  //lines->SetInputArray(0, "X Axis");

  //areaTransm->SetInputArray(1, "Energy");
  //areaTransm->SetInputArray(1, "Cosine");
  //line->SetInputArray(1, "AlphaTransmUp");
#if VTK_MAJOR_VERSION <= 5
  line->SetInput(table, 0, 1);
#else
  line->SetInputData(table, 0, 1);
#endif
  line->SetColor(0, 0, 0, 255);

  //lines->SetValidPointMaskName("ValidMask");

  //vtkPlotLine::SafeDownCast(line)->SetMarkerStyle(vtkPlotLine::CROSS);

  qDebug()<<"Finish Alpha";


  //lineTransmBeta->vtkPlotLine::SafeDownCast(chartTransm->AddPlot(vtkChart::LINE));
  line = chartTransm->AddPlot(vtkChart::LINE);

  //lines->SetInputData(table.GetPointer());
  //lines->SetInputArray(0, "X Axis");
  //lineTransm->SetInputArray(2, "AlphaTransmDown");
  //areaTransm->SetInputArray(6, "Sine");
  //areaTransm->SetInputArray(3, "Sine2");
  //areaTransm->SetInputArray(4, "Sine3");
  //areaTransm->SetInputArray(5, "One");
  //lines->SetInputArray(2, "BetaTransmUp");
#if VTK_MAJOR_VERSION <= 5
  line->SetInput(table, 0, 2);
#else
  line->SetInputData(table, 0, 2);
#endif
  line->SetColor(0, 255, 0, 255);

#ifndef WIN32
  line->GetPen()->SetLineType(vtkPen::DASH_LINE);
#endif

  vtkPlotLine::SafeDownCast(line)->SetMarkerStyle(vtkPlotLine::CIRCLE);
  //lineTransm->SetInputArray(4, "BetaTransmDown");
  //areaTransm->SetInputArray(2, "Transm");

  //line->SetValidPointMaskName("ValidMask");
  //area->GetBrush()->SetColorF(0.5, 0.5, 0.5, 0.5);
  //line->GetBrush()->SetColorF(0.0, 0.0, 1.0, 1.0);
  //chart->GetAxis(vtkAxis::LEFT)->SetLogScale(true); // COMMENT LOGARITHMIC SCALE BY C.SALGADO.
  //chart->GetAxis(vtkAxis::RIGHT)->SetLogScale(true); // ORIGINALLY COMMENTED LOGARITHMIC SCALE BY C.SALGADO.


  qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 5";
  //vtkNew<vtkAxis> xAxis;

  //xAxis = chart->GetAxis(vtkAxis::LEFT);

  //chart->GetAxis(0)->SetUnscaledRange();

  // Render the scene and compare the image to a reference image
  //viewTransm->GetRenderWindow()->SetMultiSamples(0);
  //view->GetInteractor()->Initialize();
  //view->GetInteractor()->Start();

  //connect(ui.horizontalSliderqvtkWidget3, SIGNAL(valueChanged(int)), this, SLOT(setTransmXRange(int)));
  //connect(ui.verticalSliderqvtkWidget3, SIGNAL(valueChanged(int)), this, SLOT(setTransmYRange(int)));
  //connect(ui.horizontalSliderqvtkWidget2, SIGNAL(sliderMoved(int)), this, SLOT(setXRange(int)));
  //connect(ui.verticalSliderqvtkWidget2, SIGNAL(sliderMoved(int)), this, SLOT(setYRange(int)));
  //connect(ui.horizontalSliderqvtkWidget2, SIGNAL(sliderMoved(int)), this, SLOT(view->Update()));
  //connect(ui.verticalSliderqvtkWidget2, SIGNAL(sliderMoved(int)), this, SLOT(view->Update()));
  //connect(ui.autoScaleButton3, SIGNAL(clicked()), this, SLOT(autoScalePlot(int)));

  // Graph View needs to get my render window
  //viewTransm->SetInteractor(this->ui.qvtkWidget3->GetInteractor());
  //this->ui.qvtkWidget3->SetRenderWindow(viewTransm->GetRenderWindow());
  viewTransm->SetInteractor(ui.qvtkWidget3->GetInteractor());
  ui.qvtkWidget3->SetRenderWindow(viewTransm->GetRenderWindow());

  qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 6";

  //this->ui->qvtkWidget2->SetRenderWindow(view->GetRenderWindow());
  //this->ui->qvtkWidget2->Set
  //view->GetInteractor()->Initialize();
  viewTransm->GetInteractor()->Start();
  viewTransm->Render();

  originalTransmXsize = (double)(chartTransm->GetAxis(1)->GetMaximum() - chartTransm->GetAxis(1)->GetMinimum());
  originalTransmYsize = (double)(chartTransm->GetAxis(0)->GetMaximum() - chartTransm->GetAxis(0)->GetMinimum());

  qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 7";

}

void PlotTransmDosDialog::on_plotTransmAxisLimitsButton_clicked(){
    qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 0";
    //chartTransm->RemovePlot(0);
    //chartTransm->RemovePlot(1);
    //chartTransm->RecalculateBounds();
    //chartTransm->RecalculatePlotBounds();
    //chartTransm->RecalculatePlotTransforms();
    qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 0a";
    chartTransm->ClearPlots();
    qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 0b";
    //for (int i = 0; i < viewTransm->GetScene()->GetNumberOfItems(); ++i){
    //  viewTransm->GetScene()->GetItem(i)->ClearItems();
    //}
    qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 0c";
    for (int i = 0; i < chartTransm->GetNumberOfAxes(); ++i){
      chartTransm->GetAxis(i)->ClearItems();
    }
    qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 0d";
    for (int i = 0; i < chartTransm->GetNumberOfPlots(); ++i){
      chartTransm->RemovePlot(i);
    }
    qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 0e";

    //chartTransm->ClearItems();
    /*
    // Graph View needs to get my render window
    //viewTransm->SetInteractor(this->ui.qvtkWidget3->GetInteractor());
    viewTransm->GetInteractor()->Delete();
    ui.qvtkWidget3->GetRenderWindow()->FastDelete();
    viewTransm->GetRenderWindow()->FastDelete();
    //ui.qvtkWidget3->SetRenderWindow(viewTransm->GetRenderWindow());

    //view->GetInteractor()->Initialize();
    //viewTransm->GetInteractor()->Start();
    //viewTransm->Render();
    disconnect(ui.horizontalSliderqvtkWidget3, SIGNAL(valueChanged(int)), this, SLOT(setTransmXRange(int)));
    disconnect(ui.verticalSliderqvtkWidget3, SIGNAL(valueChanged(int)), this, SLOT(setTransmYRange(int)));
    */
// TRANSMISSION PLOT.
qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 1";
QList<QList<double>> dataTransmission = colTransmission;
QList<double> enerdataTransmission = enercolTransmission;
//QVariant varTransmission(dataTransmission[i]);
qint32 numcolDataTransmission = dataTransmission.size();
int n = dataTransmission[0].size();
QVector<float> x(n), y1(n);
QVector<QVector<float>> y0(numcolDataTransmission);
for (int col=0; col<numcolDataTransmission; ++col){
  y0[col].resize(n);
}
//vtkNew<vtkFloatArray> xvtkfloat;
//vtkNew<vtkFloatArray> y0vtkfloat;
qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 2. dataTransmission.size() = "<<dataTransmission.size();
//xvtkfloat->SetNumberOfComponents(n);
//y0vtkfloat->SetNumberOfComponents(n);
for (int i=0; i<n; ++i)        {
  x[i] = (float)enerdataTransmission[i];
  //xvtkfloat->SetValue(i,(float)enerdataTransmission[i]);
  for (int col=0; col<numcolDataTransmission; ++col){
    y0[col][i] = (float)dataTransmission[col][i];
//    qDebug()<<"dataTransmission["<<col<<"]["<<i<<"] = "<< dataTransmission[col][i];
  }
}

/*
// Set up a 2D scene, add an XY chart to it
VTK_CREATE(vtkContextView, viewTransm);
//vtkSmartPointer<vtkContextView> viewTransm =
//    vtkSmartPointer<vtkContextView>::New();
//vtkNew<vtkContextView> view;
  viewTransm->GetRenderWindow()->SetSize(400, 300);

  //vtkNew<vtkChartXY> chart;
  //vtkNew<vtkChartXY> chartTransm =
  //        vtkSmartPointer<vtkChartXY>::New();
  chartTransm = vtkSmartPointer<vtkChartXY>::New();

  qDebug()<<"PlotTransmDosDialog::PlotTransmDosDialog() 2a";
  //viewTransm->GetScene()->RemoveItem(chartTransm.GetPointer());
  qDebug()<<"PlotTransmDosDialog::PlotTransmDosDialog() 2b";
  viewTransm->GetScene()->AddItem(chartTransm.GetPointer());
 qDebug()<<"PlotTransmDosDialog::PlotTransmDosDialog() 2c";

 */ // COMMENTED BY C.SALGADO ON 2016-08-03 TO AVOID VTK CRASH WHEN RESTARTING INTERACTOR.
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

  //renderWindow->Render();

  // Screenshot
    vtkSmartPointer<vtkWindowToImageFilter> windowToImageFilter =
      vtkSmartPointer<vtkWindowToImageFilter>::New();
    //windowToImageFilter->SetInput(renderWindow);
    windowToImageFilter->SetInput(ui.qvtkWidget3->GetRenderWindow());
    windowToImageFilter->SetMagnification(3); //set the resolution of the output image (3 times the current resolution of vtk render window)
    windowToImageFilter->SetInputBufferTypeToRGBA(); //also record the alpha (transparency) channel
    windowToImageFilter->ReadFrontBufferOff(); // read from the back buffer
    windowToImageFilter->Update();

    vtkSmartPointer<vtkPNGWriter> writer =
      vtkSmartPointer<vtkPNGWriter>::New();
    writer->SetFileName("screenshot2.png");
    writer->SetInputConnection(windowToImageFilter->GetOutputPort());
    writer->Write();
    */
  //-----------------------------------------------------------------
  //-----------------------------------------------------------------

  qDebug()<<"PlotTransmDosDialog::PlotTransmDosDialog() 3";

  // Create a table with some points in it...
  //vtkNew<vtkTable> table;
  vtkSmartPointer<vtkTable> table =
      vtkSmartPointer<vtkTable>::New();
  //vtkNew<vtkTable> tableTransm;
  vtkNew<vtkFloatArray> arrTransmX;
  arrTransmX->SetName("X Axis");
  table->AddColumn(arrTransmX.GetPointer());

  vtkNew<vtkFloatArray> AlphaTransm;
  AlphaTransm->SetName("AlphaTransm");
  table->AddColumn(AlphaTransm.GetPointer());

  vtkNew<vtkFloatArray> BetaTransm;
  BetaTransm->SetName("BetaTransm");
  table->AddColumn(BetaTransm.GetPointer());

  vtkNew<vtkCharArray> validMask;
  validMask->SetName("ValidMask");
  table->AddColumn(validMask.GetPointer());


  qDebug()<<"PlotTransmDosDialog::PlotTransmDosDialog() 4";

  // Test charting with a few more points...
  float inc = 7.5 / (n-1);
  table->SetNumberOfRows(n);
  for (int i = 0; i < n; ++i){
    //table->SetValue(i, 0, i * inc + 0.01);
    table->SetValue(i, 0, (float)(x[i]));
    if(abs(y0[0][i])<100.0){
      table->SetValue(i, 1, y0[0][i]);
    }else{
      table->SetValue(i, 1, (y0[0][i]/abs(y0[0][i]))*100.0);
    }

    if(y0.size() == 2){
      //table->SetValue(i, 2, -y0[1][i]);
      if(abs(y0[1][i])<100.0){
        table->SetValue(i, 2, -y0[1][i]);
      }else{
        table->SetValue(i, 2, -(y0[1][i]/abs(y0[1][i]))*100.0);
      }
      //BetaTransmUp->SetValue(i,-y0[1][i]);
      //table->SetValue(i, 4, -y0[1][i] - 0.01);
    }
    validMask->SetValue(i,1);
    qDebug()<<"table->GetValue("<<i<<",2) = "<<table->GetValue(i,2).ToFloat();
  }



  // Add multiple line plots, setting the colors etc
  //lineTransm = vtkPlotLine::SafeDownCast(chartTransm->AddPlot(vtkChart::LINE));
  //vtkPlot *line = chartTransm->AddPlot(vtkChart::LINE);
  vtkSmartPointer<vtkPlotLine> lineTransmAlpha =
      vtkSmartPointer<vtkPlotLine>::New();
  //chartTransm->RemovePlot(0);
  lineTransmAlpha = vtkPlotLine::SafeDownCast(chartTransm->AddPlot(vtkChart::LINE));
  //line->SetInputData(table.GetPointer());
  //line->SetInputArray(1, "AlphaTransmUp");
#if VTK_MAJOR_VERSION <= 5
  lineTransmAlpha->SetInput(table, 0, 1);
#else
  lineTransmAlpha->SetInputData(table, 0, 1);
#endif
  lineTransmAlpha->SetColor( 0, 0, 255, 255 );
  lineTransmAlpha->SetWidth(2.0);
  //vtkPlotLine::SafeDownCast(line)->SetMarkerStyle(vtkPlotLine::CROSS);

  lineTransmAlpha->SetValidPointMaskName("ValidMask");

  lineTransmAlpha->Update();
  qDebug()<<"Finish Alpha";


  if(y0.size() == 2){
    //lineTransmBeta->vtkPlotLine::SafeDownCast(chartTransm->AddPlot(vtkChart::LINE));
    //line = chartTransm->AddPlot(vtkChart::LINE);
    vtkSmartPointer<vtkPlotLine> lineTransmBeta =
        vtkSmartPointer<vtkPlotLine>::New();
    //chartTransm->RemovePlot(1);
    lineTransmBeta = vtkPlotLine::SafeDownCast(chartTransm->AddPlot(vtkChart::LINE));

    //lines->SetInputData(table.GetPointer());
    //lines->SetInputArray(0, "X Axis");
    //lineTransm->SetInputArray(2, "AlphaTransmDown");// Mapper

    /*
    //VTK_CREATE(vtkPolyDataMapper, mapper);
    vtkSmartPointer<vtkPolyDataMapper> mapper =
        vtkSmartPointer<vtkPolyDataMapper>::New();
    //mapper->ImmediateModeRenderingOn();
    //mapper->SetInputConnection(elevation->GetOutputPort());
    //mapper->SetInputConnection(viewTransm->GetRepresentation());

    // Actor in scene
    VTK_CREATE(vtkActor, actor);
    actor->SetMapper(mapper);

    // VTK Renderer
    VTK_CREATE(vtkRenderer, ren);

    // Add Actor to renderer
    ren->AddActor(actor);
    //areaTransm->SetInputArray(6, "Sine");
    //areaTransm->SetInputArray(3, "Sine2");
    //areaTransm->SetInputArray(4, "Sine3");
    //areaTransm->SetInputArray(5, "One");
    //lines->SetInputArray(2, "BetaTransmUp");
    */ // THIS DOES NOTHING HERE 2016-08-04.
#if VTK_MAJOR_VERSION <= 5
    lineTransmBeta->SetInput(table, 0, 2);
#else
    lineTransmBeta->SetInputData(table, 0, 2);
#endif
    lineTransmBeta->SetColor( 255, 0, 0, 255 );
    lineTransmBeta->SetWidth(2.0);


//#ifndef WIN32
//  line->GetPen()->SetLineType(vtkPen::DASH_LINE);
//#endif

    lineTransmBeta->SetValidPointMaskName("ValidMask");
    //vtkPlotLine::SafeDownCast(line)->SetMarkerStyle(vtkPlotLine::CIRCLE);
    lineTransmBeta->Update();
    qDebug()<<"Finish Beta";
  }


  /*
  // Graph View needs to get my render window
  qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 5a";
  //ui.qvtkWidget3->GetInteractor()->ReInitialize();
  //viewTransm->SetInteractor(this->ui.qvtkWidget3->GetInteractor());
  viewTransm->SetInteractor(ui.qvtkWidget3->GetInteractor());
  ui.qvtkWidget3->SetRenderWindow(viewTransm->GetRenderWindow());

  qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 6";

  //view->GetInteractor()->Initialize();
  //viewTransm->GetInteractor()->ReInitialize();
  viewTransm->GetInteractor()->Start();
  viewTransm->Render();
  */

  qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 5";
  //viewTransm->Update();
  //lineTransmAlpha->Update();
  //
  //view->Update();
  //view->GetInteractor()->Render();
  //view->Render();
  //std::cout << "Clicked." << std::endl;
  qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 6.";
  //chartTransm->GetNumberOfAxes()
  if(chartTransm->GetAxis(0)->GetMaximum()>100.0){
    chartTransm->GetAxis(0)->SetMaximum(100.0);
  }
  if(chartTransm->GetAxis(0)->GetMinimum()<-100.0){
    chartTransm->GetAxis(0)->SetMinimum(-100.0);
  }
  if(chartTransm->GetAxis(1)->GetMaximum()>100.0){
    chartTransm->GetAxis(1)->SetMaximum(100.0);
  }
  if(chartTransm->GetAxis(1)->GetMinimum()<-100.0){
    chartTransm->GetAxis(1)->SetMinimum(-100.0);
  }
  qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 6a.";
  chartTransm->Update();
  qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 6b.";
  //viewTransm->GetScene()->AddItem(chartTransm.GetPointer());
  qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 6c.";
  //viewTransm->Update();
  qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 6d.";
  ui.qvtkWidget3->update();
  qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 6e.";

  //originalTransmXsize = (double)(chartTransm->GetAxis(1)->GetMaximum() - chartTransm->GetAxis(1)->GetMinimum());
  //originalTransmYsize = (double)(chartTransm->GetAxis(0)->GetMaximum() - chartTransm->GetAxis(0)->GetMinimum());
  originalTransmXsize = (double)(chartTransm->GetAxis(0)->GetMaximum() - chartTransm->GetAxis(0)->GetMinimum());
  originalTransmYsize = (double)(chartTransm->GetAxis(1)->GetMaximum() - chartTransm->GetAxis(1)->GetMinimum());

  /*
  connect(ui.horizontalSliderqvtkWidget3, SIGNAL(valueChanged(int)), this, SLOT(setTransmXRange(int)));
  connect(ui.verticalSliderqvtkWidget3, SIGNAL(valueChanged(int)), this, SLOT(setTransmYRange(int)));
  */ // COMMENTED BY C.SALGADO ON 2016-08-03 TO AVOID VTK CRASH WHEN RESTARTING INTERACTOR.

  qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 7";

}

void PlotTransmDosDialog::on_plotTransmButton_clicked(){
    qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 0";
    //chartTransm->RemovePlot(0);
    //chartTransm->RemovePlot(1);
    //chartTransm->RecalculateBounds();
    //chartTransm->RecalculatePlotBounds();
    //chartTransm->RecalculatePlotTransforms();
    qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 0a";
    chartTransm->ClearPlots();
    qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 0b";
    //for (int i = 0; i < viewTransm->GetScene()->GetNumberOfItems(); ++i){
    //  viewTransm->GetScene()->GetItem(i)->ClearItems();
    //}
    qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 0c";
    for (int i = 0; i < chartTransm->GetNumberOfAxes(); ++i){
      chartTransm->GetAxis(i)->ClearItems();
    }
    qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 0d";
    for (int i = 0; i < chartTransm->GetNumberOfPlots(); ++i){
      chartTransm->RemovePlot(i);
    }
    qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 0e";

    //chartTransm->ClearItems();
    /*
    // Graph View needs to get my render window
    //viewTransm->SetInteractor(this->ui.qvtkWidget3->GetInteractor());
    viewTransm->GetInteractor()->Delete();
    ui.qvtkWidget3->GetRenderWindow()->FastDelete();
    viewTransm->GetRenderWindow()->FastDelete();
    //ui.qvtkWidget3->SetRenderWindow(viewTransm->GetRenderWindow());

    //view->GetInteractor()->Initialize();
    //viewTransm->GetInteractor()->Start();
    //viewTransm->Render();
    disconnect(ui.horizontalSliderqvtkWidget3, SIGNAL(valueChanged(int)), this, SLOT(setTransmXRange(int)));
    disconnect(ui.verticalSliderqvtkWidget3, SIGNAL(valueChanged(int)), this, SLOT(setTransmYRange(int)));
    */
// TRANSMISSION PLOT.
qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 1";
QList<QList<double>> dataTransmission = colTransmission;
QList<double> enerdataTransmission = enercolTransmission;
//QVariant varTransmission(dataTransmission[i]);
qint32 numcolDataTransmission = dataTransmission.size();
int n = dataTransmission[0].size();
QVector<float> x(n), y1(n);
QVector<QVector<float>> y0(numcolDataTransmission);
for (int col=0; col<numcolDataTransmission; ++col){
  y0[col].resize(n);
}
//vtkNew<vtkFloatArray> xvtkfloat;
//vtkNew<vtkFloatArray> y0vtkfloat;
qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 2. dataTransmission.size() = "<<dataTransmission.size();
//xvtkfloat->SetNumberOfComponents(n);
//y0vtkfloat->SetNumberOfComponents(n);
for (int i=0; i<n; ++i)        {
  x[i] = (float)enerdataTransmission[i];
  //xvtkfloat->SetValue(i,(float)enerdataTransmission[i]);
  for (int col=0; col<numcolDataTransmission; ++col){
    y0[col][i] = (float)dataTransmission[col][i];
//    qDebug()<<"dataTransmission["<<col<<"]["<<i<<"] = "<< dataTransmission[col][i];
  }
}

/*
// Set up a 2D scene, add an XY chart to it
VTK_CREATE(vtkContextView, viewTransm);
//vtkSmartPointer<vtkContextView> viewTransm =
//    vtkSmartPointer<vtkContextView>::New();
//vtkNew<vtkContextView> view;
  viewTransm->GetRenderWindow()->SetSize(400, 300);

  //vtkNew<vtkChartXY> chart;
  //vtkNew<vtkChartXY> chartTransm =
  //        vtkSmartPointer<vtkChartXY>::New();
  chartTransm = vtkSmartPointer<vtkChartXY>::New();

  qDebug()<<"PlotTransmDosDialog::PlotTransmDosDialog() 2a";
  //viewTransm->GetScene()->RemoveItem(chartTransm.GetPointer());
  qDebug()<<"PlotTransmDosDialog::PlotTransmDosDialog() 2b";
  viewTransm->GetScene()->AddItem(chartTransm.GetPointer());
 qDebug()<<"PlotTransmDosDialog::PlotTransmDosDialog() 2c";

 */ // COMMENTED BY C.SALGADO ON 2016-08-03 TO AVOID VTK CRASH WHEN RESTARTING INTERACTOR.
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

  //renderWindow->Render();

  // Screenshot
    vtkSmartPointer<vtkWindowToImageFilter> windowToImageFilter =
      vtkSmartPointer<vtkWindowToImageFilter>::New();
    //windowToImageFilter->SetInput(renderWindow);
    windowToImageFilter->SetInput(ui.qvtkWidget3->GetRenderWindow());
    windowToImageFilter->SetMagnification(3); //set the resolution of the output image (3 times the current resolution of vtk render window)
    windowToImageFilter->SetInputBufferTypeToRGBA(); //also record the alpha (transparency) channel
    windowToImageFilter->ReadFrontBufferOff(); // read from the back buffer
    windowToImageFilter->Update();

    vtkSmartPointer<vtkPNGWriter> writer =
      vtkSmartPointer<vtkPNGWriter>::New();
    writer->SetFileName("screenshot2.png");
    writer->SetInputConnection(windowToImageFilter->GetOutputPort());
    writer->Write();
    */
  //-----------------------------------------------------------------
  //-----------------------------------------------------------------

  qDebug()<<"PlotTransmDosDialog::PlotTransmDosDialog() 3";

  // Create a table with some points in it...
  //vtkNew<vtkTable> table;
  vtkSmartPointer<vtkTable> table =
      vtkSmartPointer<vtkTable>::New();
  //vtkNew<vtkTable> tableTransm;

  vtkSmartPointer<vtkTable> tableFermi =
      vtkSmartPointer<vtkTable>::New();

  vtkNew<vtkFloatArray> arrFermiX;
  arrFermiX->SetName("X Fermi");
  tableFermi->AddColumn(arrFermiX.GetPointer());

  vtkNew<vtkFloatArray> arrFermiY;
  arrFermiY->SetName("Y Fermi");
  tableFermi->AddColumn(arrFermiY.GetPointer());

  vtkNew<vtkFloatArray> arrTransmX;
  arrTransmX->SetName("X Axis");
  table->AddColumn(arrTransmX.GetPointer());

  vtkNew<vtkFloatArray> AlphaTransm;
  AlphaTransm->SetName("AlphaTransm");
  table->AddColumn(AlphaTransm.GetPointer());

  vtkNew<vtkFloatArray> BetaTransm;
  BetaTransm->SetName("BetaTransm");
  table->AddColumn(BetaTransm.GetPointer());

  vtkNew<vtkCharArray> validMask;
  validMask->SetName("ValidMask");
  table->AddColumn(validMask.GetPointer());


  qDebug()<<"PlotTransmDosDialog::PlotTransmDosDialog() 4";

  // Test charting with a few more points...
  float inc = 7.5 / (n-1);
  table->SetNumberOfRows(n);
  for (int i = 0; i < n; ++i){
    //table->SetValue(i, 0, i * inc + 0.01);
    table->SetValue(i, 0, (float)(x[i]));
    table->SetValue(i, 1, y0[0][i]);

    if(y0.size() == 2){
      table->SetValue(i, 2, -y0[1][i]);
      //BetaTransmUp->SetValue(i,-y0[1][i]);
      //table->SetValue(i, 4, -y0[1][i] - 0.01);
    }


    validMask->SetValue(i,1);
//    qDebug()<<"table->GetValue("<<i<<",2) = "<<table->GetValue(i,2).ToFloat();
  }



  // Add multiple line plots, setting the colors etc
  //lineTransm = vtkPlotLine::SafeDownCast(chartTransm->AddPlot(vtkChart::LINE));
  //vtkPlot *line = chartTransm->AddPlot(vtkChart::LINE);
  vtkSmartPointer<vtkPlotLine> lineTransmAlpha =
      vtkSmartPointer<vtkPlotLine>::New();
  //chartTransm->RemovePlot(0);
  lineTransmAlpha = vtkPlotLine::SafeDownCast(chartTransm->AddPlot(vtkChart::LINE));
  //line->SetInputData(table.GetPointer());
  //line->SetInputArray(1, "AlphaTransmUp");
#if VTK_MAJOR_VERSION <= 5
  lineTransmAlpha->SetInput(table, 0, 1);
#else
  lineTransmAlpha->SetInputData(table, 0, 1);
#endif
  lineTransmAlpha->SetColor( 0, 0, 255, 255 );
  lineTransmAlpha->SetWidth(2.0);
  //vtkPlotLine::SafeDownCast(line)->SetMarkerStyle(vtkPlotLine::CROSS);

  lineTransmAlpha->SetValidPointMaskName("ValidMask");

  lineTransmAlpha->Update();
  qDebug()<<"Finish Alpha";


  if(y0.size() == 2){
    //lineTransmBeta->vtkPlotLine::SafeDownCast(chartTransm->AddPlot(vtkChart::LINE));
    //line = chartTransm->AddPlot(vtkChart::LINE);
    vtkSmartPointer<vtkPlotLine> lineTransmBeta =
        vtkSmartPointer<vtkPlotLine>::New();
    //chartTransm->RemovePlot(1);
    lineTransmBeta = vtkPlotLine::SafeDownCast(chartTransm->AddPlot(vtkChart::LINE));

    //lines->SetInputData(table.GetPointer());
    //lines->SetInputArray(0, "X Axis");
    //lineTransm->SetInputArray(2, "AlphaTransmDown");// Mapper

    /*
    //VTK_CREATE(vtkPolyDataMapper, mapper);
    vtkSmartPointer<vtkPolyDataMapper> mapper =
        vtkSmartPointer<vtkPolyDataMapper>::New();
    //mapper->ImmediateModeRenderingOn();
    //mapper->SetInputConnection(elevation->GetOutputPort());
    //mapper->SetInputConnection(viewTransm->GetRepresentation());

    // Actor in scene
    VTK_CREATE(vtkActor, actor);
    actor->SetMapper(mapper);

    // VTK Renderer
    VTK_CREATE(vtkRenderer, ren);

    // Add Actor to renderer
    ren->AddActor(actor);
    //areaTransm->SetInputArray(6, "Sine");
    //areaTransm->SetInputArray(3, "Sine2");
    //areaTransm->SetInputArray(4, "Sine3");
    //areaTransm->SetInputArray(5, "One");
    //lines->SetInputArray(2, "BetaTransmUp");
    */ // THIS DOES NOTHING HERE 2016-08-04.
#if VTK_MAJOR_VERSION <= 5
    lineTransmBeta->SetInput(table, 0, 2);
#else
    lineTransmBeta->SetInputData(table, 0, 2);
#endif
    lineTransmBeta->SetColor( 255, 0, 0, 255 );
    lineTransmBeta->SetWidth(2.0);


//#ifndef WIN32
//  line->GetPen()->SetLineType(vtkPen::DASH_LINE);
//#endif

    lineTransmBeta->SetValidPointMaskName("ValidMask");
    //vtkPlotLine::SafeDownCast(line)->SetMarkerStyle(vtkPlotLine::CIRCLE);
    lineTransmBeta->Update();
    qDebug()<<"Finish Beta";
  }

  qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 4 Fermi";
  //chartTransm->GetAxis(0)->GetMaximum();
  tableFermi->SetNumberOfRows(2);
  tableFermi->SetValue(0, 0, -0.0000001);
  tableFermi->SetValue(1, 0, 0.0000001);
  qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 4 Fermi a";
  //tableFermi->SetValue(0, 1, chartTransm->GetAxis(0)->GetMinimum());
  //tableFermi->SetValue(1, 1, chartTransm->GetAxis(0)->GetMaximum());
  //tableFermi->SetValue(0, 1, -10.0);
  //tableFermi->SetValue(1, 1, 10.0);
  //tableFermi->SetValue(0, 1, BetaTransm->GetDataTypeMin());
  //tableFermi->SetValue(1, 1, AlphaTransm->GetDataTypeMax());

  double fermimin = 0.0;
  double fermimax = 0.0;
  if(y0.size() == 2){
    //double betamin = *std::min_element(dataTransmission[1].begin(), dataTransmission[1].end());
    //double betamax = *std::max_element(dataTransmission[1].begin(), dataTransmission[1].end());
    double alphamin = *std::min_element(y0[0].begin(), y0[0].end());
    double alphamax = *std::max_element(y0[0].begin(), y0[0].end());
    double betamin = - *std::max_element(y0[1].begin(), y0[1].end());
    double betamax = - *std::min_element(y0[1].begin(), y0[1].end());

    fermimin = 1.5*fmin(alphamin,betamin);
    fermimax = 1.5*fmax(alphamax,betamax);
  }else{
    fermimin = 1.5* (*std::min_element(y0[0].begin(), y0[0].end()));
    fermimax = 1.5* (*std::max_element(y0[0].begin(), y0[0].end()));
  }
  tableFermi->SetValue(0, 1, fermimin);
  tableFermi->SetValue(1, 1, fermimax);

//  qDebug()<<"tableFermi->GetValue(0,0) = "<<tableFermi->GetValue(0,0).ToDouble();
//  qDebug()<<"tableFermi->GetValue(0,1) = "<<tableFermi->GetValue(0,1).ToDouble();
//  qDebug()<<"tableFermi->GetValue(1,0) = "<<tableFermi->GetValue(1,0).ToDouble();
//  qDebug()<<"tableFermi->GetValue(1,1) = "<<tableFermi->GetValue(1,1).ToDouble();
  qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 4 Fermi b";
  vtkSmartPointer<vtkPlotLine> lineTransmFermi =
      vtkSmartPointer<vtkPlotLine>::New();
  //chartTransm->RemovePlot(0);
  qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 4 Fermi c";
  lineTransmFermi = vtkPlotLine::SafeDownCast(chartTransm->AddPlot(vtkChart::LINE));
  //line->SetInputData(table.GetPointer());
  //line->SetInputArray(1, "FermiTransmUp");
  qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 4 Fermi d";
#if VTK_MAJOR_VERSION <= 5
  lineTransmFermi->SetInput(tableFermi, 0, 1);
#else
  lineTransmFermi->SetInputData(tableFermi, 0, 1);
#endif
  qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 4 Fermi e";
  lineTransmFermi->SetColor( 0, 255, 0, 255 );
  lineTransmFermi->SetWidth(2.0);
  //vtkPlotLine::SafeDownCast(line)->SetMarkerStyle(vtkPlotLine::CROSS);

  //lineTransmFermi->SetValidPointMaskName("ValidMask");

  lineTransmFermi->Update();
  qDebug()<<"Finish Fermi";

  /*
  // Graph View needs to get my render window
  qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 5a";
  //ui.qvtkWidget3->GetInteractor()->ReInitialize();
  //viewTransm->SetInteractor(this->ui.qvtkWidget3->GetInteractor());
  viewTransm->SetInteractor(ui.qvtkWidget3->GetInteractor());
  ui.qvtkWidget3->SetRenderWindow(viewTransm->GetRenderWindow());

  qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 6";

  //view->GetInteractor()->Initialize();
  //viewTransm->GetInteractor()->ReInitialize();
  viewTransm->GetInteractor()->Start();
  viewTransm->Render();
  */

  chartTransm->GetPlot(0)->GetXAxis()->SetTitle("Energy (eV)");
  chartTransm->GetPlot(0)->GetYAxis()->SetTitle("Transmission (e²/h)");

  vtkSmartPointer<vtkTextProperty> XaxisLabelProp =
      vtkSmartPointer<vtkTextProperty>::New();
  XaxisLabelProp = chartTransm->GetPlot(0)->GetXAxis()->GetTitleProperties();
  XaxisLabelProp->SetFontSize(20);
  vtkSmartPointer<vtkTextProperty> YaxisLabelProp =
      vtkSmartPointer<vtkTextProperty>::New();
  YaxisLabelProp = chartTransm->GetPlot(0)->GetYAxis()->GetTitleProperties();
  YaxisLabelProp->SetFontSize(20);

  //chartTransm->GetAxis(0)->
  //chartTransm->GetPlot(1)->SetLabels(labels.GetPointer());
  //chartTransm->GetPlot(1)->SetLabels("labels");
  //chartTransm->GetPlot(0)->SetLabels(labelArray);
  //chartTransm->GetPlot(0)->SetLabels(labelArray.GetPointer());
  //chartTransm->GetPlot(0)->SetLabel
  //lineTransmAlpha->SetLabels(labelArray);
  //lineTransmAlpha->SetLabels(labelArray.GetPointer());
  //lineTransmAlpha->Update();

  //chartTransm->GetPlot(0)->SetL

  qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 5";
  //viewTransm->Update();
  //lineTransmAlpha->Update();
  //
  //view->Update();
  //view->GetInteractor()->Render();
  //view->Render();
  //std::cout << "Clicked." << std::endl;
  qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 6.";
  //chartTransm->GetNumberOfAxes()

  qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 6a.";
  chartTransm->Update();
  qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 6b.";
  //viewTransm->GetScene()->AddItem(chartTransm.GetPointer());
  qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 6c.";
  //viewTransm->Update();
  qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 6d.";
  ui.qvtkWidget3->update();
  qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 6e.";

  //originalTransmXsize = (double)(chartTransm->GetAxis(1)->GetMaximum() - chartTransm->GetAxis(1)->GetMinimum());
  //originalTransmYsize = (double)(chartTransm->GetAxis(0)->GetMaximum() - chartTransm->GetAxis(0)->GetMinimum());
  originalTransmXsize = (double)(chartTransm->GetAxis(0)->GetMaximum() - chartTransm->GetAxis(0)->GetMinimum());
  originalTransmYsize = (double)(chartTransm->GetAxis(1)->GetMaximum() - chartTransm->GetAxis(1)->GetMinimum());

  /*
  connect(ui.horizontalSliderqvtkWidget3, SIGNAL(valueChanged(int)), this, SLOT(setTransmXRange(int)));
  connect(ui.verticalSliderqvtkWidget3, SIGNAL(valueChanged(int)), this, SLOT(setTransmYRange(int)));
  */ // COMMENTED BY C.SALGADO ON 2016-08-03 TO AVOID VTK CRASH WHEN RESTARTING INTERACTOR.

  qDebug()<<"PlotTransmDosDialog::on_plotTransmButton_clicked() 7";

}

void PlotTransmDosDialog::on_plotDosButton_clicked(){
    qDebug()<<"PlotTransmDosDialog::on_plotDosButton_clicked() 0";
    //chartDos->RemovePlot(0);
    //chartDos->RemovePlot(1);
    //chartDos->RecalculateBounds();
    //chartDos->RecalculatePlotBounds();
    //chartDos->RecalculatePlotTransforms();
    qDebug()<<"PlotTransmDosDialog::on_plotDosButton_clicked() 0a";
    chartDos->ClearPlots();
    qDebug()<<"PlotTransmDosDialog::on_plotDosButton_clicked() 0b";
    //for (int i = 0; i < viewDos->GetScene()->GetNumberOfItems(); ++i){
    //  viewDos->GetScene()->GetItem(i)->ClearItems();
    //}
    qDebug()<<"PlotTransmDosDialog::on_plotDosButton_clicked() 0c";
    for (int i = 0; i < chartDos->GetNumberOfAxes(); ++i){
      chartDos->GetAxis(i)->ClearItems();
    }
    qDebug()<<"PlotTransmDosDialog::on_plotDosButton_clicked() 0d";
    for (int i = 0; i < chartDos->GetNumberOfPlots(); ++i){
      chartDos->RemovePlot(i);
    }
    qDebug()<<"PlotTransmDosDialog::on_plotDosButton_clicked() 0e";


// DOS PLOT.
qDebug()<<"PlotTransmDosDialog::on_plotDosButton_clicked() 1";
QList<QList<double>> dataDos = colDos;
QList<double> enerdataDos = enercolDos;

qint32 numcolDataDos = dataDos.size();
int n = dataDos[0].size();
QVector<float> x(n), y1(n);
QVector<QVector<float>> y0(numcolDataDos);
for (int col=0; col<numcolDataDos; ++col){
  y0[col].resize(n);
}
//vtkNew<vtkFloatArray> xvtkfloat;
//vtkNew<vtkFloatArray> y0vtkfloat;
qDebug()<<"PlotTransmDosDialog::on_plotDosButton_clicked() 2. dataDos.size() = "<<dataDos.size();
//xvtkfloat->SetNumberOfComponents(n);
//y0vtkfloat->SetNumberOfComponents(n);
for (int i=0; i<n; ++i)        {
  x[i] = (float)enerdataDos[i];
  //xvtkfloat->SetValue(i,(float)enerdataDos[i]);
  for (int col=0; col<numcolDataDos; ++col){
    y0[col][i] = (float)dataDos[col][i];
//    qDebug()<<"dataDos["<<col<<"]["<<i<<"] = "<< dataDos[col][i];
  }
}

  //-----------------------------------------------------------------
  //-----------------------------------------------------------------

  qDebug()<<"PlotTransmDosDialog::PlotTransmDosDialog() 3";

  // Create a table with some points in it...
  //vtkNew<vtkTable> table;
  vtkSmartPointer<vtkTable> table =
      vtkSmartPointer<vtkTable>::New();
  //vtkNew<vtkTable> tableDos;

  vtkSmartPointer<vtkTable> tableFermi =
      vtkSmartPointer<vtkTable>::New();

  vtkNew<vtkFloatArray> arrFermiX;
  arrFermiX->SetName("X Fermi");
  tableFermi->AddColumn(arrFermiX.GetPointer());

  vtkNew<vtkFloatArray> arrFermiY;
  arrFermiY->SetName("Y Fermi");
  tableFermi->AddColumn(arrFermiY.GetPointer());

  vtkNew<vtkFloatArray> arrDosX;
  arrDosX->SetName("X Axis");
  table->AddColumn(arrDosX.GetPointer());

  vtkNew<vtkFloatArray> AlphaDos;
  AlphaDos->SetName("AlphaDos");
  table->AddColumn(AlphaDos.GetPointer());

  vtkNew<vtkFloatArray> BetaDos;
  BetaDos->SetName("BetaDos");
  table->AddColumn(BetaDos.GetPointer());

  vtkNew<vtkCharArray> validMask;
  validMask->SetName("ValidMask");
  table->AddColumn(validMask.GetPointer());


  qDebug()<<"PlotTransmDosDialog::PlotTransmDosDialog() 4";

  // Test charting with a few more points...
  float inc = 7.5 / (n-1);
  table->SetNumberOfRows(n);
  for (int i = 0; i < n; ++i){
    //table->SetValue(i, 0, i * inc + 0.01);
    table->SetValue(i, 0, (float)(x[i]));
    table->SetValue(i, 1, y0[0][i]);

    if(y0.size() == 2){
      table->SetValue(i, 2, y0[1][i]);
      //BetaDosUp->SetValue(i,-y0[1][i]);
      //table->SetValue(i, 4, -y0[1][i] - 0.01);
    }


    validMask->SetValue(i,1);
//    qDebug()<<"table->GetValue("<<i<<",2) = "<<table->GetValue(i,2).ToFloat();
  }



  // Add multiple line plots, setting the colors etc
  //lineDos = vtkPlotLine::SafeDownCast(chartDos->AddPlot(vtkChart::LINE));
  //vtkPlot *line = chartDos->AddPlot(vtkChart::LINE);
  vtkSmartPointer<vtkPlotLine> lineDosAlpha =
      vtkSmartPointer<vtkPlotLine>::New();
  //chartDos->RemovePlot(0);
  lineDosAlpha = vtkPlotLine::SafeDownCast(chartDos->AddPlot(vtkChart::LINE));
  //line->SetInputData(table.GetPointer());
  //line->SetInputArray(1, "AlphaDosUp");
#if VTK_MAJOR_VERSION <= 5
  lineDosAlpha->SetInput(table, 0, 1);
#else
  lineDosAlpha->SetInputData(table, 0, 1);
#endif
  lineDosAlpha->SetColor( 0, 0, 255, 255 );
  lineDosAlpha->SetWidth(2.0);
  //vtkPlotLine::SafeDownCast(line)->SetMarkerStyle(vtkPlotLine::CROSS);

  lineDosAlpha->SetValidPointMaskName("ValidMask");

  lineDosAlpha->Update();
  qDebug()<<"Finish Alpha";


  if(y0.size() == 2){
    //lineDosBeta->vtkPlotLine::SafeDownCast(chartDos->AddPlot(vtkChart::LINE));
    //line = chartDos->AddPlot(vtkChart::LINE);
    vtkSmartPointer<vtkPlotLine> lineDosBeta =
        vtkSmartPointer<vtkPlotLine>::New();
    //chartDos->RemovePlot(1);
    lineDosBeta = vtkPlotLine::SafeDownCast(chartDos->AddPlot(vtkChart::LINE));

#if VTK_MAJOR_VERSION <= 5
    lineDosBeta->SetInput(table, 0, 2);
#else
    lineDosBeta->SetInputData(table, 0, 2);
#endif
    lineDosBeta->SetColor( 255, 0, 0, 255 );
    lineDosBeta->SetWidth(2.0);


//#ifndef WIN32
//  line->GetPen()->SetLineType(vtkPen::DASH_LINE);
//#endif

    lineDosBeta->SetValidPointMaskName("ValidMask");
    //vtkPlotLine::SafeDownCast(line)->SetMarkerStyle(vtkPlotLine::CIRCLE);
    lineDosBeta->Update();
    qDebug()<<"Finish Beta";
  }

  qDebug()<<"PlotTransmDosDialog::on_plotDosButton_clicked() 4 Fermi";
  //chartDos->GetAxis(0)->GetMaximum();
  tableFermi->SetNumberOfRows(2);
  tableFermi->SetValue(0, 0, -0.0000001);
  tableFermi->SetValue(1, 0, 0.0000001);
  qDebug()<<"PlotTransmDosDialog::on_plotDosButton_clicked() 4 Fermi a";
  //tableFermi->SetValue(0, 1, chartDos->GetAxis(0)->GetMinimum());
  //tableFermi->SetValue(1, 1, chartDos->GetAxis(0)->GetMaximum());
  //tableFermi->SetValue(0, 1, -10.0);
  //tableFermi->SetValue(1, 1, 10.0);
  //tableFermi->SetValue(0, 1, BetaDos->GetDataTypeMin());
  //tableFermi->SetValue(1, 1, AlphaDos->GetDataTypeMax());

  double fermimin = 0.0;
  double fermimax = 0.0;
  if(y0.size() == 2){
    double alphamin = *std::min_element(y0[0].begin(), y0[0].end());
    double alphamax = *std::max_element(y0[0].begin(), y0[0].end());
    double betamin = *std::min_element(y0[1].begin(), y0[1].end());
    double betamax = *std::max_element(y0[1].begin(), y0[1].end());

    fermimin = 1.5*fmin(alphamin,betamin);
    fermimax = 1.5*fmax(alphamax,betamax);
  }else{
    fermimin = 1.5* (*std::min_element(y0[0].begin(), y0[0].end()));
    fermimax = 1.5* (*std::max_element(y0[0].begin(), y0[0].end()));
  }
  tableFermi->SetValue(0, 1, fermimin);
  tableFermi->SetValue(1, 1, fermimax);

//  qDebug()<<"tableFermi->GetValue(0,0) = "<<tableFermi->GetValue(0,0).ToDouble();
//  qDebug()<<"tableFermi->GetValue(0,1) = "<<tableFermi->GetValue(0,1).ToDouble();
//  qDebug()<<"tableFermi->GetValue(1,0) = "<<tableFermi->GetValue(1,0).ToDouble();
//  qDebug()<<"tableFermi->GetValue(1,1) = "<<tableFermi->GetValue(1,1).ToDouble();
  qDebug()<<"PlotTransmDosDialog::on_plotDosButton_clicked() 4 Fermi b";
  vtkSmartPointer<vtkPlotLine> lineDosFermi =
      vtkSmartPointer<vtkPlotLine>::New();
  //chartDos->RemovePlot(0);
  qDebug()<<"PlotTransmDosDialog::on_plotDosButton_clicked() 4 Fermi c";
  lineDosFermi = vtkPlotLine::SafeDownCast(chartDos->AddPlot(vtkChart::LINE));
  //line->SetInputData(table.GetPointer());
  //line->SetInputArray(1, "FermiDosUp");
  qDebug()<<"PlotDosDosDialog::on_plotDosButton_clicked() 4 Fermi d";
#if VTK_MAJOR_VERSION <= 5
  lineDosFermi->SetInput(tableFermi, 0, 1);
#else
  lineDosFermi->SetInputData(tableFermi, 0, 1);
#endif
  qDebug()<<"PlotTransmDosDialog::on_plotDosButton_clicked() 4 Fermi e";
  lineDosFermi->SetColor( 0, 255, 0, 255 );
  lineDosFermi->SetWidth(2.0);
  //vtkPlotLine::SafeDownCast(line)->SetMarkerStyle(vtkPlotLine::CROSS);

  //lineDosFermi->SetValidPointMaskName("ValidMask");

  lineDosFermi->Update();
  qDebug()<<"Finish Fermi";

  chartDos->GetPlot(0)->GetXAxis()->SetTitle("Energy (eV)");
  chartDos->GetPlot(0)->GetYAxis()->SetTitle("DOS");

  vtkSmartPointer<vtkTextProperty> XaxisLabelProp =
      vtkSmartPointer<vtkTextProperty>::New();
  XaxisLabelProp = chartDos->GetPlot(0)->GetXAxis()->GetTitleProperties();
  XaxisLabelProp->SetFontSize(20);
  vtkSmartPointer<vtkTextProperty> YaxisLabelProp =
      vtkSmartPointer<vtkTextProperty>::New();
  YaxisLabelProp = chartDos->GetPlot(0)->GetYAxis()->GetTitleProperties();
  YaxisLabelProp->SetFontSize(20);


  qDebug()<<"PlotTransmDosDialog::on_plotDosButton_clicked() 5";
  //viewDos->Update();
  //lineDosAlpha->Update();
  //
  //view->Update();
  //view->GetInteractor()->Render();
  //view->Render();
  //std::cout << "Clicked." << std::endl;
  qDebug()<<"PlotTransmDosDialog::on_plotDosButton_clicked() 6.";
  //chartDos->GetNumberOfAxes()

  qDebug()<<"PlotTransmDosDialog::on_plotDosButton_clicked() 6a.";
  chartDos->Update();
  qDebug()<<"PlotTransmDosDialog::on_plotDosButton_clicked() 6b.";
  //viewDos->GetScene()->AddItem(chartDos.GetPointer());
  qDebug()<<"PlotTransmDosDialog::on_plotDosButton_clicked() 6c.";
  //viewDos->Update();
  qDebug()<<"PlotTransmDosDialog::on_plotDosButton_clicked() 6d.";
  ui.qvtkWidgetDos->update();
  qDebug()<<"PlotTransmDosDialog::on_plotDosButton_clicked() 6e.";

  //originalDosXsize = (double)(chartDos->GetAxis(1)->GetMaximum() - chartDos->GetAxis(1)->GetMinimum());
  //originalDosYsize = (double)(chartDos->GetAxis(0)->GetMaximum() - chartDos->GetAxis(0)->GetMinimum());
  originalDosXsize = (double)(chartDos->GetAxis(0)->GetMaximum() - chartDos->GetAxis(0)->GetMinimum());
  originalDosYsize = (double)(chartDos->GetAxis(1)->GetMaximum() - chartDos->GetAxis(1)->GetMinimum());

  /*
  connect(ui.horizontalSliderqvtkWidget3, SIGNAL(valueChanged(int)), this, SLOT(setDosXRange(int)));
  connect(ui.verticalSliderqvtkWidget3, SIGNAL(valueChanged(int)), this, SLOT(setDosYRange(int)));
  */ // COMMENTED BY C.SALGADO ON 2016-08-03 TO AVOID VTK CRASH WHEN RESTARTING INTERACTOR.

  qDebug()<<"PlotTransmDosDialog::on_plotDosButton_clicked() 7";

}

void PlotTransmDosDialog::on_outputPDosAlphaColumn_selected(){
  qDebug()<<"PlotTransmDosDialog::on_outputPDosAlphaColumn_selected() 0";
  //QModelIndexList selectedColumnsAlpha = ui.outPDosAlphaTableView->selectionModel()->selectedColumns().;
  //selectedColumnsAlpha.in
  int currentColumnAlpha = ui.outPDosAlphaTableView->selectionModel()->currentIndex().column();
  qDebug()<<"PlotTransmDosDialog::on_outputPDosAlphaColumn_selected() currentColumnAlpha = "<<currentColumnAlpha;

  if(currentColumnAlpha>0){
    on_plotPDosButton_clicked(currentColumnAlpha-1);
  }

  //ui.outPDosAlphaTableView->selectionModel()->selectedRows()
}

void PlotTransmDosDialog::on_outputPDosBetaColumn_selected(){
  qDebug()<<"PlotTransmDosDialog::on_outputPDosAlphaColumn_selected() 0";
  //QModelIndexList selectedColumnsAlpha = ui.outPDosAlphaTableView->selectionModel()->selectedColumns().;
  //selectedColumnsAlpha.in
  int currentColumnBeta = ui.outPDosBetaTableView->selectionModel()->currentIndex().column();
  qDebug()<<"PlotTransmDosDialog::on_outputPDosAlphaColumn_selected() currentColumnAlpha = "<<currentColumnBeta;

  if(currentColumnBeta>0){
    on_plotPDosButton_clicked(currentColumnBeta-1);
  }

  //ui.outPDosAlphaTableView->selectionModel()->selectedRows()
}

void PlotTransmDosDialog::on_plotPDosButton_clicked(int currentColumn){
    qDebug()<<"PlotTransmDosDialog::on_plotPDosButton_clicked() 0";
    //chartPDos->RemovePlot(0);
    //chartPDos->RemovePlot(1);
    //chartPDos->RecalculateBounds();
    //chartPDos->RecalculatePlotBounds();
    //chartPDos->RecalculatePlotTransforms();
    qDebug()<<"PlotTransmDosDialog::on_plotPDosButton_clicked() 0a";
    chartPDos->ClearPlots();
    qDebug()<<"PlotTransmDosDialog::on_plotPDosButton_clicked() 0b";
    //for (int i = 0; i < viewPDos->GetScene()->GetNumberOfItems(); ++i){
    //  viewPDos->GetScene()->GetItem(i)->ClearItems();
    //}
    qDebug()<<"PlotTransmDosDialog::on_plotPDosButton_clicked() 0c";
    for (int i = 0; i < chartPDos->GetNumberOfAxes(); ++i){
      chartPDos->GetAxis(i)->ClearItems();
    }
    qDebug()<<"PlotTransmDosDialog::on_plotPDosButton_clicked() 0d";
    for (int i = 0; i < chartPDos->GetNumberOfPlots(); ++i){
      chartPDos->RemovePlot(i);
    }
    qDebug()<<"PlotTransmDosDialog::on_plotPDosButton_clicked() 0e";


// PDos PLOT.
qDebug()<<"PlotTransmDosDialog::on_plotPDosButton_clicked() 1";
QList<QList<double>> dataPDosAlpha = colPDosAlpha;
QList<QList<double>> dataPDosBeta = colPDosBeta;
QList<double> enerdataPDos = enercolPDos;

for (int col=0; col<dataPDosAlpha.size(); ++col){
  for (int row=0; row<dataPDosAlpha[col].size(); ++row){
//    qDebug()<<"dataPDosAlpha["<<col<<"]["<<row<<"] = "<<dataPDosAlpha[col][row];
  }
}

qint32 numcolDataPDosAlpha = dataPDosAlpha.size();
int n = dataPDosAlpha[currentColumn].size();
QVector<float> x(enerdataPDos.size()), y1(n);
//QVector<QVector<float>> y0(numcolDataPDosAlpha);
QVector<QVector<float>> y0(2);
//for (int col=0; col<dataPDosAlpha.size(); ++col){
for (int col=0; col<2; ++col){
  y0[col].resize(dataPDosAlpha[currentColumn].size());
}

/*
qint32 numcolDataPDosBeta = dataPDosBeta.size();
int nBeta = dataPDosBeta[0].size();
QVector<float> y1Beta(nBeta);
QVector<QVector<float>> y0Beta(numcolDataPDosBeta);
for (int col=0; col<numcolDataPDosBeta; ++col){
  y0Beta[col].resize(nBeta);
}
*/

//vtkNew<vtkFloatArray> xvtkfloat;
//vtkNew<vtkFloatArray> y0vtkfloat;
qDebug()<<"PlotTransmDosDialog::on_plotPDosButton_clicked() 2. dataPDosAlpha.size() = "<<dataPDosAlpha.size();
//xvtkfloat->SetNumberOfComponents(n);
//y0vtkfloat->SetNumberOfComponents(n);
for (int i=0; i<enerdataPDos.size(); ++i)        {
  x[i] = (float)enerdataPDos[i];
  //xvtkfloat->SetValue(i,(float)enerdataPDos[i]);
}
/*
for (int col=0; col<dataPDosAlpha.size(); ++col){
  for (int row=0; row<dataPDosAlpha[col].size(); ++row){
    y0[col][row] = (float)dataPDosAlpha[col][row];
    qDebug()<<"dataPDos["<<col<<"]["<<row<<"] = "<< dataPDosAlpha[col][row];
  }
}
*/
for (int row=0; row<dataPDosAlpha[currentColumn].size(); ++row){
  y0[0][row] = (float)dataPDosAlpha[currentColumn][row];
  y0[1][row] = (float)dataPDosBeta[currentColumn][row];
//  qDebug()<<"y0[0:1]["<<row<<"] = ["<< y0[0][row]<<","<<y0[1][row]<<"]";
}

  //-----------------------------------------------------------------
  //-----------------------------------------------------------------

  qDebug()<<"PlotTransmDosDialog::PlotTransmPDosDialog() 3";

  // Create a table with some points in it...
  //vtkNew<vtkTable> table;
  vtkSmartPointer<vtkTable> table =
      vtkSmartPointer<vtkTable>::New();
  //vtkNew<vtkTable> tablePDos;

  vtkSmartPointer<vtkTable> tableFermi =
      vtkSmartPointer<vtkTable>::New();

  vtkNew<vtkFloatArray> arrFermiX;
  arrFermiX->SetName("X Fermi");
  tableFermi->AddColumn(arrFermiX.GetPointer());

  vtkNew<vtkFloatArray> arrFermiY;
  arrFermiY->SetName("Y Fermi");
  tableFermi->AddColumn(arrFermiY.GetPointer());

  vtkNew<vtkFloatArray> arrPDosX;
  arrPDosX->SetName("X Axis");
  table->AddColumn(arrPDosX.GetPointer());

  vtkNew<vtkFloatArray> AlphaPDos;
  AlphaPDos->SetName("AlphaPDos");
  table->AddColumn(AlphaPDos.GetPointer());

  vtkNew<vtkFloatArray> BetaPDos;
  BetaPDos->SetName("BetaPDos");
  table->AddColumn(BetaPDos.GetPointer());

  vtkNew<vtkCharArray> validMask;
  validMask->SetName("ValidMask");
  table->AddColumn(validMask.GetPointer());


  qDebug()<<"PlotTransmDosDialog::PlotTransmPDosDialog() 4";

  // Test charting with a few more points...
  float inc = 7.5 / (n-1);
  table->SetNumberOfRows(dataPDosAlpha[currentColumn].size());
  for (int row = 0; row < dataPDosAlpha[currentColumn].size(); ++row){
    //table->SetValue(i, 0, i * inc + 0.01);
    table->SetValue(row, 0, (float)(x[row]));
    //table->SetValue(i, 1, y0[0][i]);
    //table->SetValue(row, 1, y0[currentColumn][row]);
    table->SetValue(row, 1, y0[0][row]);

    if(y0.size() == 2){
      //table->SetValue(i, 2, y0[1][row]);
      table->SetValue(row, 2, y0[1][row]);
      //table->SetValue(row, 2, y0[currentColumn][row]);
      //BetaPDosUp->SetValue(i,-y0[1][i]);
      //table->SetValue(i, 4, -y0[1][i] - 0.01);
    }

    validMask->SetValue(row,1);
//    qDebug()<<"table->GetValue("<<row<<",2) = "<<table->GetValue(row,2).ToFloat();
  }



  // Add multiple line plots, setting the colors etc
  //linePDos = vtkPlotLine::SafeDownCast(chartPDos->AddPlot(vtkChart::LINE));
  //vtkPlot *line = chartPDos->AddPlot(vtkChart::LINE);
  vtkSmartPointer<vtkPlotLine> linePDosAlpha =
      vtkSmartPointer<vtkPlotLine>::New();
  //chartPDos->RemovePlot(0);
  linePDosAlpha = vtkPlotLine::SafeDownCast(chartPDos->AddPlot(vtkChart::LINE));
  //line->SetInputData(table.GetPointer());
  //line->SetInputArray(1, "AlphaPDosUp");
#if VTK_MAJOR_VERSION <= 5
  linePDosAlpha->SetInput(table, 0, 1);
#else
  linePDosAlpha->SetInputData(table, 0, 1);
#endif
  linePDosAlpha->SetColor( 0, 0, 255, 255 );
  linePDosAlpha->SetWidth(2.0);
  //vtkPlotLine::SafeDownCast(line)->SetMarkerStyle(vtkPlotLine::CROSS);

  linePDosAlpha->SetValidPointMaskName("ValidMask");

  linePDosAlpha->Update();
  qDebug()<<"Finish Alpha";


  if(y0.size() == 2){
    //linePDosBeta->vtkPlotLine::SafeDownCast(chartPDos->AddPlot(vtkChart::LINE));
    //line = chartPDos->AddPlot(vtkChart::LINE);
    vtkSmartPointer<vtkPlotLine> linePDosBeta =
        vtkSmartPointer<vtkPlotLine>::New();
    //chartPDos->RemovePlot(1);
    linePDosBeta = vtkPlotLine::SafeDownCast(chartPDos->AddPlot(vtkChart::LINE));

#if VTK_MAJOR_VERSION <= 5
    linePDosBeta->SetInput(table, 0, 2);
#else
    linePDosBeta->SetInputData(table, 0, 2);
#endif
    linePDosBeta->SetColor( 255, 0, 0, 255 );
    linePDosBeta->SetWidth(2.0);


//#ifndef WIN32
//  line->GetPen()->SetLineType(vtkPen::DASH_LINE);
//#endif

    linePDosBeta->SetValidPointMaskName("ValidMask");
    //vtkPlotLine::SafeDownCast(line)->SetMarkerStyle(vtkPlotLine::CIRCLE);
    linePDosBeta->Update();
    qDebug()<<"Finish Beta";
  }

  qDebug()<<"PlotTransmDosDialog::on_plotPDosButton_clicked() 4 Fermi";
  //chartPDos->GetAxis(0)->GetMaximum();
  tableFermi->SetNumberOfRows(2);
  tableFermi->SetValue(0, 0, -0.0000001);
  tableFermi->SetValue(1, 0, 0.0000001);
  qDebug()<<"PlotTransmPDosDialog::on_plotPDosButton_clicked() 4 Fermi a";
  //tableFermi->SetValue(0, 1, chartPDos->GetAxis(0)->GetMinimum());
  //tableFermi->SetValue(1, 1, chartPDos->GetAxis(0)->GetMaximum());
  //tableFermi->SetValue(0, 1, -10.0);
  //tableFermi->SetValue(1, 1, 10.0);
  //tableFermi->SetValue(0, 1, BetaPDos->GetDataTypeMin());
  //tableFermi->SetValue(1, 1, AlphaPDos->GetDataTypeMax());

  double fermimin = 0.0;
  double fermimax = 0.0;
  if(y0.size() == 2){
    double alphamin = *std::min_element(y0[0].begin(), y0[0].end());
    double alphamax = *std::max_element(y0[0].begin(), y0[0].end());
    double betamin = *std::min_element(y0[1].begin(), y0[1].end());
    double betamax = *std::max_element(y0[1].begin(), y0[1].end());

    fermimin = 1.5*fmin(alphamin,betamin);
    fermimax = 1.5*fmax(alphamax,betamax);
  }else{
    fermimin = 1.5* (*std::min_element(y0[0].begin(), y0[0].end()));
    fermimax = 1.5* (*std::max_element(y0[0].begin(), y0[0].end()));
  }
  tableFermi->SetValue(0, 1, fermimin);
  tableFermi->SetValue(1, 1, fermimax);

//  qDebug()<<"tableFermi->GetValue(0,0) = "<<tableFermi->GetValue(0,0).ToDouble();
//  qDebug()<<"tableFermi->GetValue(0,1) = "<<tableFermi->GetValue(0,1).ToDouble();
//  qDebug()<<"tableFermi->GetValue(1,0) = "<<tableFermi->GetValue(1,0).ToDouble();
//  qDebug()<<"tableFermi->GetValue(1,1) = "<<tableFermi->GetValue(1,1).ToDouble();
  qDebug()<<"PlotTransmDosDialog::on_plotPDosButton_clicked() 4 Fermi b";
  vtkSmartPointer<vtkPlotLine> linePDosFermi =
      vtkSmartPointer<vtkPlotLine>::New();
  //chartPDos->RemovePlot(0);
  qDebug()<<"PlotTransmDosDialog::on_plotPDosButton_clicked() 4 Fermi c";
  linePDosFermi = vtkPlotLine::SafeDownCast(chartPDos->AddPlot(vtkChart::LINE));
  //line->SetInputData(table.GetPointer());
  //line->SetInputArray(1, "FermiPDosUp");
  qDebug()<<"PlotTransmDosDialog::on_plotPDosButton_clicked() 4 Fermi d";
#if VTK_MAJOR_VERSION <= 5
  linePDosFermi->SetInput(tableFermi, 0, 1);
#else
  linePDosFermi->SetInputData(tableFermi, 0, 1);
#endif
  qDebug()<<"PlotTransmDosDialog::on_plotPDosButton_clicked() 4 Fermi e";
  linePDosFermi->SetColor( 0, 255, 0, 255 );
  linePDosFermi->SetWidth(2.0);
  //vtkPlotLine::SafeDownCast(line)->SetMarkerStyle(vtkPlotLine::CROSS);

  //linePDosFermi->SetValidPointMaskName("ValidMask");

  linePDosFermi->Update();
  qDebug()<<"Finish Fermi";

  chartPDos->GetPlot(0)->GetXAxis()->SetTitle("Energy (eV)");
  chartPDos->GetPlot(0)->GetYAxis()->SetTitle("PDOS");

  vtkSmartPointer<vtkTextProperty> XaxisLabelProp =
      vtkSmartPointer<vtkTextProperty>::New();
  XaxisLabelProp = chartPDos->GetPlot(0)->GetXAxis()->GetTitleProperties();
  XaxisLabelProp->SetFontSize(20);
  vtkSmartPointer<vtkTextProperty> YaxisLabelProp =
      vtkSmartPointer<vtkTextProperty>::New();
  YaxisLabelProp = chartPDos->GetPlot(0)->GetYAxis()->GetTitleProperties();
  YaxisLabelProp->SetFontSize(20);


  qDebug()<<"PlotTransmDosDialog::on_plotPDosButton_clicked() 5";
  //viewPDos->Update();
  //linePDosAlpha->Update();
  //
  //view->Update();
  //view->GetInteractor()->Render();
  //view->Render();
  //std::cout << "Clicked." << std::endl;
  qDebug()<<"PlotTransmDosDialog::on_plotPDosButton_clicked() 6.";
  //chartPDos->GetNumberOfAxes()

  qDebug()<<"PlotTransmDosDialog::on_plotPDosButton_clicked() 6a.";
  chartPDos->Update();
  qDebug()<<"PlotTransmDosDialog::on_plotPDosButton_clicked() 6b.";
  //viewPDos->GetScene()->AddItem(chartPDos.GetPointer());
  qDebug()<<"PlotTransmDosDialog::on_plotPDosButton_clicked() 6c.";
  //viewPDos->Update();
  qDebug()<<"PlotTransmDosDialog::on_plotPDosButton_clicked() 6d.";
  ui.qvtkWidgetPDos->update();
  qDebug()<<"PlotTransmDosDialog::on_plotPDosButton_clicked() 6e.";

  //originalPDosXsize = (double)(chartPDos->GetAxis(1)->GetMaximum() - chartPDos->GetAxis(1)->GetMinimum());
  //originalPDosYsize = (double)(chartPDos->GetAxis(0)->GetMaximum() - chartPDos->GetAxis(0)->GetMinimum());
  originalPDosXsize = (double)(chartPDos->GetAxis(0)->GetMaximum() - chartPDos->GetAxis(0)->GetMinimum());
  originalPDosYsize = (double)(chartPDos->GetAxis(1)->GetMaximum() - chartPDos->GetAxis(1)->GetMinimum());

  /*
  connect(ui.horizontalSliderqvtkWidget3, SIGNAL(valueChanged(int)), this, SLOT(setPDosXRange(int)));
  connect(ui.verticalSliderqvtkWidget3, SIGNAL(valueChanged(int)), this, SLOT(setPDosYRange(int)));
  */ // COMMENTED BY C.SALGADO ON 2016-08-03 TO AVOID VTK CRASH WHEN RESTARTING INTERACTOR.

  qDebug()<<"PlotTransmDosDialog::on_plotPDosButton_clicked() 7";

}


void PlotTransmDosDialog::on_exportRenderTransmButton_clicked()
{
  //pngWriter("screenshot2.png");
  pngWriter("screenshot2.png", 1);
}

void PlotTransmDosDialog::on_exportRenderDosButton_clicked()
{
  //pngWriter("screenshot2.png");
  pngWriter("screenshot2.png", 2);
}

void PlotTransmDosDialog::on_exportRenderPDosButton_clicked()
{
  //pngWriter("screenshot2.png");
  pngWriter("screenshot2.png", 3);
}
//int main(int argc, char *argv[])
//void PlotTransmDosDialog::pngWriter(vtkRenderer renderer){
//void PlotTransmDosDialog::pngWriter(QWidget exportWidget, QString fileName)
void PlotTransmDosDialog::pngWriter(QString fileName, int widgetSelector)
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
      windowToImageFilter->SetInput(ui.qvtkWidget3->GetRenderWindow());
    }else if(widgetSelector == 2){
      windowToImageFilter->SetInput(ui.qvtkWidgetDos->GetRenderWindow());
    }else if(widgetSelector == 3){
      windowToImageFilter->SetInput(ui.qvtkWidgetPDos->GetRenderWindow());
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
    qDebug()<<"PlotTransmDosDialog::pngWriter() 5 *c_str2 = ba.data() ="<<c_str2;
    writer->SetInputConnection(windowToImageFilter->GetOutputPort());
    writer->Write();
    qDebug()<<"PlotTransmDosDialog::pngWriter() 5a FINISH EXPORT WRITE";

  //-----------------------------------------------------------------
  //-----------------------------------------------------------------

  //return EXIT_SUCCESS;
}

void PlotTransmDosDialog::jpegWriter(QString fileName, int widgetSelector)
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
      windowToImageFilter->SetInput(ui.qvtkWidget3->GetRenderWindow());
    }else if(widgetSelector == 2){
      windowToImageFilter->SetInput(ui.qvtkWidgetDos->GetRenderWindow());
    }else if(widgetSelector == 3){
      windowToImageFilter->SetInput(ui.qvtkWidgetPDos->GetRenderWindow());
    }
    // IF SetMagnification(3); THE EXPORTED IMAGE SHOWS A WARHOLIAN
    //windowToImageFilter->SetMagnification(3); //set the resolution of the output image (3 times the current resolution of vtk render window)
    //windowToImageFilter->SetInputBufferTypeToRGBA(); //also record the alpha (transparency) channel
    windowToImageFilter->SetInputBufferTypeToRGB(); // JPEG ONLY SUPPORTS RGB, NOT RGBA ALPHA CHANNEL (TRANSPARENCY).
    windowToImageFilter->ReadFrontBufferOff(); // read from the back buffer
    windowToImageFilter->Update();


    vtkSmartPointer<vtkJPEGWriter> writer =
      vtkSmartPointer<vtkJPEGWriter>::New();
    //writer->SetFileName("screenshot2.png");
    //writer->SetFileName(fileName);
    QByteArray ba = fileName.toLatin1();
    const char *c_str2 = ba.data();
    writer->SetFileName(c_str2);
    qDebug()<<"PlotTransmDosDialog::pngWriter() 5 *c_str2 = ba.data() ="<<c_str2;
    writer->SetInputConnection(windowToImageFilter->GetOutputPort());
    writer->Write();
    qDebug()<<"PlotTransmDosDialog::pngWriter() 5a FINISH EXPORT WRITE";

  //-----------------------------------------------------------------
  //-----------------------------------------------------------------

  //return EXIT_SUCCESS;
}

} // end namespace QtPlugins
} // end namespace Avogadro
