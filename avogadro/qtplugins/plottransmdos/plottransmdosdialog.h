/*=========================================================================

  Program:   Visualization Toolkit
  Module:    plottransmdosdialog.h
  Language:  C++

  Copyright 2009 Sandia Corporation.
  Under the terms of Contract DE-AC04-94AL85000, there is a non-exclusive
  license for use of this work by or on behalf of the
  U.S. Government. Redistribution and use in source and binary forms, with
  or without modification, are permitted provided that this Notice and any
  statement of authorship are reproduced on all copies.

=========================================================================*/
#ifndef PLOTTRANSMDOSDIALOG_H
#define PLOTTRANSMDOSDIALOG_H

#include <QProcess>
#include <QProgressDialog>

#include <QtCore/QSettings>

#include <QWidget>
#include <QFile>
#include <QFileDialog>
#include <QTextStream>
#include <QDebug>
#include <QString>
#include <QStandardItemModel>
#include <QVector>
#include <QList>
//#include "myclass.h"
#include <iostream>

#include "plottransmdos.h"
#include "ui_plottransmdosdialog.h"

#include "vtkSmartPointer.h"    // Required for smart pointer internal ivars.
#include "vtkSystemIncludes.h"    // ADDED BY C.SALGADO

//#include <QDialog>

#include <vtkDataObjectToTable.h>
#include <vtkElevationFilter.h>
#include <vtkPolyDataMapper.h>
#include <vtkQtTableView.h>
#include <vtkRenderer.h>
#include <vtkRenderWindow.h>
#include <vtkVectorText.h>

#include <vtkSliderWidget.h>
#include <vtkSliderRepresentation2D.h>
#include <vtkCallbackCommand.h>

#include "vtkSmartPointer.h"


#include "vtkAxis.h"
#include "vtkBrush.h"
#include "vtkCharArray.h"
#include "vtkChartXY.h"
#include "vtkContextScene.h"
#include </home/carlos/Qt-Projects/Avogadro2OShared/build-openchemistry-Desktop-Default/prefix/include/vtk-6.3/vtkContextView.h>
//#include <vtkContextView.h>
#include "vtkFloatArray.h"
#include "vtkNew.h"
#include "vtkPlotArea.h"
#include "vtkPlotLine.h"
#include "vtkPlot.h"
//#include "vtkRenderWindow.h"
#include "vtkRenderWindowInteractor.h"
//#include "vtkSmartPointer.h"
#include "vtkTable.h"

#include <algorithm>

// Forward Qt class declarations
//class Ui_PlotTransmDosDialog;

// Forward VTK class declarations
class vtkQtTableView;

class QJsonObject;

namespace MoleQueue {
class JobObject;
}

namespace Avogadro {
namespace QtGui {
class Molecule;
}

namespace QtPlugins {
//class GamessHighlighter;
//class SimuneAntHighlighter;

/*
class vtkSliderCallback : public vtkCommand
{
public:
  static vtkSliderCallback *New()
    {
    return new vtkSliderCallback;
    }
  virtual void Execute(vtkObject *caller, unsigned long, void*)
    {
    vtkSliderWidget *sliderWidget =
      reinterpret_cast<vtkSliderWidget*>(caller);
    //this->SphereSource->SetPhiResolution(static_cast<vtkSliderRepresentation *>(sliderWidget->GetRepresentation())->GetValue());
    //this->SphereSource->SetThetaResolution(static_cast<vtkSliderRepresentation *>(sliderWidget->GetRepresentation())->GetValue());
    //double d = static_cast<vtkSliderRepresentation *>(sliderWidget->GetRepresentation())->GetValue();
    //double d = sliderWidget->GetRepresentation()->GetValue();
    //this->chart->GetAxis(1)->SetUnscaledRange(-d,d);
    //chart->GetAxis(1)->SetUnscaledRange( static_cast<vtkSliderRepresentation *>(sliderWidget->GetRepresentation())->GetValue() ,
    //                                           static_cast<vtkSliderRepresentation *>(sliderWidget->GetRepresentation())->GetValue() );
  }
  //vtkSliderCallback():SphereSource(0) {}
  //vtkSphereSource *SphereSource;
  vtkSliderCallback():chart(0) {}
  vtkSmartPointer<vtkChartXY>         *chart;
  };
*/

class PlotTransmDosDialog : public QDialog
{
  Q_OBJECT
 public:

   // Constructor/Destructor
   //PlotTransmDosDialog();
   explicit PlotTransmDosDialog(QWidget *parent_ = 0, Qt::WindowFlags f = 0 );
   ~PlotTransmDosDialog();

   // OPENTRANSMWIDGET
   void auto_Open_triggered();
   // PRINTTRANSMWID
   static void autoPrintTransmission();

 public slots:

   virtual void slotOpenFile();
   virtual void slotExit();

   // OPENTRANSMWIDGET
   void receiveSignal()
    {
        std::cout << "signal received" << std::endl;
    }


 private Q_SLOTS:

   void setTransmXRange(int i);
   void setTransmYRange(int i);
   void setDosXRange(int i);
   void setDosYRange(int i);
   void setPDosXRange(int i);
   void setPDosYRange(int i);
   //void autoScalePlot();

 protected:

 protected slots:

private slots:
   //void on_horizontalSliderqvtkWidget2_rangeChanged(int min, int max);
   //void on_verticalSliderqvtkWidget2_rangeChanged(int min, int max);
   void on_autoScaleButton_clicked();

   // PRINTTRANSMWID
   void on_outputTransmButton_clicked();
   void on_outputDosButton_clicked();
   void on_outputPDosButton_clicked();
   //void on_outputPDosColumn_selected(QItemSelection selected, QItemSelection deselected);
   void on_outputPDosAlphaColumn_selected();
   void on_outputPDosBetaColumn_selected();

   // OPENTRANSMWIDGET
   void on_action_Open_triggered();
   void checkString(QString &temp, QChar character = 0);
   //void modcheckString(QString &temp, QChar character = 0);
   void modcheckString(QString &temp, QChar character = 0);
   void modcheckStringDos(QString &temp, QChar character = 0);
   void modcheckStringPDos(QString &temp, QChar character = 0);
   //void on_outTransmPushButton_clicked();


   //void pngWriter(QVTKWidget exportWidget, QString fileName);
   //void pngWriter(QString fileName);
   //void imageWriter(QString fileName, bool choosePngJpeg, int widgetSelector); // widgetSelector is 1 for Transm, 2 for DOS.
   void pngWriter(QString fileName, int widgetSelector);
   void jpegWriter(QString fileName, int widgetSelector);

   void on_exportRenderTransmButton_clicked();
   void on_exportRenderDosButton_clicked();
   void on_exportRenderPDosButton_clicked();

   //void on_exportRenderDosButton_clicked();

   // FOR THE MENU IN THE DIALOG.
   //void newFile();
   void open();
   void openTransm();
   void openDos();
   void openPDos();
   void save();
   void print();
   void exportPlotTransm();
   void exportPlotDos();
   void exportPlotPDos();
   void close();

private:

   // PRINTTRANSMWID
   void on_printTransmButton_clicked();
   void on_plotTransmButton_clicked();
   void on_plotLinesDirtyTransmButton_clicked();
   void on_plotTransmButton_clicked_old();
   void on_plotTransmAxisLimitsButton_clicked();
   void on_plotAreaTransmButton_clicked();

   void on_plotDosButton_clicked();
   void on_plotPDosButton_clicked(int currentColumn);


   void clearPlotTransmItems();
   void clearPlotDosItems();
   void clearPlotPDosItems();


   vtkSmartPointer<vtkQtTableView>         TableView;

   vtkSmartPointer<vtkContextView>         view;
   vtkSmartPointer<vtkChartXY>         chart;

   vtkPlotArea* area;

   // Designer form
   //Ui_PlotTransmDosDialog *ui;
   Ui::PlotTransmDosDialog ui;

   double originalXsize = 10.0;
   double originalYsize = 10.0;

   double newXsize = 10.0;
   double newYsize = 10.0;

   //vtkSliderWidget *sliderWidget =
   //  reinterpret_cast<vtkSliderWidget*>(caller);
   //vtkSliderCallback():chart(0) {}
   //vtkSmartPointer<vtkChartXY>         *chart;

   //QVTKWidget qvtkWidget2;

   vtkSmartPointer<vtkContextView>         viewTransm;
   vtkSmartPointer<vtkChartXY>         chartTransm;
   vtkSmartPointer<vtkContextView>         viewDos;
   vtkSmartPointer<vtkChartXY>         chartDos;
   vtkSmartPointer<vtkContextView>         viewPDos;
   vtkSmartPointer<vtkChartXY>         chartPDos;

   //vtkSmartPointer<vtkFloatArray> arrTransmX;
   //vtkSmartPointer<vtkFloatArray> arrTransmC;

   //vtkSmartPointer<vtkCharArray> validMaskTransm;

   vtkPlotArea* areaTransm;

   //vtkPlotLine* lineTransmAlpha;
   //vtkPlotLine* lineTransmBeta;
   //vtkSmartPointer<vtkPlotLine> lineTransmAlpha;
   //vtkSmartPointer<vtkPlotLine> lineTransmBeta;

   int numcolDataTransmission = 1;
   int numcolDataDos = 1;
   int numcolDataPDos = 1;

   double originalTransmXsize = 10.0;
   double originalTransmYsize = 10.0;
   double originalDosXsize = 10.0;
   double originalDosYsize = 10.0;
   double originalPDosXsize = 10.0;
   double originalPDosYsize = 10.0;

   double newTransmXsize = 10.0;
   double newTransmYsize = 10.0;
   double newDosXsize = 10.0;
   double newDosYsize = 10.0;
   double newPDosXsize = 10.0;
   double newPDosYsize = 10.0;

   //vtkSmartPointer<vtkTable> tableTransm;


   // OPENTRANSMWIDGET
   QList<QStringList> csv;
   QStandardItemModel *model;
   QStandardItemModel *auxmodel;
   QList<QStandardItem*> standardItemList;
   QStandardItemModel *modelDos;
   QStandardItemModel *auxmodelDos;
   QList<QStandardItem*> standardItemListDos;
   QStandardItemModel *modelPDos;
   QStandardItemModel *modelPDosAlpha;
   QStandardItemModel *modelPDosBeta;
   QStandardItemModel *auxmodelPDos;
   QList<QStandardItem*> standardItemListPDos;
   QList<QStandardItem*> standardItemListPDosAlpha;
   QList<QStandardItem*> standardItemListPDosBeta;
   // MYCLASS
   //static qint32 size;
   //static qint32 s_count;
   //static QList<double> colTransmission;
   //static QList<double> enercolTransmission;
   //static QString jobname;
   qint32 size = 1;
   qint32 s_count = 0;
   //QList<double> colTransmission;
   QList<QList<double>> colTransmission;
   QList<double> enercolTransmission;
   QList<double> singlespincolTransmission;
   QList<QList<double>> colDos;
   QList<double> enercolDos;
   QList<double> singlespincolDos;
   QList<QList<double>> colPDos;
   QList<QList<double>> colPDosAlpha;
   QList<QList<double>> colPDosBeta;
   QList<double> enercolPDos;
   QList<double> singlespincolPDos;

   QString jobname;

   // Plot Window.
   //vtkSmartPointer<vtkRenderWindowInteractor> renderWindowInteractor;
   //vtkSmartPointer<vtkRenderer> renderer;
   //vtkSmartPointer<vtkRenderWindow> renderWindow;

   // FOR THE MENU IN THE DIALOG.
   void createActions();
   void connectActions();
   void createMenus();

   QMenu *fileMenu;
   //QAction *actionNew;
   //QAction *actionOpenFile;
   QAction *openAct;
   QAction *saveAct;
   QAction *printAct;
   QAction *exportAct;
   QAction *helpAct;
   QAction *exitAct;

   QLabel *infoLabel;

};

} // end namespace QtPlugins
} // end namespace Avogadro

#endif // PLOTTRANSMDOSDIALOG_H
