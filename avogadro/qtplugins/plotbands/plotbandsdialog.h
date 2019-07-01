/*=========================================================================

  Program:   Visualization Toolkit
  Module:    plotbandsdialog.h
  Language:  C++

  Copyright 2009 Sandia Corporation.
  Under the terms of Contract DE-AC04-94AL85000, there is a non-exclusive
  license for use of this work by or on behalf of the
  U.S. Government. Redistribution and use in source and binary forms, with
  or without modification, are permitted provided that this Notice and any
  statement of authorship are reproduced on all copies.

=========================================================================*/
#ifndef PLOTBANDSDIALOG_H
#define PLOTBANDSDIALOG_H

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

#include "plotbands.h"
#include "ui_plotbandsdialog.h"

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
//class Ui_PlotBandsDialog;

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

class PlotBandsDialog : public QDialog
{
  Q_OBJECT
 public:

   // Constructor/Destructor
   //PlotBandsDialog();
   explicit PlotBandsDialog(QWidget *parent_ = 0, Qt::WindowFlags f = 0 );
   ~PlotBandsDialog();

   // OPENTRANSMWIDGET
   //void auto_Open_triggered();
   // PRINTTRANSMWID
   static void autoPrintBandStructure();

 public slots:

   virtual void slotOpenFile();
   virtual void slotExit();

   // OPENTRANSMWIDGET
   void receiveSignal()
    {
        std::cout << "signal received" << std::endl;
    }


 private Q_SLOTS:

   void setBandsXRange(int i);
   void setBandsYRange(int i);
   //void autoScalePlot();

 protected:

 protected slots:

private slots:
   //void on_horizontalSliderqvtkWidget2_rangeChanged(int min, int max);
   //void on_verticalSliderqvtkWidget2_rangeChanged(int min, int max);
   void on_autoScaleButton_clicked();

   // PRINTTRANSMWID
   void on_outputBandsButton_clicked();
   void on_outputBandsButton_clicked_old();

   // OPENTRANSMWIDGET
   //void on_action_Open_triggered();
   //void modcheckString(QString &temp, QChar character = 0);
   //void on_outBandsPushButton_clicked();
   int modcheckStringBands(QString &temp, QChar character = 0, int bandsnumspin = 1, int bandsnumcol = 1000);
   int modcheckStringBandsData(QString &temp, QChar character = 0);
   int modcheckStringBandsBrillouin(QString &temp, QChar character = 0);


   //void pngWriter(QVTKWidget exportWidget, QString fileName);
   //void pngWriter(QString fileName);
   //void imageWriter(QString fileName, bool choosePngJpeg, int widgetSelector); // widgetSelector is 1 for Bands, 2 for DOS.
   void pngWriter(QString fileName, int widgetSelector);
   void jpegWriter(QString fileName, int widgetSelector);

   void on_exportRenderBandsButton_clicked();

   //void on_exportRenderDosButton_clicked();

   // FOR THE MENU IN THE DIALOG.
   //void newFile();
   void open();
   void openBands();
   void openDos();
   void openPDos();
   void save();
   void print();
//   void exportPlotTransm();
//   void exportPlotDos();
//   void exportPlotPDos();
   void exportPlotBands();
   void close();

private:

   // PRINTTRANSMWID
   void on_plotBandsButton_clicked_old();
   void on_plotBandsButton_clicked();

   void clearPlotBandsItems();


   // Designer form
   //Ui_PlotBandsDialog *ui;
   Ui::PlotBandsDialog ui;



   vtkSmartPointer<vtkContextView>         viewBands;
   vtkSmartPointer<vtkChartXY>         chartBands;

   //vtkSmartPointer<vtkFloatArray> arrBandsX;
   //vtkSmartPointer<vtkFloatArray> arrBandsC;

   //vtkSmartPointer<vtkCharArray> validMaskBands;

   vtkPlotArea* areaBands;

   //vtkPlotLine* lineBandsAlpha;
   //vtkPlotLine* lineBandsBeta;
   //vtkSmartPointer<vtkPlotLine> lineBandsAlpha;
   //vtkSmartPointer<vtkPlotLine> lineBandsBeta;

   int numcolDataBandStructure = 1;

   double originalBandsXsize = 10.0;
   double originalBandsYsize = 10.0;

   double newBandsXsize = 10.0;
   double newBandsYsize = 10.0;

   //vtkSmartPointer<vtkTable> tableBands;


   // OPENTRANSMWIDGET
   QList<QStandardItem*> standardItemList;

   QStandardItemModel *modelBandsAlpha;
   QList<QStandardItem*> standardItemListBandsAlpha;
   QStandardItemModel *modelBandsBeta;
   QList<QStandardItem*> standardItemListBandsBeta;
   QStandardItemModel *datamodel;
   QList<QStandardItem*> datastandardItemList;
   QStandardItemModel *modelBrillouin;
   QList<QStandardItem*> standardItemListBrillouin;
   QList<QStandardItem*> standardItemListBrillouinLabels;
   int brillouinitemcount = 0;


   // MYCLASS
   //static qint32 size;
   //static qint32 s_count;
   //static QList<double> fullBands;
   //static QList<double> enerfullBands;
   //static QString jobname;
   qint32 size = 1;
   qint32 s_count = 0;
   //QList<double> fullBands;
   QList<QList<double>> fullBands;
   QList<QList<double>> fullBandsAlpha;
   QList<QList<double>> fullBandsBeta;
   QList<double> enerfullBands;
   QList<double> singlespinfullBands;

   int bandsnumspin = 1;
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

#endif // PLOTBANDSDIALOG_H
