#include "pqrwidget.h"
#include "importpqr.h"
#include "pqrrequest.h"
#include "ui_pqrwidget.h"

namespace Avogadro {
namespace QtPlugins {

PQRWidget::PQRWidget(QWidget* parent, ImportPQR* p)
  : QDialog(parent), ui(new Ui::PQRWidget)
{
  plugin = p;
  ui->setupUi(this);

  ui->tableWidget->setColumnCount(3);
  ui->tableWidget->setHorizontalHeaderLabels(QStringList() << "Name"
                                                           << "Formula"
                                                           << "Mass (g/mol)");
  ui->tableWidget->horizontalHeader()->setStretchLastSection(true);
  ui->tableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);
  ui->tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
  ui->tableWidget->setSortingEnabled(true);
  connect(ui->searchButton, SIGNAL(clicked(bool)), this, SLOT(searchAction()));
  connect(ui->downloadButton, SIGNAL(clicked(bool)), this, SLOT(downloadMol()));
  connect(ui->tableWidget, SIGNAL(cellClicked(int, int)), this,
          SLOT(molSelected(int, int)));

  request = new PQRRequest(ui->tableWidget, ui->pngPreview, ui->nameDisplay,
                           ui->formulaDisplay, this);
}

PQRWidget::~PQRWidget()
{
  delete request;
  delete ui;
}

/**
* @brief Called when the search button is clicked to send a query to PQR
*/
void PQRWidget::searchAction()
{
  ui->downloadButton->setEnabled(false);
  QString url = "https://pqr.pitt.edu/api/browse/" + ui->molName->text() + "/" +
                ui->searchTypeBox->currentText();
  request->sendRequest(url);
}

/**
* @brief Called when a table result is double clicked to display preview
* information
* about the result before downloading.
* @param row The row of the result selected.
* @param col The column of the result selected.
*/
void PQRWidget::molSelected(int row, int col)
{
  currentlySelectedMol = request->molSelected(row);
  if (currentlySelectedMol == "N/A")
    return;

  ui->downloadButton->setEnabled(true);
}

/**
* @brief Called when PNG data is ready to be loaded
*/
void PQRWidget::loadPNG(QByteArray& data)
{
  QPixmap pixmap;
  pixmap.loadFromData(data, "PNG");
  pixmap = pixmap.scaled(300, 300);
  ui->pngPreview->setPixmap(pixmap);
  ui->pngPreview->show();
}

/**
* @brief Called when the download button is clicked to send a request to
* download
* molecule information from PQR.
*/
void PQRWidget::downloadMol()
{
  QString mol2url = currentlySelectedMol;
  if (mol2url != "N/A" && mol2url != "") {
    mol2url.remove(0, 3); // remove first 3 characters to map to PQR's url
    QString url = "https://pqr.pitt.edu/api/mol/" + mol2url;
    request->sendRequest(url, mol2url);
  }
}

void PQRWidget::loadMolecule(QByteArray& molData, QString name)
{
  plugin->setMoleculeData(molData, name);
}

} // namespace QtPlugins
} // namespace Avogadro
