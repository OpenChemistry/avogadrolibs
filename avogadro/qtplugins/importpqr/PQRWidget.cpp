#include "PQRWidget.h"
#include "PQRRequest.h"
#include "ui_PQRWidget.h"

namespace Avogadro {
namespace QtPlugins {
PQRWidget::PQRWidget(QWidget* parent) :
    QDialog(parent),
    ui(new Ui::PQRWidget)
{
  ui->setupUi(this);

	ui->tableWidget->setColumnCount(3);
	ui->tableWidget->setHorizontalHeaderLabels(QStringList() << "Name" << "Formula" << "Mass (g/mol)");
	ui->tableWidget->horizontalHeader()->setStretchLastSection(true);
	ui->tableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);
	ui->tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
  ui->tableWidget->setSortingEnabled(true);
  connect(ui->searchButton, SIGNAL(clicked(bool)), this, SLOT(searchAction()));
	connect(ui->downloadButton, SIGNAL(clicked(bool)), this, SLOT(downloadMol()));
	connect(ui->tableWidget, SIGNAL(cellDoubleClicked(int, int)),
		this, SLOT(molSelected(int, int)));

  request = new PQRRequest(ui->tableWidget, ui->svgPreview, ui->filename, ui->nameDisplay, ui->formulaDisplay, ui->extensionType);
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
    QString url = "https://pqr.pitt.edu/api/browse/"+ui->molName->text() + "/" + ui->searchTypeBox->currentText();
    request->sendRequest(url);
}

/**
* @brief Called when a table result is double clicked to display preview information
* about the result before downloading.
* @param row The row of the result selected.
* @param col The column of the result selected.
*/
void PQRWidget::molSelected(int row, int col)
{
	currentlySelectedMol = request->molSelected(row);

  QString url = "https://pqr.pitt.edu/static/data/svg/"+ currentlySelectedMol + ".svg";

  ui->nameDisplay->setText(currentlySelectedMol);
  ui->svgPreview->load(url);
  ui->svgPreview->show();
}

/**
* @brief Called when the download button is clicked to send a request to download
* molecule information from PQR.
*/
void PQRWidget::downloadMol()
{
	QString mol2url = currentlySelectedMol;
	if (mol2url != "N/A" && mol2url != "") {
		QString ext = ui->extensionType->currentText();
		if (ext == "mol2") {
			ext = "mol"; //easiest workaround to PQR api using /mol not /mol2
		}
		if (ext == "mol" || ext == "json") {
			mol2url.remove(0, 3); //remove first 3 characters to map to PQR's url
			QString url = "https://pqr.pitt.edu/api/" + ext + "/" + mol2url;
			request->sendRequest(url, mol2url, ui->downloadFolder->text(), "."+ext);
		}
		else if (ext == "svg") {
			QString url = "https://pqr.pitt.edu/static/data/svg/"+ mol2url + ".svg";
			request->sendRequest(url, mol2url.remove(0, 3), ui->downloadFolder->text(), "." + ext);
		}
	}
}

} //namespace QtPlugins
} //namespace Avogadro
