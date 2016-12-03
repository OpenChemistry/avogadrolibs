#include "PQRRequest.h"
#include "PQRWidget.h"

#include <avogadro/core/elements.h>

namespace Avogadro {
namespace QtPlugins {
/**
* @brief Constuctor to initialize the NetworkAcessManager and set pointers to
* the widget's ui elements.
*/
PQRRequest::PQRRequest(QTableWidget* tw, QWebEngineView* gv, QLineEdit* fn, QLineEdit* nd, QLabel* fd, PQRWidget* w)
{
  //set pointers to ui elements now instead of in individual functions
  table = tw; //pointer to ui table
  svgPreview = gv; //svg GraphicsView
  filename = fn; //filename LineEdit
  nameDisplay = nd; //name
  formulaDisplay = fd; //formula

  //used to load molecule in Avogadro when downloaded
  widget = w;
  oNetworkAccessManager = new QNetworkAccessManager(this);
}

/**
* @brief Free the ui pointers
*/
PQRRequest::~PQRRequest()
{
  delete results;
  delete read;
  delete oNetworkAccessManager;
}

/**
* @brief Sends a network request to search for molecules from PQR;
* @param url The url to query
*/
void PQRRequest::sendRequest(QString url)
{
  reply = oNetworkAccessManager->get(QNetworkRequest(QUrl(url)));
	connect(reply, SIGNAL(finished()), this, SLOT(parseJson()));
}

/**
* @brief Sends a network request to download a file from PQR
* @param url The url to send the request to
* @param mol2 The mol2 representation of the molecule to download
* @param downlaodFolder The path of the download folder
* @param ext The file extension to download
*/
void PQRRequest::sendRequest(QString url, QString mol2, QString downloadFolder)
{
	QUrl httpRequest(url);
	QNetworkRequest request;
	request.setRawHeader("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8");
	request.setRawHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36");
	request.setRawHeader("Accept-Language", "en - US, en; q = 0.8");
	request.setUrl(httpRequest); // Set the url

	reply = oNetworkAccessManager->get(request);

	//see if user wants to change the download folder
	if (downloadFolder.isNull() || downloadFolder.isEmpty()) {
		currentDownloadFolder = "/";
	}
	else {
		currentDownloadFolder = downloadFolder;
	}

	currentFilename = mol2 + ".mol2"; //default filename to be downloaded
  currentMolName = nameDisplay->text(); //needed to load mol into Avogadro
	connect(reply, SIGNAL(finished()), this, SLOT(getFile()));
}

/**
* @brief Called when a molecule is selected to display information about the
* molecule and start grabbing the SVG preview.
* @param num The row number of the table result selected
* @returns The mol2 of the result for the widget to reference
*/
QString PQRRequest::molSelected(int num) {
  if(results == NULL) {
    return QString("N/A");
  }
		QString mol2 = results[num].mol2url;
    QString url = "https://pqr.pitt.edu/static/data/svg/"+ mol2 + ".svg";

    //default filename
    QString file = mol2;
    filename->setText(file.remove(0, 3));
    formulaDisplay->setText(parseSubscripts(results[num].formula));
    nameDisplay->setText(results[num].name);

    return mol2;
}

/**
* @brief Parses the JSON response from querying PQR
*/
void PQRRequest::parseJson()
{
    if (reply->error() == QNetworkReply::NoError)
    {
		read = new Json::Reader();
    // Reading the data from the response
    QByteArray bytes = reply->readAll();
    QString jsonString(bytes);

    //parse the json
		read->parse(jsonString.toStdString().c_str(), root);

		int resultSize = root.size();

		if (resultSize == 0) {
      table->setRowCount(1);
			table->setItem(0, 0, new QTableWidgetItem("No Results!"));
			table->setItem(0, 1, new QTableWidgetItem("N/A"));
			table->setItem(0, 2, new QTableWidgetItem("N/A"));
			results = NULL;
		}
		else {
			results = new result[root.size()];
			table->setRowCount(resultSize);
			for (int i = 0; i < resultSize; i++) {
				results[i].formula = root[i].get("formula", "Error").asCString();
				results[i].inchikey = root[i].get("inchikey", "Error").asCString();
				results[i].mol2url = root[i].get("mol2url", "Error").asCString();
				results[i].name = root[i].get("name", "Error").asCString();
				results[i].mass = getMolMass(results[i].formula);

				table->setItem(i, 0, new QTableWidgetItem(results[i].name));

        //clear possible QTableWidget if there were no results previously
        table->setItem(i, 1, NULL);
        //use this to display subscripts, should automatically delete previous QLabel according to documentation
				table->setCellWidget(i, 1, new QLabel(parseSubscripts(results[i].formula)));

        //table->setItem(i, 2, new QTableWidgetItem(QString::number(results[i].mass, 'f', 3) + QString(" g/mol")));
        QTableWidgetItem* massItem = new QTableWidgetItem();
        massItem->setData(Qt::DisplayRole, results[i].mass);
        table->setItem(i, 2, massItem);
			}
		}
	}
  else {
    table->setRowCount(3);
    table->setItem(0, 0, new QTableWidgetItem("Network Error!"));
    table->setItem(0, 1, new QTableWidgetItem("N/A"));
    table->setItem(0, 2, new QTableWidgetItem(reply->errorString()));
  }
	reply->deleteLater();
}

/**
* @brief Creates a file after requesting a file from PQR
*/
void PQRRequest::getFile()
{

	QDir *dir = new QDir();
	dir->mkpath(currentDownloadFolder);

	QFile *file;
  QString path;
  //make sure filename box isn't blank
  if(filename->text() == NULL) {
    path = currentDownloadFolder + "/" + currentFilename;
  } else {
    path = currentDownloadFolder + "/" + filename->text() + ".mol2";
  }
  file = new QFile(path);

	if (file->open(QFile::WriteOnly))
	{
		file->write(reply->readAll());
		file->flush();
		file->close();
    widget->loadMolecule(path, currentMolName);
	}
	delete file;
	delete dir;

	reply->deleteLater();

}

/**
* @brief Takes a formula string and returns a QString with subscript tags
* @param formula The formula string
*/
QString PQRRequest::parseSubscripts(QString formula)
{
  std::string str = formula.toStdString();
  QString toReturn;
  for(int i = 0; i < str.length(); i++) {
    if(isdigit(str[i])) {
      toReturn.append("<sub>");
      toReturn.append(str[i]);
      toReturn.append("</sub>");
    } else {
      toReturn.append(str[i]);
    }
  }
  return toReturn;
}

/**
* @brief Takes a formula string and returns the molecular mass of the molecule
* @param formula The formula string
*/
float PQRRequest::getMolMass(QString formula) {
	std::string str = formula.toStdString();
	float totalMass = 0.0;
	int subscript = 1;
	std::string element;
  unsigned char atomicNum;
	for (int i = 0; i < str.length(); i++) {
		//each element will start with a capital letter
		if (isupper(str[i])) {
			//if next letter is a lower case then we know the whole element
			if (islower(str[i + 1])) {
        element = { str[i], str[i + 1] };
				//this might be the last element of the formula
        if(isdigit(str[i + 2])) {
          subscript = (int)str[i + 2] - '0';
          i += 2; //increment past lowercase and numeral
        }
				else {
          i += 1;
					subscript = 1;
				}
			}
			//get the subscript
			else if (isdigit(str[i + 1])) {
				if (isdigit(str[i + 2])) {
					//might be 2 digit subscript
					subscript = (int)str[i + 1] - '0';
					subscript *= 10; //shift forward one decimal place
					subscript += (int)str[i + 2] - '0';
					element = { str[i] };
					i += 2;
				}
				else {
					subscript = (int)str[i + 1] - '0';
					element = { str[i] };
					i += 1;
				}
			}
			//if the next letter is another uppercase or null, the current subscript is 1
			else if (isupper(str[i + 1]) || str[i + 1] == NULL) {
				subscript = 1;
				element = { str[i] };
			}
      atomicNum = Core::Elements::atomicNumberFromSymbol(element);
			totalMass += (subscript * Core::Elements::mass(atomicNum));
		}
	}
	return totalMass;
}

}
}
