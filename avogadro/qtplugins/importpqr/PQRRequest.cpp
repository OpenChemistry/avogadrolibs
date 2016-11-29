#include "PQRRequest.h"

namespace Avogadro {
namespace QtPlugins {
/**
* @brief Constuctor to initialize the NetworkAcessManager and set pointers to
* the widget's ui elements.
*/
PQRRequest::PQRRequest(QTableWidget* tw, QWebEngineView* gv, QLineEdit* fn, QLineEdit* nd, QLabel* fd)
{
  //set pointers to ui elements now instead of in individual functions
  table = tw; //pointer to ui table
  svgPreview = gv; //svg GraphicsView
  filename = fn; //filename LineEdit
  nameDisplay = nd; //name
  formulaDisplay = fd; //formula
  oNetworkAccessManager = new QNetworkAccessManager(this);
}

/**
* @brief Free the ui pointers
*/
PQRRequest::~PQRRequest()
{
  delete results;
  delete reply;
  delete read;
  delete oNetworkAccessManager;
  delete table;
  delete filename;
  delete formulaDisplay;
  delete svgPreview;
  delete svgScene;
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
void PQRRequest::sendRequest(QString url, QString mol2, QString downloadFolder, QString ext)
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

	currentFilename = mol2+ext; //default filename to be downloaded

	connect(reply, SIGNAL(finished()), this, SLOT(getFile()));
}

/**
* @brief Called when a molecule is selected to display information about the
* molecule and start grabbing the SVG preview.
* @param num The row number of the table result selected
* @returns The mol2 of the result for the widget to reference
*/
QString PQRRequest::molSelected(int num) {
		QString mol2 = results[num].mol2url;
    QString url = "https://pqr.pitt.edu/static/data/svg/"+ mol2 + ".svg";

    //default filename
    filename->setText(mol2.remove(0, 3));
    formulaDisplay->setText(parseSubscripts(results[num].formula));
    nameDisplay->setText(results[num].name);

    this->updateSVGPreview(url, mol2.remove(0, 3));
    return mol2;
}

/**
* @brief Sends a network request to get the SVG for the download preview
* @param url The url to send request to
* @param mol2 The mol2 representation of the molecule to query a SVG for
*/
void PQRRequest::updateSVGPreview(QString url, QString mol2)
{
  svgPreview = new QWebEngineView();
  svgPreview->load(url);
/**
  QUrl httpRequest(url);
  QNetworkRequest request;
  //had trouble grabbing the svgs from PQR without this

  request.setRawHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36");
  request.setRawHeader("Accept-Language", "en - US, en; q = 0.8");
  request.setUrl(httpRequest); // Set the url

  reply = oNetworkAccessManager->get(request);
  connect(reply, SIGNAL(finished()), this, SLOT(setSVG()));
  **/
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
				results[i].last_updated = root[i].get("last_updated", "Error").asCString();
				results[i].mol2url = root[i].get("mol2url", "Error").asCString();
				results[i].name = root[i].get("name", "Error").asCString();
				results[i].mass = getMolMass(results[i].formula);

				table->setItem(i, 0, new QTableWidgetItem(results[i].name));

        //clear possible QTableWidget if there were no results previously
        table->setItem(i, 1, NULL);
        //use this to display subscripts, should automatically delete previous QLabel according to documentation
				table->setCellWidget(i, 1, new QLabel(parseSubscripts(results[i].formula)));

        table->setItem(i, 2, new QTableWidgetItem(QString::number(results[i].mass, 'f', 3) + QString(" g/mol")));
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
  //make sure filename box isn't blank
  if(filename->text() == NULL) {
    file = new QFile(currentDownloadFolder + "/" + currentFilename);
  } else {
    file = new QFile(currentDownloadFolder + "/" + filename->text());
  }
	if (file->open(QFile::WriteOnly))
	{
		file->write(reply->readAll());
		file->flush();
		file->close();
	}
	delete file;
	delete dir;
	reply->deleteLater();
}

/**
* @brief Creates a temporary file for the SVG preview and attempts to render
* it into the QGraphicsView
*/
void PQRRequest::setSVG()
{
  QDir *dir = new QDir();
  dir->mkpath("temp");

  QFile *file = new QFile("temp/currentPreview.svg");

  if (file->open(QFile::WriteOnly))
  {
    file->write(reply->readAll());
    file->flush();
    file->close();
  }
  /**
  //attempt to render svg WIP
  svgScene = new QGraphicsScene(this);
  //svgScene->addPixmap(QIcon("temp/currentPreview.svg").pixmap(100, QIcon::Normal, QIcon::Off));
  QSvgRenderer *test = new QSvgRenderer(QString("temp/currentPreview.svg"));
  svgimg = new QGraphicsSvgItem();
  svgimg->setSharedRenderer(test);
  svgScene->addItem(svgimg);
  //svgimg->setTransform(QTransform(test->viewBoxF().width() / (test->viewBoxF().width() + 1.0), 0.0, 0.0, test->viewBoxF().height() / (test->viewBoxF().height() + 1.0), 0.5, 0.5));
  svgPreview->setScene(svgScene);
  svgScene->setSceneRect(svgScene->itemsBoundingRect());
  svgPreview->fitInView(svgimg, Qt::KeepAspectRatio);
    **/
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
	for (int i = 0; i < str.length(); i++) {
		//each element will start with a capital letter
		if (isupper(str[i])) {
			//if next letter is a lower case then we know the whole element
			if (islower(str[i + 1])) {
				//this might be the last element of the formula
				if (str[i + 2] == NULL) {
					subscript = 1;
				}
				else {
					subscript = (int)str[i + 2] - '0';
				}
				element = { str[i], str[i + 1] };
				i += 2; //increment past lowercase and numeral
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
			totalMass += (subscript * elementToMass(element));
		}
	}
	return totalMass;
}

/**
* @brief Takes a single element string and returns the atomic mass of that element
* @param element The element string
* @returns The atomic mass
*/
float PQRRequest::elementToMass(std::string element) {
	if (element == "H") {
		return 1.0079;
	}
	else if (element == "He") {
		return 4.0026;
	}
	else if (element == "Li") {
		return 6.941;
	}
	else if (element == "Be") {
		return 9.0122;
	}
	else if (element == "B") {
		return 10.811;
	}
	else if (element == "C") {
		return 12.0107;
	}
	else if (element == "N") {
		return 14.0067;
	}
	else if (element == "O") {
		return 15.9994;
	}
	else if (element == "F") {
		return 18.9984;
	}
	else if (element == "Ne") {
		return 20.1797;
	}
	else if (element == "Na") {
		return 22.9897;
	}
	else if (element == "Mg") {
		return 24.305;
	}
	else if (element == "Al") {
		return 26.9815;
	}
	else if (element == "Si") {
		return 28.0855;
	}
	else if (element == "P") {
		return 30.9738;
	}
	else if (element == "S") {
		return 32.065;
	}
	else if (element == "Cl") {
		return 35.453;
	}
	else if (element == "K") {
		return 39.0983;
	}
	else if (element == "Ar") {
		return 39.948;
	}
	else if (element == "Ca") {
		return 40.078;
	}
	else if (element == "Sc") {
		return 44.9559;
	}
	else if (element == "Ti") {
		return 47.867;
	}
	else if (element == "V") {
		return 50.9415;
	}
	else if (element == "Cr") {
		return 51.9961;
	}
	else if (element == "Mn") {
		return 54.938;
	}
	else if (element == "Fe") {
		return 55.845;
	}
	else if (element == "Ni") {
		return 58.6934;
	}
	else if (element == "Co") {
		return 58.9332;
	}
	else if (element == "Cu") {
		return 63.546;
	}
	else if (element == "Zn") {
		return 65.39;
	}
	else if (element == "Ga") {
		return 69.723;
	}
	else if (element == "Ge") {
		return 72.64;
	}
	else if (element == "As") {
		return 74.9216;
	}
	else if (element == "Se") {
		return 78.96;
	}
	else if (element == "Br") {
		return 79.904;
	}
	else if (element == "Kr") {
		return 83.8;
	}
	else if (element == "Rb") {
		return 85.4678;
	}
	else if (element == "Sr") {
		return 87.62;
	}
	else if (element == "Y") {
		return 88.9059;
	}
	else if (element == "Zr") {
		return 91.224;
	}
	else if (element == "Nb") {
		return 92.9064;
	}
	else if (element == "Mo") {
		return 95.94;
	}
	else if (element == "Tc") {
		return 98.0;
	}
	else if (element == "Ru") {
		return 101.07;
	}
	else if (element == "Rh") {
		return 102.9055;
	}
	else if (element == "Pd") {
		return 106.42;
	}
	else if (element == "Ag") {
		return 107.8682;
	}
	else if (element == "Cd") {
		return 112.411;
	}
	else if (element == "In") {
		return 114.818;
	}
	else if (element == "Sn") {
		return 118.71;
	}
	else if (element == "Sb") {
		return 121.76;
	}
	else if (element == "I") {
		return 126.9045;
	}
	else if (element == "Te") {
		return 127.6;
	}
	else if (element == "Xe") {
		return 131.293;
	}
	else if (element == "Cs") {
		return 132.9055;
	}
	else if (element == "Ba") {
		return 137.327;
	}
	else if (element == "La") {
		return 138.9055;
	}
	else if (element == "Ce") {
		return 140.116;
	}
	else if (element == "Pr") {
		return 140.9077;
	}
	else if (element == "Nd") {
		return 144.24;
	}
	else if (element == "Pm") {
		return 145.0;
	}
	else if (element == "Sm") {
		return 150.36;
	}
	else if (element == "Eu") {
		return 151.964;
	}
	else if (element == "Gd") {
		return 157.25;
	}
	else if (element == "Tb") {
		return 158.9253;
	}
	else if (element == "Dy") {
		return 162.5;
	}
	else if (element == "Ho") {
		return 164.9303;
	}
	else if (element == "Er") {
		return 167.259;
	}
	else if (element == "Tm") {
		return 168.9342;
	}
	else if (element == "Yb") {
		return 173.04;
	}
	else if (element == "Lu") {
		return 174.967;
	}
	else if (element == "Hf") {
		return 178.49;
	}
	else if (element == "Ta") {
		return 180.9479;
	}
	else if (element == "W") {
		return 183.84;
	}
	else if (element == "Re") {
		return 186.207;
	}
	else if (element == "Os") {
		return 190.23;
	}
	else if (element == "Ir") {
		return 192.217;
	}
	else if (element == "Pt") {
		return 195.078;
	}
	else if (element == "Au") {
		return 196.9665;
	}
	else if (element == "Hg") {
		return 200.59;
	}
	else if (element == "Tl") {
		return 204.3833;
	}
	else if (element == "Pb") {
		return 207.2;
	}
	else if (element == "Bi") {
		return 208.9804;
	}
	else if (element == "Po") {
		return 209.0;
	}
	else if (element == "At") {
		return 210.0;
	}
	else if (element == "Rn") {
		return 222.0;
	}
	else if (element == "Fr") {
		return 223.0;
	}
	else if (element == "Ra") {
		return 226.0;
	}
	else if (element == "Ac") {
		return 227.0;
	}
	else if (element == "Pa") {
		return 231.0359;
	}
	else if (element == "Th") {
		return 232.0381;
	}
	else if (element == "Np") {
		return 237.0;
	}
	else if (element == "U") {
		return 238.0289;
	}
	else if (element == "Am") {
		return 243.0;
	}
	else if (element == "Pu") {
		return 244.0;
	}
	else if (element == "Cm") {
		return 247.0;
	}
	else if (element == "Bk") {
		return 247.0;
	}
	else if (element == "Cf") {
		return 251.0;
	}
	else if (element == "Es") {
		return 252.0;
	}
	else if (element == "Fm") {
		return 257.0;
	}
	else if (element == "Md") {
		return 258.0;
	}
	else if (element == "No") {
		return 259.0;
	}
	else if (element == "Rf") {
		return 261.0;
	}
	else if (element == "Lr") {
		return 262.0;
	}
	else if (element == "Db") {
		return 262.0;
	}
	else if (element == "Bh") {
		return 264.0;
	}
	else if (element == "Sg") {
		return 266.0;
	}
	else if (element == "Mt") {
		return 268.0;
	}
	else if (element == "Rg") {
		return 272.0;
	}
	else if (element == "Hs") {
		return 277.0;
	}
}
}
}
