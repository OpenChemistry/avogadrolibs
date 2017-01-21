#include "downloaderwidget.h"
#include "zipextracter.h"
#include "ui_downloaderwidget.h"

namespace Avogadro {
namespace QtPlugins {

DownloaderWidget::DownloaderWidget(QWidget* parent) :
  QDialog(parent),
  ui(new Ui::DownloaderWidget)
{
	ready = true;
	numProcessed = 0;
	filePath = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
  oNetworkAccessManager = new QNetworkAccessManager(this);
  ui->setupUi(this);
  connect(ui->downloadButton, SIGNAL(clicked(bool)), this, SLOT(downloadRepos()));
	connect(ui->repoTable, SIGNAL(cellClicked(int, int)),
		this, SLOT(downloadREADME(int, int)));

	repos.append(QString("https://github.com/OpenChemistry/crystals"));
	repos.append(QString("https://github.com/OpenChemistry/avogenerators"));
	ui->repoTable->setColumnCount(4);
	ui->repoTable->setSelectionBehavior(QAbstractItemView::SelectRows);
	ui->repoTable->setHorizontalHeaderLabels(QStringList() << "Update" << "Name" << "Description" << "Releases");
	ui->repoTable->horizontalHeader()->setStretchLastSection(true);

	numRepos = repos.size();

	ui->repoTable->setRowCount(numRepos);

	getRepoData();

}

DownloaderWidget::~DownloaderWidget()
{
  delete ui;
}

void DownloaderWidget::getRepoData()
{
	if(currentTableIndex <= repos.size()){
		QString url = "https://api.github.com/repos/";
		QString slug = repos.at(currentTableIndex);
		slug.remove(0, 19);
		url.append(slug);
		ui->readmeBrowser->append(url);
		QNetworkRequest request;
		request.setRawHeader("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8");
		request.setRawHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36");
		request.setRawHeader("Accept-Language", "en - US, en; q = 0.8");
		request.setUrl(url); // Set the url
		reply = oNetworkAccessManager->get(request);
		connect(reply, SIGNAL(finished()), this, SLOT(updateRepoData()));
	}
}

void DownloaderWidget::updateRepoData()
{

	if (reply->error() == QNetworkReply::NoError)
	{

		read = new Json::Reader();
		// Reading the data from the response
		QByteArray bytes = reply->readAll();
		QString jsonString(bytes);

		//parse the json
		read->parse(jsonString.toStdString().c_str(), root);

		repo tempData;
		tempData.name = root.get("name", "ERROR").asCString();
		tempData.description = root.get("description", "ERROR").asCString();
		tempData.release = root.get("updated_at", "ERROR").asCString();
		repoData.append(tempData);
		ui->readmeBrowser->append(tempData.name);

		QTableWidgetItem *checkbox = new QTableWidgetItem();
		checkbox->setCheckState(Qt::Unchecked);
		ui->repoTable->setItem(currentTableIndex, 0, checkbox);
		ui->repoTable->setItem(currentTableIndex, 1, new QTableWidgetItem(tempData.name));
		ui->repoTable->setItem(currentTableIndex, 2, new QTableWidgetItem(tempData.description));
		ui->repoTable->setItem(currentTableIndex, 3, new QTableWidgetItem(tempData.release));


	}
	currentTableIndex++;
	reply->deleteLater();
	if(currentTableIndex < repos.size())
		getRepoData();
}
bool DownloaderWidget::checkSHA1(QByteArray file)
{
//TODO
return false;
}

void DownloaderWidget::downloadNext()
{
	if(!downloadList.isEmpty())
	{
		QString url = downloadList.takeFirst();
		QNetworkRequest request;
		request.setRawHeader("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8");
		request.setRawHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36");
		request.setRawHeader("Accept-Language", "en - US, en; q = 0.8");
		request.setUrl(url); // Set the url
		ui->readmeBrowser->append("making download request to: " + url);
		reply = oNetworkAccessManager->get(request);
		connect(reply, SIGNAL(finished()), this, SLOT(handleRedirect()));
	}
}

void DownloaderWidget::downloadNextPlugin()
{
	if(!pluginList.isEmpty())
	{
		QString url = pluginList.takeFirst();
		QNetworkRequest request;
		request.setRawHeader("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8");
		request.setRawHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36");
		request.setRawHeader("Accept-Language", "en - US, en; q = 0.8");
		request.setUrl(url); // Set the url
		ui->readmeBrowser->append(url);
		reply = oNetworkAccessManager->get(request);
		connect(reply, SIGNAL(finished()), this, SLOT(parsePluginType()));
	} else {
		for(int i = 0; i < pluginTypes.size(); i++) {
			ui->readmeBrowser->append("plugin #" + QString::number(i) + " is: " + pluginTypes.at(i));
		}
		downloadNext();
	}
}

void DownloaderWidget::parsePluginType()
{
	if (reply->error() == QNetworkReply::NoError)
	{

		read = new Json::Reader();
		// Reading the data from the response
		QByteArray bytes = reply->readAll();
		QString jsonString(bytes);

		//parse the json
		read->parse(jsonString.toStdString().c_str(), root);
		QByteArray encodedType = root.get("content", "ERROR").asCString();

		read = new Json::Reader();

		QByteArray pluginJSON = QByteArray::fromBase64(encodedType);
		QString pluginString(pluginJSON);
		read->parse(pluginString.toStdString().c_str(), root);
		pluginTypes.append(root.get("type", "other").asCString());
	}
	downloadNextPlugin();
}

void DownloaderWidget::downloadRepos()
{

	for(int i = 0; i < numRepos; i++) {
		if(ui->repoTable->item(i, 0)->checkState() == Qt::Checked) {
			QString url = "https://api.github.com/repos/";
			QString slug = repos.at(i);
			slug.remove(0, 19);
			url.append(slug);
			url.append("/zipball/master");
			downloadList.append(url);

			QString pluginURL = "https://api.github.com/repos/";
			pluginURL.append(slug);
			pluginURL.append("/contents/plugin.json");
			pluginList.append(pluginURL);

			QString repoURL = repos.at(i);
			QStringList urlparts = repoURL.split('/', QString::SkipEmptyParts);
			nameList.append(urlparts[3]);
	  }
  }
	//get "type" form plugin.json
	downloadNextPlugin();
	//download the repos
	//downloadNext();
}
void DownloaderWidget::updateRepos()
{
	if (reply->error() == QNetworkReply::NoError) {
		//done with redirect
		ui->readmeBrowser->append("done with redirect" );
		QByteArray fileData = reply->readAll();
		ui->readmeBrowser->append("fileData size: " + QString::number(fileData.size()));
		QDir().mkpath(filePath);
		QString repoName = nameList.takeFirst();
		QString filename = repoName + ".zip";

		QString absolutePath = filePath + "/" + filename;
		QString extractdirectory;
			QString subdir = pluginTypes.takeFirst();
		ui->readmeBrowser->append("subdir: " + subdir);

		extractdirectory = filePath + "/" + subdir + "/";


		QDir().mkpath(extractdirectory);

		QFile out(absolutePath);
		ui->readmeBrowser->append("file downloaded");
		ui->readmeBrowser->append(filePath);
		out.open(QIODevice::WriteOnly);
		QDataStream outstr(&out);
		outstr << fileData;
		out.close();

		QByteArray ba = filename.toLatin1();
		const char *filen = ba.data();

		std::string extractdir = extractdirectory.toStdString();

		std::string absolutep = absolutePath.toStdString();

		ZipExtracter unzip;

		ui->readmeBrowser->append("filename: " + filename);
		ui->readmeBrowser->append("absolutePath: " + absolutePath);
		ui->readmeBrowser->append("extractdir: " + extractdirectory);
		QList<QString> extractres = unzip.extract(filen, extractdir, absolutep);
		ui->readmeBrowser->append("check extractdir: " + QString::fromStdString(extractdir));
		ui->readmeBrowser->append("extracres size: " + QString::number(extractres.size()));
	//	for(int i = 0; i < extractres.size(); i++) {
	//		ui->readmeBrowser->append("filename: " + QString::number(i) + ": " + extractres.at(i));
	//	}
		reply->deleteLater();
		downloadNext();
  }
}
void DownloaderWidget::handleRedirect()
{
//	ui->readmeBrowser->append("updateRepos called");
	if (reply->error() == QNetworkReply::NoError)
	{
  	QVariant statusCode = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute);
		if(statusCode.toInt() == 302)
		{
			ui->readmeBrowser->append("redirect");
			QVariant possibleRedirectUrl =
			reply->attribute(QNetworkRequest::RedirectionTargetAttribute);

			QUrl _urlRedirectedTo = possibleRedirectUrl.toUrl();

			QNetworkRequest request;
			request.setRawHeader("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8");
			request.setRawHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36");
			request.setRawHeader("Accept-Language", "en - US, en; q = 0.8");
			request.setUrl(_urlRedirectedTo); // Set the url
			//reply->deleteLater();
			reply = oNetworkAccessManager->get(request);
	    connect(reply, SIGNAL(finished()), this, SLOT(updateRepos()));

    } else {
				ui->readmeBrowser->append("error handling redirect: " + QString::number(statusCode.toInt()));

		}
	}
	else
	{
		ui->readmeBrowser->append("error in reply");
		ready = true;
	  reply->deleteLater();
		if(!nameList.isEmpty())
			nameList.takeFirst();
		downloadNext();
	}

}

void DownloaderWidget::downloadREADME(int row, int col)
{
 ui->readmeBrowser->clear();
 ui->readmeBrowser->append(QString(row));
 QString url = "https://api.github.com/repos/";
 QString slug = repos.at(row);
 slug.remove(0, 19);
 url.append(slug);
 url.append("/readme");
 QNetworkRequest request;
 request.setRawHeader("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8");
 request.setRawHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36");
 request.setRawHeader("Accept-Language", "en - US, en; q = 0.8");
 request.setUrl(url); // Set the url

 reply = oNetworkAccessManager->get(request);
 connect(reply, SIGNAL(finished()), this, SLOT(showREADME()));
}

void DownloaderWidget::showREADME()
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
		QByteArray content = root.get("content", "ERROR").asCString();
		ui->readmeBrowser->append(QByteArray::fromBase64(content).data());
	}
}

} //namespace QtPlugins
} //namespace Avogadro
