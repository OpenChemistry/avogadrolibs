#include "downloaderwidget.h"
#include "zipextracter.h"
#include "ui_downloaderwidget.h"

namespace Avogadro {
namespace QtPlugins {

DownloaderWidget::DownloaderWidget(QWidget* parent) :
  QDialog(parent),
  ui(new Ui::DownloaderWidget)
{
	numRepos = 0;
	filePath = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
  oNetworkAccessManager = new QNetworkAccessManager(this);
  ui->setupUi(this);
  connect(ui->downloadButton, SIGNAL(clicked(bool)), this, SLOT(getCheckedRepos()));
	connect(ui->repoTable, SIGNAL(cellClicked(int, int)),
		this, SLOT(downloadREADME(int, int)));

	ui->repoTable->setColumnCount(4);
	ui->repoTable->setSelectionBehavior(QAbstractItemView::SelectRows);
	ui->repoTable->setHorizontalHeaderLabels(QStringList() << "Update" << "Name" << "Description" << "Releases");
	ui->repoTable->horizontalHeader()->setStretchLastSection(true);

	ui->repoTable->setRowCount(0);

	getRepoData();

}

DownloaderWidget::~DownloaderWidget()
{
  delete ui;
}

void DownloaderWidget::getRepoData()
{

	QString url = "https://avogadro.cc/plugins.json";
	ui->readmeBrowser->append(url);
	QNetworkRequest request;
	request.setRawHeader("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8");
	request.setRawHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36");
	request.setRawHeader("Accept-Language", "en - US, en; q = 0.8");
	request.setUrl(url); // Set the url
	reply = oNetworkAccessManager->get(request);
	connect(reply, SIGNAL(finished()), this, SLOT(updateRepoData()));

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
		numRepos = root.size();
		repoList = new repo[numRepos];
		ui->repoTable->setRowCount(numRepos);
		for(int i = 0; i < numRepos; i++) {
			repoList[i].name = root[i].get("name", "Error").asCString();
			repoList[i].description = root[i].get("description", "Error").asCString();
			repoList[i].release_version = root[i].get("release_version", "Error").asCString();
			repoList[i].updated_at = root[i].get("updated_at", "Error").asCString();
			repoList[i].zipball_url = root[i].get("zipball_url", "Error").asCString();
			repoList[i].has_release = root[i].get("has_release", false).asBool();

			//readme should be included or at least the repo url so we don't have to do this
			QStringList urlParts = repoList[i].zipball_url.split("/");
			urlParts.removeLast();
			urlParts.removeLast(); //remove /zipball/(version/branch)
			urlParts.append("readme");
			QString readmeUrl = urlParts.join("/");
			ui->readmeBrowser->append("readme url: " + readmeUrl);
			repoList[i].readme_url = readmeUrl;
			QTableWidgetItem *checkbox = new QTableWidgetItem();
			checkbox->setCheckState(Qt::Unchecked);
			ui->repoTable->setItem(i, 0, checkbox);
			ui->repoTable->setItem(i, 1, new QTableWidgetItem(repoList[i].name));
			ui->repoTable->setItem(i, 2, new QTableWidgetItem(repoList[i].description));
			if(repoList[i].has_release)
				ui->repoTable->setItem(i, 3, new QTableWidgetItem(repoList[i].release_version));
			else
				ui->repoTable->setItem(i, 3, new QTableWidgetItem(repoList[i].updated_at));
		}

	}
	reply->deleteLater();
}

void DownloaderWidget::downloadREADME(int row, int col)
{
 ui->readmeBrowser->clear();
 QString url = repoList[row].readme_url;
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

void DownloaderWidget::getCheckedRepos()
{
	downloadList.clear();
	for(int i = 0; i < numRepos; i++) {
		if(ui->repoTable->item(i, 0)->checkState() == Qt::Checked) {
			downloadEntry newEntry;
			newEntry.url = repoList[i].zipball_url;
			newEntry.name = repoList[i].name;
			newEntry.type = "other"; //change when type added to plugin.json
			downloadList.append(newEntry);
		}
	}
	downloadNext();
}

void DownloaderWidget::downloadNext()
{
	if(!downloadList.isEmpty()) {
		QString url = downloadList.last().url;
		QNetworkRequest request;
		request.setRawHeader("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8");
	  request.setRawHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36");
	  request.setRawHeader("Accept-Language", "en - US, en; q = 0.8");
	  request.setUrl(url); // Set the url

	  reply = oNetworkAccessManager->get(request);
	  connect(reply, SIGNAL(finished()), this, SLOT(handleRedirect()));
	}
}

void DownloaderWidget::handleRedirect()
{
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
	    connect(reply, SIGNAL(finished()), this, SLOT(unzipPlugin()));

    }
		else
			ui->readmeBrowser->append("error handling redirect: " + QString::number(statusCode.toInt()));
	}
	else
	{
		ui->readmeBrowser->append("error in reply");

	  reply->deleteLater();
		downloadList.removeLast();
		downloadNext();
	}

}

void DownloaderWidget::unzipPlugin()
{
	if (reply->error() == QNetworkReply::NoError) {
		//done with redirect
		ui->readmeBrowser->append("done with redirect" );
		QByteArray fileData = reply->readAll();
		ui->readmeBrowser->append("fileData size: " + QString::number(fileData.size()));
		QDir().mkpath(filePath);
		QString repoName = downloadList.last().name;
		QString filename = repoName + ".zip";

		QString absolutePath = filePath + "/" + filename;
		QString extractdirectory;
		QString subdir = downloadList.last().type;
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
		downloadList.removeLast();
		downloadNext();
  }
}

} //namespace QtPlugins
} //namespace Avogadro
