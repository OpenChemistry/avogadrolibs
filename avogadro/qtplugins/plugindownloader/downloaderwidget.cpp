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
	QList<QString> repos;
	repos.append(QString("https://github.com/OpenChemistry/crystals"));
	repos.append(QString("https://github.com/OpenChemistry/avogenerators"));
	ui->repoTable->setColumnCount(1);
	ui->repoTable->setHorizontalHeaderLabels(QStringList() << "Repository");
	ui->repoTable->horizontalHeader()->setStretchLastSection(true);

	numRepos = repos.size();

	ui->repoTable->setRowCount(numRepos);
	for(int i = 0; i < numRepos; i++) {
		QString url = repos.at(i);
		ui->repoTable->setItem(i, 0, new QTableWidgetItem(url));

		QStringList urlparts = url.split('/', QString::SkipEmptyParts);
		nameList.append(urlparts[3]);
	}
}

DownloaderWidget::~DownloaderWidget()
{
  delete ui;
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
		ui->readmeBrowser->append(url);
		reply = oNetworkAccessManager->get(request);
		connect(reply, SIGNAL(finished()), this, SLOT(updateRepos()));
	}
}
void DownloaderWidget::downloadRepos()
{
	for(int i = 0; i < numRepos; i++) {
		QString url = "https://api.github.com/repos/";
		QString slug = ui->repoTable->item(i, 0)->text();
		slug.remove(0, 19);
		url.append(slug);
		url.append("/zipball/master");
		downloadList.append(url);
  }
	downloadNext();
}
void DownloaderWidget::updateRepos()
{
	ui->readmeBrowser->append("updateRepos called");
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

			reply = oNetworkAccessManager->get(request);
	    connect(reply, SIGNAL(finished()), this, SLOT(updateRepos()));
    }
		else
  	{
		//done with redirect
		ui->readmeBrowser->append("done with redirect");
		QByteArray fileData = reply->readAll();

		QDir().mkpath(filePath);
		QString repoName = nameList.takeFirst();
		QString filename = repoName + ".zip";

		QString absolutePath = filePath + "/" + filename;
		QString extractdirectory = filePath + "/";

		QFile out(absolutePath);
		ui->readmeBrowser->append("file downloaded");
		ui->readmeBrowser->append(filePath);
		out.open(QIODevice::WriteOnly);
    QDataStream outstr(&out);
    outstr << fileData;
		out.close();

		QByteArray ba = filename.toLatin1();
		const char *filen = ba.data();
		ba = extractdirectory.toLatin1();
		const char *extractdir = ba.data();
		ba = absolutePath.toLatin1();
		const char *absolutep = ba.data();

		ui->readmeBrowser->append("extractdir: " + extractdirectory);
		ZipExtracter::extract(filen, extractdir, absolutep);

		reply->deleteLater();
		downloadNext();
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
 QString slug = ui->repoTable->item(row, 0)->text();
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
