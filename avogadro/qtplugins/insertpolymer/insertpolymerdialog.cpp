/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "insertpolymerdialog.h"
#include "ui_insertpolymerdialog.h"

#include <avogadro/qtgui/utilities.h>

#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QFileInfo>
#include <QtCore/QRandomGenerator>
#include <QtCore/QStandardPaths>
#include <QtCore/QTextStream>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFileSystemModel>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QSortFilterProxyModel>
#include <QToolButton>
#include <QTreeView>
#include <QVBoxLayout>

namespace Avogadro::QtPlugins {

// Local proxy model that shows .smi files but hides images and dev files
class PolymerProxyModel : public QSortFilterProxyModel
{
public:
  using QSortFilterProxyModel::QSortFilterProxyModel;

  void setSourceRoot(const QModelIndex& root) { m_sourceRoot = root; }

protected:
  bool filterAcceptsRow(int sourceRow,
                        const QModelIndex& sourceParent) const override
  {
    QModelIndex idx = sourceModel()->index(sourceRow, 0, sourceParent);
    if (!idx.isValid() || !sourceParent.isValid())
      return true;
    if (m_sourceRoot.isValid() && idx == m_sourceRoot)
      return true;

    QString name = sourceModel()->data(idx).toString();
    // hide image and dev files, but keep .smi
    if (name.endsWith(".png") || name.endsWith(".svg") ||
        name.endsWith(".json") || name.endsWith(".md") ||
        name.endsWith(".py") || name.endsWith(".toml"))
      return false;

    // Filter text matching (walk up parents)
    if (sourceParent != m_sourceRoot) {
      bool childOfRoot = false;
      QModelIndex parent = sourceParent;
      for (int depth = 3; depth > 0; depth--) {
        if (sourceModel()->data(parent).toString().contains(
              filterRegularExpression()))
          return true;
        parent = parent.parent();
        if (!parent.isValid())
          return true;
        if (parent == m_sourceRoot) {
          childOfRoot = true;
          break;
        }
      }
      if (!childOfRoot)
        return true;
    }

    if (name.contains(filterRegularExpression()))
      return true;

    // Show directory if any child matches
    sourceModel()->fetchMore(idx);
    for (int i = 0; i < sourceModel()->rowCount(idx); ++i) {
      QModelIndex child = sourceModel()->index(i, 0, idx);
      if (child.isValid() && sourceModel()->data(child).toString().contains(
                               filterRegularExpression()))
        return true;
    }
    return false;
  }

private:
  QModelIndex m_sourceRoot;
};

InsertPolymerDialog::InsertPolymerDialog(QWidget* parent)
  : QDialog(parent), m_ui(new ::Ui::InsertPolymerDialog)
{
  setWindowFlags(Qt::Dialog | Qt::Tool);
  m_ui->setupUi(this);

  m_polymerDirectory = resolvePolymerDirectory();

  // Connect monomer chooser buttons
  connect(m_ui->monomerAButton, &QPushButton::clicked, this,
          &InsertPolymerDialog::chooseMonomerA);
  connect(m_ui->monomerBButton, &QPushButton::clicked, this,
          &InsertPolymerDialog::chooseMonomerB);
  connect(m_ui->monomerCButton, &QPushButton::clicked, this,
          &InsertPolymerDialog::chooseMonomerC);

  // Connect repeat validation
  connect(m_ui->aRepeatSpinBox, &QSpinBox::valueChanged, this,
          &InsertPolymerDialog::validateMonomerRepeats);
  connect(m_ui->bRepeatSpinBox, &QSpinBox::valueChanged, this,
          &InsertPolymerDialog::validateMonomerRepeats);
  connect(m_ui->cRepeatSpinBox, &QSpinBox::valueChanged, this,
          &InsertPolymerDialog::validateMonomerRepeats);
  connect(m_ui->monomerRepeatStyle, &QComboBox::currentIndexChanged, this,
          &InsertPolymerDialog::validateMonomerRepeats);

  // Connect build button
  connect(m_ui->buildPolymerButton, &QPushButton::clicked, this,
          &InsertPolymerDialog::build);
}

InsertPolymerDialog::~InsertPolymerDialog()
{
  delete m_ui;
}

QString InsertPolymerDialog::resolvePolymerDirectory() const
{
  QStringList dirs;
  QStringList stdPaths =
    QStandardPaths::standardLocations(QStandardPaths::AppLocalDataLocation);
  for (const QString& dirStr : stdPaths)
    dirs << dirStr + "/data/fragments/polymers";

  dirs << QCoreApplication::applicationDirPath() + "/../" +
            QtGui::Utilities::dataDirectory() + "/avogadro2/fragments/polymers";

#ifdef Q_WS_X11
  dirs << QString(INSTALL_PREFIX) + "/share/avogadro2/fragments/polymers";
#else
  dirs << QCoreApplication::applicationDirPath() +
            "/../share/avogadro2/fragments/polymers";
#endif

  for (const QString& dirStr : dirs) {
    QDir testdir(dirStr);
    if (testdir.exists() && testdir.isReadable())
      return testdir.absolutePath();
  }
  return QString();
}

QString InsertPolymerDialog::chooseMonomerFile()
{
  if (m_polymerDirectory.isEmpty()) {
    QMessageBox::warning(this, tr("Error"),
                         tr("Polymer monomer data directory not found."));
    return QString();
  }

  // Build a small chooser dialog
  QDialog chooser(this);
  chooser.setWindowTitle(tr("Choose Monomer"));
  chooser.resize(350, 400);

  auto* layout = new QVBoxLayout(&chooser);

  // Filter row
  auto* filterLayout = new QHBoxLayout;
  auto* filterLabel = new QLabel(tr("Filter:"));
  auto* filterEdit = new QLineEdit;
  filterEdit->setClearButtonEnabled(true);
  filterLayout->addWidget(filterLabel);
  filterLayout->addWidget(filterEdit);
  layout->addLayout(filterLayout);

  // Tree view + preview
  auto* contentLayout = new QHBoxLayout;
  auto* treeView = new QTreeView;

  auto* preview = new QToolButton;
  preview->setMinimumSize(128, 128);
  preview->setIconSize(QSize(128, 128));
  preview->hide();

  contentLayout->addWidget(treeView);
  contentLayout->addWidget(preview);
  layout->addLayout(contentLayout);

  // OK/Cancel
  auto* buttons =
    new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
  connect(buttons, &QDialogButtonBox::accepted, &chooser, &QDialog::accept);
  connect(buttons, &QDialogButtonBox::rejected, &chooser, &QDialog::reject);
  layout->addWidget(buttons);

  // Set up file system model
  auto* model = new QFileSystemModel(&chooser);
  model->setReadOnly(true);
  QModelIndex rootIndex = model->setRootPath(m_polymerDirectory);
  model->setNameFilters({ "*.smi" });

  auto* proxy = new PolymerProxyModel(&chooser);
  proxy->setSourceModel(model);
  proxy->setSortLocaleAware(true);
  QModelIndex proxyRoot = proxy->mapFromSource(rootIndex);
  proxy->setSourceRoot(rootIndex);

  treeView->setModel(proxy);
  treeView->setRootIndex(proxyRoot);
  for (int i = 1; i < model->columnCount(); ++i)
    treeView->hideColumn(i);
  treeView->setSelectionMode(QAbstractItemView::SingleSelection);
  treeView->setSelectionBehavior(QAbstractItemView::SelectRows);
  treeView->setUniformRowHeights(true);

  // Filter
  connect(filterEdit, &QLineEdit::textChanged,
          [proxy, treeView](const QString& text) {
            QRegularExpression reg(text,
                                   QRegularExpression::CaseInsensitiveOption);
            proxy->setFilterRegularExpression(reg);
            if (!text.isEmpty())
              treeView->expandToDepth(2);
          });

  // Preview on selection change
  connect(
    treeView->selectionModel(), &QItemSelectionModel::currentChanged,
    [model, proxy, preview](const QModelIndex& current, const QModelIndex&) {
      QString filePath =
        current.data(QFileSystemModel::FilePathRole).toString();
      QFileInfo info(filePath);
      if (!info.isDir()) {
        // Look for matching image
        QString imgPath = info.absolutePath() + '/' + info.baseName() + ".svg";
        if (!QFile::exists(imgPath))
          imgPath = info.absolutePath() + '/' + info.baseName() + ".png";
        if (QFile::exists(imgPath)) {
          preview->setIcon(QIcon(imgPath));
          preview->show();
        } else {
          preview->hide();
        }
      } else {
        preview->hide();
      }
    });

  // Double-click to accept
  connect(treeView, &QTreeView::doubleClicked,
          [&chooser, model, proxy](const QModelIndex& idx) {
            QString filePath =
              idx.data(QFileSystemModel::FilePathRole).toString();
            QFileInfo info(filePath);
            if (info.isFile())
              chooser.accept();
          });

  if (chooser.exec() != QDialog::Accepted)
    return QString();

  // Get selected file
  QModelIndexList selected = treeView->selectionModel()->selectedIndexes();
  if (selected.isEmpty())
    return QString();

  QString filePath =
    selected.first().data(QFileSystemModel::FilePathRole).toString();
  QFileInfo info(filePath);
  if (info.isDir())
    return QString();

  return filePath;
}

void InsertPolymerDialog::loadMonomer(const QString& filePath, int slot)
{
  QFileInfo info(filePath);
  QString name = info.baseName();

  // Read the SMILES from the file
  QFile file(filePath);
  QString smiles;
  if (file.open(QIODevice::ReadOnly | QIODevice::Text)) {
    QTextStream stream(&file);
    smiles = stream.readLine().trimmed();
  }

  // Find the matching image
  QString imgPath = info.absolutePath() + '/' + info.baseName() + ".svg";
  if (!QFile::exists(imgPath))
    imgPath = info.absolutePath() + '/' + info.baseName() + ".png";
  QIcon icon;
  if (QFile::exists(imgPath))
    icon = QIcon(imgPath);

  switch (slot) {
    case 0:
      m_ui->monomerAName->setText(name);
      m_ui->monomerAGraphics->setIcon(icon);
      m_ui->monomerAGraphics->setIconSize(QSize(128, 128));
      m_smilesA = smiles;
      break;
    case 1:
      m_ui->monomerBName->setText(name);
      m_ui->monomerBGraphics->setIcon(icon);
      m_ui->monomerBGraphics->setIconSize(QSize(128, 128));
      m_smilesB = smiles;
      break;
    case 2:
      m_ui->monomerCName->setText(name);
      m_ui->monomerCGraphics->setIcon(icon);
      m_ui->monomerCGraphics->setIconSize(QSize(128, 128));
      m_smilesC = smiles;
      break;
  }
}

void InsertPolymerDialog::chooseMonomerA()
{
  QString filePath = chooseMonomerFile();
  if (filePath.isEmpty())
    return;

  loadMonomer(filePath, 0);

  // Enable B slot
  m_ui->monomerBButton->setEnabled(true);
  m_ui->monomerBName->setEnabled(true);
}

void InsertPolymerDialog::chooseMonomerB()
{
  QString filePath = chooseMonomerFile();
  if (filePath.isEmpty())
    return;

  loadMonomer(filePath, 1);

  m_ui->bRepeatSpinBox->setValue(1);
  m_ui->bRepeatSpinBox->setEnabled(true);
  m_ui->monomerBGraphics->setEnabled(true);

  // Enable C slot
  m_ui->monomerCButton->setEnabled(true);
  m_ui->monomerCName->setEnabled(true);
}

void InsertPolymerDialog::chooseMonomerC()
{
  QString filePath = chooseMonomerFile();
  if (filePath.isEmpty())
    return;

  loadMonomer(filePath, 2);

  if (m_ui->monomerRepeatStyle->currentIndex() != 0)
    m_ui->cRepeatSpinBox->setValue(1);
  m_ui->cRepeatSpinBox->setEnabled(true);
  m_ui->monomerCGraphics->setEnabled(true);
}

void InsertPolymerDialog::validateMonomerRepeats()
{
  int repeatStyle = m_ui->monomerRepeatStyle->currentIndex();
  // 0 == percent, 1 == repeat units
  if (repeatStyle != 0)
    return;

  // For single component, force 100%
  if (!m_ui->bRepeatSpinBox->isEnabled() ||
      m_ui->bRepeatSpinBox->value() == 0) {
    m_ui->aRepeatSpinBox->setValue(100);
    m_ui->bRepeatSpinBox->setValue(0);
    m_ui->cRepeatSpinBox->setValue(0);
    return;
  }

  // For 2 components, adjust the other to sum to 100
  if (!m_ui->cRepeatSpinBox->isEnabled() ||
      m_ui->cRepeatSpinBox->value() == 0) {
    int aVal = m_ui->aRepeatSpinBox->value();
    int bVal = m_ui->bRepeatSpinBox->value();
    // Determine which changed and adjust the other
    // (signals are blocked implicitly by checking before setting)
    if (aVal + bVal != 100) {
      // Just adjust B to complement A
      m_ui->bRepeatSpinBox->setValue(100 - aVal);
    }
    m_ui->cRepeatSpinBox->setValue(0);
    return;
  }

  // For 3 components, indicate validity via style
  int total = m_ui->aRepeatSpinBox->value() + m_ui->bRepeatSpinBox->value() +
              m_ui->cRepeatSpinBox->value();
  QString style = (total != 100) ? "color: red" : "";
  m_ui->aRepeatSpinBox->setStyleSheet(style);
  m_ui->bRepeatSpinBox->setStyleSheet(style);
  m_ui->cRepeatSpinBox->setStyleSheet(style);
}

QString InsertPolymerDialog::monomerSmiles(int slot) const
{
  switch (slot) {
    case 0:
      return m_smilesA;
    case 1:
      return m_smilesB;
    case 2:
      return m_smilesC;
    default:
      return QString();
  }
}

bool InsertPolymerDialog::usesAttachmentPoints(const QString& smiles)
{
  return smiles.contains('*');
}

QString InsertPolymerDialog::cleanSmiles(const QString& smiles)
{
  QString cleaned = smiles;
  while (cleaned.endsWith('/') || cleaned.endsWith('\\') ||
         cleaned.endsWith('=')) {
    cleaned.chop(1);
  }
  return cleaned;
}

QString InsertPolymerDialog::assemblePolymerSmiles() const
{
  QString smiA = monomerSmiles(0);
  if (smiA.isEmpty())
    return QString();

  QString smiB = monomerSmiles(1);
  QString smiC = monomerSmiles(2);

  int aRepeats = m_ui->aRepeatSpinBox->value();
  int bRepeats = m_ui->bRepeatSpinBox->value();
  int cRepeats = m_ui->cRepeatSpinBox->value();
  double aPercent = aRepeats / 100.0;
  double bPercent = bRepeats / 100.0;

  int totalRepeats = m_ui->totalLengthSpinBox->value();
  bool statisticalPolymer = (m_ui->monomerRepeatStyle->currentIndex() == 0);
  int tacticity = m_ui->tacticityComboBox->currentIndex();

  // Check if any monomer uses attachment points
  bool attachMode = usesAttachmentPoints(smiA) ||
                    (!smiB.isEmpty() && usesAttachmentPoints(smiB)) ||
                    (!smiC.isEmpty() && usesAttachmentPoints(smiC));

  QString fullSMI;
  int currentBlock = 0;
  bool switchTacticity = false;
  auto* rng = QRandomGenerator::global();

  for (int repeat = 0; repeat < totalRepeats; ++repeat) {
    QString nextMonomer;

    if (!statisticalPolymer) {
      // Block copolymer: cycle A×aRepeats, B×bRepeats, C×cRepeats
      int totalBlock = aRepeats + bRepeats + cRepeats;
      if (totalBlock == 0)
        totalBlock = 1;
      if (currentBlock < aRepeats)
        nextMonomer = smiA;
      else if (currentBlock < aRepeats + bRepeats)
        nextMonomer = smiB;
      else
        nextMonomer = smiC;
      currentBlock = (currentBlock + 1) % totalBlock;
    } else {
      // Statistical/random copolymer
      double random = rng->generateDouble();
      if (random < aPercent)
        nextMonomer = smiA;
      else if (random < aPercent + bPercent)
        nextMonomer = smiB;
      else
        nextMonomer = smiC;
    }

    if (nextMonomer.isEmpty())
      nextMonomer = smiA; // fallback

    // Apply tacticity
    if (tacticity == 0) {
      // Atactic: random 50% chance to flip @@ to @
      if (rng->generateDouble() < 0.5)
        nextMonomer.replace(QLatin1String("@@"), QLatin1String("@"));
    } else if (tacticity == 2) {
      // Syndiotactic: alternate flipping
      if (switchTacticity)
        nextMonomer.replace(QLatin1String("@@"), QLatin1String("@"));
      switchTacticity = !switchTacticity;
    }
    // Isotactic (1): keep as-is

    if (attachMode) {
      // Attachment point assembly:
      // Replace the last * in fullSMI with nextMonomer (minus its first *)
      if (fullSMI.isEmpty()) {
        fullSMI = nextMonomer;
      } else {
        // Remove the first * from nextMonomer
        QString toInsert = nextMonomer;
        int firstStar = toInsert.indexOf('*');
        if (firstStar >= 0)
          toInsert.remove(firstStar, 1);

        // Replace the last * in fullSMI
        int lastStar = fullSMI.lastIndexOf('*');
        if (lastStar >= 0)
          fullSMI.replace(lastStar, 1, toInsert);
        else
          fullSMI += toInsert; // fallback: no * found, just append
      }
    } else {
      // Concatenation style
      fullSMI += nextMonomer;
    }
  }

  if (attachMode) {
    // Strip remaining * characters from the final string
    fullSMI.remove('*');
  }

  return cleanSmiles(fullSMI);
}

void InsertPolymerDialog::build()
{
  QString smiles = assemblePolymerSmiles();
  if (smiles.isEmpty()) {
    QMessageBox::warning(this, tr("Error"),
                         tr("No monomer specified. Please choose at least "
                            "monomer A."));
    return;
  }

  m_ui->buildPolymerButton->setEnabled(false);
  m_ui->buildPolymerButton->setText(tr("Working..."));

  emit buildPolymer(smiles);

  m_ui->buildPolymerButton->setEnabled(true);
  m_ui->buildPolymerButton->setText(tr("Insert Polymer"));
}

} // namespace Avogadro::QtPlugins
