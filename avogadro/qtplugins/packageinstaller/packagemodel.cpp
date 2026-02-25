/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "packagemodel.h"

#include <avogadro/qtgui/packagemanager.h>

#include <QtCore/QDateTime>
#include <QtCore/QFileInfo>
#include <QtCore/QHash>
#include <QtCore/QLocale>
#include <QtCore/QStringList>
#include <QtGui/QIcon>

#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace Avogadro::QtPlugins {

PackageModel::PackageModel(QObject* parent) : QAbstractTableModel(parent) {}

// ---------------------------------------------------------------------------
// QAbstractTableModel interface
// ---------------------------------------------------------------------------

int PackageModel::rowCount(const QModelIndex& parent) const
{
  return parent.isValid() ? 0 : static_cast<int>(m_entries.size());
}

int PackageModel::columnCount(const QModelIndex& parent) const
{
  return parent.isValid() ? 0 : ColumnCount;
}

QVariant PackageModel::data(const QModelIndex& index, int role) const
{
  if (!index.isValid() || index.row() >= m_entries.size())
    return {};

  const PackageEntry& e = m_entries[index.row()];

  if (role == Qt::CheckStateRole && index.column() == StatusColumn)
    return e.checked ? Qt::Checked : Qt::Unchecked;

  if (role == Qt::DecorationRole && index.column() == StatusColumn)
    return statusIcon(e.status);

  if (role == Qt::ToolTipRole && index.column() == StatusColumn) {
    switch (e.status) {
      case PackageStatus::NotInstalled:
        return tr("Not installed");
      case PackageStatus::Installed:
        return tr("Installed (up to date)");
      case PackageStatus::UpdateAvailable:
        return tr("Update available");
      case PackageStatus::LocalOnly:
        return tr("Installed locally (not in online catalog)");
    }
  }

  if (role == Qt::DisplayRole) {
    switch (index.column()) {
      case StatusColumn:
        return {};
      case NameColumn:
        return e.name;
      case InstalledColumn:
        return e.installedVersion;
      case AvailableColumn:
        if (e.status == PackageStatus::LocalOnly)
          return tr("local only");
        return e.hasRelease ? e.onlineVersion : e.updatedAt;
      case DescriptionColumn:
        return e.description;
      default:
        return {};
    }
  }

  return {};
}

bool PackageModel::setData(const QModelIndex& index, const QVariant& value,
                           int role)
{
  if (!index.isValid() || index.row() >= m_entries.size())
    return false;

  if (role == Qt::CheckStateRole && index.column() == StatusColumn) {
    m_entries[index.row()].checked = (value.toInt() == Qt::Checked);
    emit dataChanged(index, index, { Qt::CheckStateRole });
    return true;
  }
  return false;
}

QVariant PackageModel::headerData(int section, Qt::Orientation orientation,
                                  int role) const
{
  if (orientation != Qt::Horizontal || role != Qt::DisplayRole)
    return {};
  switch (section) {
    case StatusColumn:
      return tr("Status");
    case NameColumn:
      return tr("Name");
    case InstalledColumn:
      return tr("Installed");
    case AvailableColumn:
      return tr("Available");
    case DescriptionColumn:
      return tr("Description");
    default:
      return {};
  }
}

Qt::ItemFlags PackageModel::flags(const QModelIndex& index) const
{
  if (!index.isValid())
    return Qt::NoItemFlags;

  Qt::ItemFlags f = Qt::ItemIsEnabled | Qt::ItemIsSelectable;
  if (index.column() == StatusColumn)
    f |= Qt::ItemIsUserCheckable;
  return f;
}

// ---------------------------------------------------------------------------
// Data loading
// ---------------------------------------------------------------------------

void PackageModel::loadOnlineCatalog(const QByteArray& jsonBytes)
{
  beginResetModel();
  m_entries.clear();

  if (!json::accept(jsonBytes.data())) {
    endResetModel();
    return;
  }

  json root = json::parse(jsonBytes.data());
  if (!root.is_array()) {
    endResetModel();
    return;
  }

  for (const auto& item : root) {
    if (!item.is_object())
      continue;

    PackageEntry e;
    auto get = [&](const char* key, QString& out) {
      auto it = item.find(key);
      if (it != item.end() && it->is_string())
        out = QString::fromStdString(it->get<std::string>());
    };

    get("name", e.name);
    get("description", e.description);
    get("release_version", e.onlineVersion);
    get("type", e.type);
    get("zipball_url", e.zipballUrl);
    get("repo_url", e.baseUrl);
    get("readme_url", e.readmeUrl);

    auto hasIt = item.find("has_release");
    if (hasIt != item.end() && hasIt->is_boolean())
      e.hasRelease = hasIt->get<bool>();

    auto dateIt = item.find("updated_at");
    if (dateIt != item.end() && dateIt->is_string()) {
      QString raw = QString::fromStdString(dateIt->get<std::string>());
      QDateTime dt = QDateTime::fromString(raw, Qt::ISODate);
      e.updatedAt = QLocale().toString(dt.date(), QLocale::ShortFormat);
    }

    // Derive readmeUrl from baseUrl if not supplied
    if (e.readmeUrl.isEmpty() && !e.baseUrl.isEmpty()) {
      QStringList parts = e.baseUrl.split('/');
      parts.append(QStringLiteral("readme"));
      e.readmeUrl = parts.join('/');
    }

    e.status = PackageStatus::NotInstalled;
    if (!e.name.isEmpty())
      m_entries.append(e);
  }

  endResetModel();
}

void PackageModel::mergeInstalledPackages()
{
  // Use a full model reset because we may be adding or removing LocalOnly rows.
  beginResetModel();

  // First, clear any previously set installed state from catalog entries
  for (PackageEntry& e : m_entries) {
    if (e.status != PackageStatus::LocalOnly) {
      e.installedVersion.clear();
      e.installedDir.clear();
      e.isSymlink = false;
      e.status = PackageStatus::NotInstalled;
      e.checked = false;
    }
  }
  // Remove any previously added LocalOnly entries
  m_entries.removeIf(
    [](const PackageEntry& e) { return e.status == PackageStatus::LocalOnly; });

  QtGui::PackageManager* pm = QtGui::PackageManager::instance();
  const QStringList installed = pm->registeredPackages();

  // Build lookup maps from name and baseUrl-derived key
  // key: package name → index in m_entries
  QHash<QString, int> byName;
  // key: last path segment of baseUrl → index
  QHash<QString, int> byRepoSlug;
  for (int i = 0; i < m_entries.size(); ++i) {
    const PackageEntry& e = m_entries[i];
    if (!e.name.isEmpty())
      byName[e.name.toLower()] = i;
    if (!e.baseUrl.isEmpty()) {
      // e.g. "https://github.com/OpenChemistry/crystals" → "crystals"
      QString slug = e.baseUrl.split('/').last().toLower();
      if (!slug.isEmpty())
        byRepoSlug[slug] = i;
    }
  }

  for (const QString& pkgName : installed) {
    QtGui::PackageManager::PackageInfo info = pm->packageInfo(pkgName);

    // Determine if the installed directory is a symlink
    bool symlink = QFileInfo(info.directory).isSymLink();

    // Try to find a matching entry in the online catalog.
    // 1. Match by project name
    int idx = -1;
    if (byName.contains(pkgName.toLower()))
      idx = byName[pkgName.toLower()];

    // 2. Match by directory base name (repo slug)
    if (idx == -1) {
      QString dirBase = QFileInfo(info.directory).fileName().toLower();
      if (byRepoSlug.contains(dirBase))
        idx = byRepoSlug[dirBase];
    }

    if (idx != -1) {
      PackageEntry& e = m_entries[idx];
      e.installedVersion = info.version;
      e.installedDir = info.directory;
      e.isSymlink = symlink;
      e.status = computeStatus(e);
    } else {
      // LocalOnly — installed but not in the online catalog
      PackageEntry e;
      e.name = pkgName;
      e.description = info.description;
      e.installedVersion = info.version;
      e.installedDir = info.directory;
      e.isSymlink = symlink;
      e.status = PackageStatus::LocalOnly;
      m_entries.append(e);
    }
  }

  // Pre-check any UpdateAvailable entries
  for (PackageEntry& e : m_entries) {
    if (e.status == PackageStatus::UpdateAvailable)
      e.checked = true;
  }

  endResetModel();
}

// ---------------------------------------------------------------------------
// Accessors
// ---------------------------------------------------------------------------

QString PackageModel::readmeUrl(int row) const
{
  if (row < 0 || row >= m_entries.size())
    return {};
  return m_entries[row].readmeUrl;
}

QList<int> PackageModel::checkedRows() const
{
  QList<int> result;
  for (int i = 0; i < m_entries.size(); ++i) {
    if (m_entries[i].checked)
      result.append(i);
  }
  return result;
}

void PackageModel::setChecked(int row, bool checked)
{
  if (row < 0 || row >= m_entries.size())
    return;
  m_entries[row].checked = checked;
  QModelIndex idx = index(row, StatusColumn);
  emit dataChanged(idx, idx, { Qt::CheckStateRole });
}

void PackageModel::uncheckAll()
{
  for (PackageEntry& e : m_entries)
    e.checked = false;
  emit dataChanged(index(0, StatusColumn), index(rowCount() - 1, StatusColumn),
                   { Qt::CheckStateRole });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

PackageModel::PackageStatus PackageModel::computeStatus(const PackageEntry& e)
{
  if (e.installedDir.isEmpty())
    return PackageStatus::NotInstalled;
  if (e.status == PackageStatus::LocalOnly)
    return PackageStatus::LocalOnly;
  // Compare versions only when both sides are non-empty
  if (!e.installedVersion.isEmpty() && !e.onlineVersion.isEmpty() &&
      e.installedVersion != e.onlineVersion) {
    return PackageStatus::UpdateAvailable;
  }
  return PackageStatus::Installed;
}

QIcon PackageModel::statusIcon(PackageStatus status)
{
  switch (status) {
    case PackageStatus::NotInstalled:
      return QIcon::fromTheme(QStringLiteral("package-available"),
                              QIcon::fromTheme(QStringLiteral("list-add")));
    case PackageStatus::Installed:
      return QIcon::fromTheme(
        QStringLiteral("package-installed-updated"),
        QIcon::fromTheme(QStringLiteral("dialog-ok-apply")));
    case PackageStatus::UpdateAvailable:
      return QIcon::fromTheme(
        QStringLiteral("package-upgrade"),
        QIcon::fromTheme(QStringLiteral("software-update-available")));
    case PackageStatus::LocalOnly:
      return QIcon::fromTheme(QStringLiteral("folder-development"),
                              QIcon::fromTheme(QStringLiteral("folder")));
  }
  return {};
}

} // namespace Avogadro::QtPlugins
