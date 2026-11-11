/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_COPYASDIALOG_H
#define AVOGADRO_QTPLUGINS_COPYASDIALOG_H

#include <QtWidgets/QDialog>

#include <memory>
#include <string>
#include <vector>

class QListWidget;

namespace Avogadro {
namespace Io {
class FileFormat;
}

namespace QtPlugins {

/** A text format offered by the "Copy As > Other Format" dialog. */
struct CopyAsFormat
{
  /** Untranslated name shown to the user, also the stored "last used" key. */
  QString label;
  /** Preferred writer, looked up by identifier. */
  std::string identifier;
  /** Fallback writer (e.g., from Open Babel), looked up by extension. */
  std::string extension;
};

/**
 * @brief Pick a text format to copy the molecule to the clipboard in.
 */
class CopyAsDialog : public QDialog
{
  Q_OBJECT
public:
  /**
   * @param formats The formats to list, in order.
   * @param preselect The label of the entry to select first, if present.
   */
  CopyAsDialog(const std::vector<CopyAsFormat>& formats,
               const QString& preselect, QWidget* parent = nullptr);

  /** @return The index into the list given to the constructor, or -1. */
  int selectedIndex() const;

  /**
   * @return The curated formats whose writers are available right now, in
   * display order. Entries without a string writer are left out.
   */
  static std::vector<CopyAsFormat> availableFormats();

  /**
   * @return A new writer for @p format (by identifier, then by extension), or
   * nullptr if none can write to a string.
   */
  static std::unique_ptr<Io::FileFormat> createFormat(
    const CopyAsFormat& format);

private:
  QListWidget* m_list;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_COPYASDIALOG_H
