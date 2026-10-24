/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "imagesizedialog.h"

#include "glwidget.h"

#include <QCheckBox>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QSettings>
#include <QSignalBlocker>
#include <QSpinBox>
#include <QVBoxLayout>

#include <algorithm>
#include <cmath>

namespace Avogadro::QtOpenGL {

namespace {
constexpr int MaxDimension = 8192;
}

ImageSizeDialog::ImageSizeDialog(GLWidget* glWidget, const QString& settingsKey,
                                 bool showTransparent, bool evenDimensions,
                                 QWidget* parent, bool defaultTransparent)
  : QDialog(parent), m_glWidget(glWidget), m_settingsKey(settingsKey),
    m_even(evenDimensions), m_showTransparent(showTransparent)
{
  setWindowTitle(tr("Image Size"));

  m_width = new QSpinBox;
  m_width->setRange(1, MaxDimension);
  m_width->setSuffix(tr(" px"));
  m_height = new QSpinBox;
  m_height->setRange(1, MaxDimension);
  m_height->setSuffix(tr(" px"));
  if (m_even) {
    m_width->setSingleStep(2);
    m_height->setSingleStep(2);
  }

  m_lock = new QCheckBox(tr("&Lock aspect ratio"));
  // Parented to the dialog even when not shown, so it is never a top-level
  // window and is freed with the dialog. It only joins the layout (and so
  // only appears) when asked for.
  m_transparent = new QCheckBox(tr("&Transparent background"), this);
  if (!m_showTransparent)
    m_transparent->hide();

  auto* widthLabel = new QLabel(tr("&Width:"));
  widthLabel->setBuddy(m_width);
  auto* heightLabel = new QLabel(tr("&Height:"));
  heightLabel->setBuddy(m_height);

  auto* presets = new QHBoxLayout;
  const int scales[] = { 1, 2, 4 };
  for (int scale : scales) {
    auto* button = new QPushButton(tr("%1×").arg(scale));
    button->setToolTip(
      tr("Set the size to %1× the size of the view").arg(scale));
    button->setAutoDefault(false);
    connect(button, &QPushButton::clicked, this,
            [this, scale]() { applyPreset(scale); });
    presets->addWidget(button);
  }
  presets->addStretch();

  auto* form = new QFormLayout;
  form->addRow(widthLabel, m_width);
  form->addRow(heightLabel, m_height);
  form->addRow(QString(), m_lock);
  form->addRow(tr("Size of view:"), presets);
  if (m_showTransparent)
    form->addRow(QString(), m_transparent);

  auto* buttons =
    new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
  connect(buttons, &QDialogButtonBox::accepted, this, &QDialog::accept);
  connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);

  auto* layout = new QVBoxLayout(this);
  layout->addLayout(form);
  layout->addWidget(buttons);

  // Initial values: the remembered ones, else the view size.
  QSettings settings;
  settings.beginGroup(m_settingsKey);
  QSize size(settings.value("width", 0).toInt(),
             settings.value("height", 0).toInt());
  if (size.width() < 1 || size.height() < 1)
    size = viewPixelSize();
  m_lock->setChecked(settings.value("aspectLock", true).toBool());
  m_transparent->setChecked(
    settings.value("transparent", defaultTransparent).toBool());
  settings.endGroup();
  setImageSize(size);
  m_aspect = static_cast<double>(m_width->value()) / m_height->value();

  connect(m_width, &QSpinBox::valueChanged, this,
          &ImageSizeDialog::widthEdited);
  connect(m_height, &QSpinBox::valueChanged, this,
          &ImageSizeDialog::heightEdited);
  connect(m_lock, &QCheckBox::toggled, this, &ImageSizeDialog::lockToggled);
}

QSize ImageSizeDialog::viewPixelSize() const
{
  if (m_glWidget == nullptr)
    return QSize(800, 600);
  const qreal dpr = m_glWidget->devicePixelRatioF();
  QSize size(static_cast<int>(std::lround(m_glWidget->width() * dpr)),
             static_cast<int>(std::lround(m_glWidget->height() * dpr)));
  if (size.width() < 1 || size.height() < 1)
    size = QSize(800, 600);
  return size;
}

int ImageSizeDialog::normalized(int value) const
{
  value = std::clamp(value, 1, MaxDimension);
  if (m_even && value % 2 != 0)
    value = value < MaxDimension ? value + 1 : value - 1;
  return value;
}

QSize ImageSizeDialog::imageSize() const
{
  return QSize(m_width->value(), m_height->value());
}

bool ImageSizeDialog::transparentBackground() const
{
  return m_showTransparent && m_transparent->isChecked();
}

RenderOptions ImageSizeDialog::renderOptions() const
{
  RenderOptions options;
  options.size = imageSize();
  options.transparentBackground = transparentBackground();
  return options;
}

void ImageSizeDialog::setImageSize(const QSize& size)
{
  QSignalBlocker blockW(m_width);
  QSignalBlocker blockH(m_height);
  m_width->setValue(normalized(size.width()));
  m_height->setValue(normalized(size.height()));
}

void ImageSizeDialog::widthEdited(int value)
{
  const int w = normalized(value);
  if (w != value) {
    QSignalBlocker block(m_width);
    m_width->setValue(w);
  }
  if (m_lock->isChecked()) {
    QSignalBlocker block(m_height);
    m_height->setValue(normalized(static_cast<int>(std::lround(w / m_aspect))));
  } else {
    m_aspect = static_cast<double>(w) / m_height->value();
  }
}

void ImageSizeDialog::heightEdited(int value)
{
  const int h = normalized(value);
  if (h != value) {
    QSignalBlocker block(m_height);
    m_height->setValue(h);
  }
  if (m_lock->isChecked()) {
    QSignalBlocker block(m_width);
    m_width->setValue(normalized(static_cast<int>(std::lround(h * m_aspect))));
  } else {
    m_aspect = static_cast<double>(m_width->value()) / h;
  }
}

void ImageSizeDialog::lockToggled(bool locked)
{
  if (locked)
    m_aspect = static_cast<double>(m_width->value()) / m_height->value();
}

void ImageSizeDialog::applyPreset(int scale)
{
  const QSize view = viewPixelSize();
  setImageSize(QSize(view.width() * scale, view.height() * scale));
  // Presets follow the view's aspect ratio, which the lock should now keep.
  m_aspect = static_cast<double>(view.width()) / view.height();
}

void ImageSizeDialog::accept()
{
  QSettings settings;
  settings.beginGroup(m_settingsKey);
  settings.setValue("width", m_width->value());
  settings.setValue("height", m_height->value());
  settings.setValue("aspectLock", m_lock->isChecked());
  if (m_showTransparent)
    settings.setValue("transparent", m_transparent->isChecked());
  settings.endGroup();
  QDialog::accept();
}

} // namespace Avogadro::QtOpenGL
