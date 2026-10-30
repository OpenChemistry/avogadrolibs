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
#include <utility>

namespace Avogadro::QtOpenGL {

namespace {
constexpr int MaxDimension = RenderOptions::MaxDimension;
}

ImageSizeDialog::ImageSizeDialog(GLWidget* glWidget, QString settingsKey,
                                 bool showTransparent, bool evenDimensions,
                                 QWidget* parent, bool defaultTransparent)
  : QDialog(parent), m_glWidget(glWidget),
    m_settingsKey(std::move(settingsKey)), m_even(evenDimensions),
    m_transparent(nullptr)
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
  if (showTransparent)
    m_transparent = new QCheckBox(tr("&Transparent background"));

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
  if (m_transparent != nullptr)
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
  if (m_transparent != nullptr) {
    m_transparent->setChecked(
      settings.value("transparent", defaultTransparent).toBool());
  }
  settings.endGroup();
  setImageSize(size);
  updateAspect();

  connect(m_width, &QSpinBox::valueChanged, this,
          &ImageSizeDialog::widthEdited);
  connect(m_height, &QSpinBox::valueChanged, this,
          &ImageSizeDialog::heightEdited);
  connect(m_lock, &QCheckBox::toggled, this, &ImageSizeDialog::lockToggled);
}

QSize ImageSizeDialog::viewPixelSize() const
{
  const QSize size = m_glWidget != nullptr ? m_glWidget->pixelSize() : QSize();
  if (size.width() < 1 || size.height() < 1)
    return QSize(800, 600);
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
  return m_transparent != nullptr && m_transparent->isChecked();
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

void ImageSizeDialog::dimensionEdited(QSpinBox* changed, QSpinBox* other,
                                      int value)
{
  const int v = normalized(value);
  if (v != value) {
    QSignalBlocker block(changed);
    changed->setValue(v);
  }
  if (m_lock->isChecked()) {
    // The width is aspect times the height; the height is the width over it.
    const double scaled = changed == m_width ? v / m_aspect : v * m_aspect;
    QSignalBlocker block(other);
    other->setValue(normalized(static_cast<int>(std::lround(scaled))));
  } else {
    updateAspect();
  }
}

void ImageSizeDialog::widthEdited(int value)
{
  dimensionEdited(m_width, m_height, value);
}

void ImageSizeDialog::heightEdited(int value)
{
  dimensionEdited(m_height, m_width, value);
}

void ImageSizeDialog::updateAspect()
{
  m_aspect = static_cast<double>(m_width->value()) / m_height->value();
}

void ImageSizeDialog::lockToggled(bool locked)
{
  if (locked)
    updateAspect();
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
  if (m_transparent != nullptr)
    settings.setValue("transparent", m_transparent->isChecked());
  settings.endGroup();
  QDialog::accept();
}

} // namespace Avogadro::QtOpenGL
