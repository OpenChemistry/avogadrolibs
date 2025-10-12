/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "playertool.h"

#include <gif.h>
#include <gwavi.h>

#include <avogadro/core/vector.h>
#include <avogadro/qtgui/molecule.h>

#include <QAction>
#include <QOpenGLFramebufferObject>
#include <QOpenGLWidget>
#include <QtCore/QBuffer>
#include <QtCore/QProcess>
#include <QtGui/QIcon>
#include <QtGui/QScreen>
#include <QtGui/QWindow>
#include <QtWidgets/QApplication>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QFileDialog>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QMessageBox>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QSlider>
#include <QtWidgets/QSpinBox>
#include <QtWidgets/QVBoxLayout>

#include <QScreen>

#include <algorithm>
#include <cmath>

namespace Avogadro::QtPlugins {

using QtGui::Molecule;

PlayerTool::PlayerTool(QObject* parent_)
  : QtGui::ToolPlugin(parent_), m_activateAction(new QAction(this)),
    m_molecule(nullptr), m_renderer(nullptr), m_currentFrame(0),
    m_toolWidget(nullptr), m_frameIdx(nullptr), m_firstFrameIdx(nullptr),
    m_lastFrameIdx(nullptr), m_slider(nullptr), m_dynamicBonding(nullptr),
    m_glWidget(nullptr), m_timer(this), m_animationFPS(nullptr),
    playButton(nullptr)
{
  QString shortcut = tr("Ctrl+9", "control-key 9");
  m_activateAction->setText(tr("Player"));
  m_activateAction->setToolTip(tr("Animation Tool\t(%1)").arg(shortcut));
  setIcon();
}

PlayerTool::~PlayerTool() {}

void PlayerTool::setIcon(bool darkTheme)
{
  if (darkTheme) {
    m_activateAction->setIcon(QIcon(":/icons/player_dark.svg"));
  } else {
    m_activateAction->setIcon(QIcon(":/icons/player_light.svg"));
  }
}

QWidget* PlayerTool::toolWidget() const
{
  if (!m_toolWidget) {
    m_toolWidget = new QWidget(qobject_cast<QWidget*>(parent()));
    auto* layout = new QVBoxLayout;
    auto* controls = new QHBoxLayout;
    controls->addStretch(1);
    auto* leftButton = new QPushButton("<");
    connect(leftButton, SIGNAL(clicked()), SLOT(back()));
    controls->addWidget(leftButton);

    int maxFrame = m_molecule->coordinate3dCount();
    if (maxFrame < 1)
      maxFrame = 1;

    auto* frameLabel = new QLabel(tr("Frame:"));
    controls->addWidget(frameLabel);
    m_frameIdx = new QSpinBox;
    m_frameIdx->setValue(1);
    m_frameIdx->setMinimum(1);
    m_frameIdx->setMaximum(maxFrame);
    m_frameIdx->setSuffix("/" + QString::number(maxFrame));
    connect(m_frameIdx, SIGNAL(valueChanged(int)),
            SLOT(spinnerPositionChanged(int)));
    controls->addWidget(m_frameIdx);

    auto* rightButton = new QPushButton(">");
    connect(rightButton, SIGNAL(clicked()), SLOT(forward()));
    controls->addWidget(rightButton);
    controls->addStretch(1);
    layout->addLayout(controls);

    auto* sliderLayout = new QHBoxLayout;
    m_slider = new QSlider(Qt::Horizontal);
    m_slider->setMinimum(0);
    m_slider->setTickInterval(1);
    connect(m_slider, SIGNAL(valueChanged(int)),
            SLOT(sliderPositionChanged(int)));
    sliderLayout->addWidget(m_slider);
    layout->addLayout(sliderLayout);
    if (maxFrame > 1)
      m_slider->setMaximum(maxFrame - 1);

    // start / end frame limits
    auto* frameLayout = new QHBoxLayout;
    auto* label3 = new QLabel(tr("Start:", "start or first frame index"));
    m_firstFrameIdx = new QSpinBox;
    m_firstFrameIdx->setValue(1);
    m_firstFrameIdx->setMinimum(1);
    m_firstFrameIdx->setMaximum(maxFrame);
    connect(m_firstFrameIdx, SIGNAL(valueChanged(int)),
            SLOT(firstFramePositionChanged(int)));
    frameLayout->addWidget(label3);
    frameLayout->addWidget(m_firstFrameIdx);

    // last frame index
    auto* label5 = new QLabel(tr("End:", "end or last frame index"));
    m_lastFrameIdx = new QSpinBox;
    m_lastFrameIdx->setValue(maxFrame);
    m_lastFrameIdx->setMinimum(1);
    m_lastFrameIdx->setMaximum(maxFrame);
    connect(m_lastFrameIdx, SIGNAL(valueChanged(int)),
            SLOT(lastFramePositionChanged(int)));
    frameLayout->addWidget(label5);
    frameLayout->addWidget(m_lastFrameIdx);

    layout->addLayout(frameLayout);

    auto* bonding = new QHBoxLayout;
    bonding->addStretch(1);
    m_dynamicBonding = new QCheckBox(tr("Dynamic bonding?"));
    m_dynamicBonding->setChecked(false);
    bonding->addWidget(m_dynamicBonding);
    bonding->addStretch(1);
    layout->addLayout(bonding);

    auto* frames = new QHBoxLayout;
    frames->addStretch(1);
    auto* label = new QLabel(tr("Frame rate:"));
    frames->addWidget(label);
    m_animationFPS = new QSpinBox;
    m_animationFPS->setValue(5);
    m_animationFPS->setMinimum(0);
    m_animationFPS->setMaximum(1000);
    m_animationFPS->setSuffix(tr(" FPS", "frames per second"));
    frames->addWidget(m_animationFPS);
    frames->addStretch(1);
    layout->addLayout(frames);

    auto* recordLayout = new QHBoxLayout;
    recordLayout->addStretch(1);

    playButton = new QPushButton(tr("Play"));
    playButton->setIcon(QIcon::fromTheme("media-playback-start"));
    connect(playButton, SIGNAL(clicked()), SLOT(play()));
    recordLayout->addWidget(playButton);

    auto* recordButton = new QPushButton(tr("Record…"));
    recordButton->setIcon(QIcon::fromTheme("media-record"));
    connect(recordButton, SIGNAL(clicked()), SLOT(recordMovie()));
    recordLayout->addWidget(recordButton);
    recordLayout->addStretch(1);
    layout->addLayout(recordLayout);

    m_toolWidget->setLayout(layout);
  }
  connect(&m_timer, SIGNAL(timeout()), SLOT(animate()));

  return m_toolWidget;
}

QUndoCommand* PlayerTool::mousePressEvent(QMouseEvent*)
{
  return nullptr;
}

QUndoCommand* PlayerTool::mouseReleaseEvent(QMouseEvent*)
{
  return nullptr;
}

QUndoCommand* PlayerTool::mouseDoubleClickEvent(QMouseEvent*)
{
  return nullptr;
}

void PlayerTool::setActiveWidget(QWidget* widget)
{
  m_glWidget = qobject_cast<QOpenGLWidget*>(widget);
}

void PlayerTool::back()
{
  animate(-1);
}

void PlayerTool::forward()
{
  animate(1);
}

void PlayerTool::play()
{
  if (m_timer.isActive()) {
    stop();
    return;
  } else {
    // change the button to stop / pause
    playButton->setText(tr("Pause"));
    playButton->setIcon(QIcon::fromTheme("media-playback-pause"));
  }

  auto fps = static_cast<double>(m_animationFPS->value());
  if (fps < 0.00001)
    fps = 5;
  int timeOut = static_cast<int>(1000 / fps);
  if (m_timer.isActive())
    m_timer.stop();
  m_timer.start(timeOut);
}

void PlayerTool::stop()
{
  m_timer.stop();

  // set the button for play
  playButton->setText(tr("Play"));
  playButton->setIcon(QIcon::fromTheme("media-playback-start"));
}

void PlayerTool::animate(int advance)
{
  // check the start and end boxes
  int firstFrame = m_firstFrameIdx->value() - 1;
  int lastFrame = m_lastFrameIdx->value() - 1;

  if (m_molecule) {
    if (m_currentFrame < m_molecule->coordinate3dCount() - advance &&
        m_currentFrame + advance >= firstFrame &&
        m_currentFrame + advance <= lastFrame) {
      m_currentFrame += advance;
      m_molecule->setCoordinate3d(m_currentFrame);
    } else {
      int end = std::min(static_cast<int>(m_molecule->coordinate3dCount() - 1),
                         lastFrame);
      m_currentFrame = advance > 0 ? firstFrame : end;
      m_molecule->setCoordinate3d(m_currentFrame);
    }
    if (m_dynamicBonding->isChecked()) {
      m_molecule->clearBonds();
      m_molecule->perceiveBondsSimple();
    }
    m_molecule->emitChanged(Molecule::Atoms | Molecule::Added);
    m_slider->setValue(m_currentFrame);
    m_frameIdx->setValue(m_currentFrame + 1);
  }
}

void PlayerTool::recordMovie()
{
  // Qt 5.14 or later gives the more reliable way for multi-screen
#if QT_VERSION >= 0x050E00
  qreal scaling = m_glWidget->screen()->devicePixelRatio();
#else
  qreal scaling = qApp->devicePixelRatio();
#endif
  int EXPORT_WIDTH = m_glWidget->width() * scaling;
  int EXPORT_HEIGHT = m_glWidget->height() * scaling;

  if (m_timer.isActive())
    m_timer.stop();

  QString baseFileName;
  if (m_molecule)
    baseFileName = m_molecule->data("fileName").toString().c_str();

  // TODO: check path for avconv and disable MP4 if not found
  // TODO: add PNG as an export (i.e., pile of PNG for later use)
  QString selfFilter = tr("Movie (*.mp4)");
  QString baseName = QFileDialog::getSaveFileName(
    qobject_cast<QWidget*>(parent()), tr("Export Bitmap Graphics"), "",
    tr("Movie (*.mp4);;Movie (*.avi);;GIF (*.gif)"), &selfFilter);

  if (baseName.isEmpty())
    return;

  QFileInfo fileInfo(baseName);
  if (!fileInfo.suffix().isEmpty())
    baseName = fileInfo.absolutePath() + "/" + fileInfo.baseName();

  bool bonding = m_dynamicBonding->isChecked();
  int numberLength = static_cast<int>(
    ceil(log10(static_cast<float>(m_molecule->coordinate3dCount()) + 1)));
  // m_glWidget->resize(EXPORT_WIDTH, EXPORT_HEIGHT);

  if (selfFilter == tr("GIF (*.gif)")) {
    GifWriter writer;
    // GIF only supports up to 100 FPS, this minimizes breakage when FPS>100

    if (m_animationFPS->value() > 100) {
      QMessageBox::warning(
        qobject_cast<QWidget*>(parent()), tr("GIF FPS support warning"),
        tr("The GIF file format does not support frame rates over 100 FPS."));
    }
    GifBegin(&writer, (baseName + ".gif").toLatin1().data(), EXPORT_WIDTH,
             EXPORT_HEIGHT, 100 / std::min(m_animationFPS->value(), 100));
    for (int i = 0; i < m_molecule->coordinate3dCount(); ++i) {
      qApp->processEvents();
      m_molecule->setCoordinate3d(i);
      if (bonding) {
        m_molecule->clearBonds();
        m_molecule->perceiveBondsSimple();
      }
      m_molecule->emitChanged(Molecule::Atoms | Molecule::Modified);

      QImage exportImage;
      m_glWidget->raise();
      m_glWidget->repaint();
      if (QOpenGLFramebufferObject::hasOpenGLFramebufferObjects()) {
        exportImage = m_glWidget->grabFramebuffer();
      } else {
        auto* screen = QGuiApplication::primaryScreen();
        auto pixmap = screen->grabWindow(m_glWidget->winId());
        exportImage = pixmap.toImage();
      }

      int frameWidth = exportImage.width();
      int frameHeight = exportImage.height();
      int numbPixels = frameWidth * frameHeight;

      auto* imageData = new uint8_t[numbPixels * 4];
      int imageIndex = 0;
      for (int j = 0; j < frameHeight; ++j) {
        for (int k = 0; k < frameWidth; ++k) {
          QColor color = exportImage.pixel(k, j);
          imageData[imageIndex] = (uint8_t)color.red();
          imageData[imageIndex + 1] = (uint8_t)color.green();
          imageData[imageIndex + 2] = (uint8_t)color.blue();
          imageData[imageIndex + 3] = (uint8_t)color.alpha();
          imageIndex += 4;
        }
      }
      GifWriteFrame(&writer, imageData, EXPORT_WIDTH, EXPORT_HEIGHT,
                    100 / std::min(m_animationFPS->value(), 100));
      delete[] imageData;
    }
    GifEnd(&writer);
  } else if (selfFilter == tr("Movie (*.avi)")) {
    gwavi_t* gwavi;
    gwavi = gwavi_open((baseName + ".avi").toLatin1().data(), EXPORT_WIDTH,
                       EXPORT_HEIGHT, "MJPG", m_animationFPS->value(), nullptr);
    for (int i = 0; i < m_molecule->coordinate3dCount(); ++i) {
      qApp->processEvents();
      m_molecule->setCoordinate3d(i);
      if (bonding) {
        m_molecule->clearBonds();
        m_molecule->perceiveBondsSimple();
      }
      m_molecule->emitChanged(Molecule::Atoms | Molecule::Modified);

      QImage exportImage;
      m_glWidget->raise();
      m_glWidget->repaint();
      if (QOpenGLFramebufferObject::hasOpenGLFramebufferObjects()) {
        exportImage = m_glWidget->grabFramebuffer();
      } else {
        auto* screen = QGuiApplication::primaryScreen();
        auto pixmap = screen->grabWindow(m_glWidget->winId());
        exportImage = pixmap.toImage();
      }
      QByteArray ba;
      QBuffer buffer(&ba);
      buffer.open(QIODevice::WriteOnly);
      exportImage.save(&buffer, "JPG");

      if (gwavi_add_frame(
            gwavi, reinterpret_cast<const unsigned char*>(buffer.data().data()),
            buffer.size()) == -1) {
        QMessageBox::warning(qobject_cast<QWidget*>(parent()), tr("Avogadro"),
                             tr("Error: cannot add frame to video."));
      }
    }
    gwavi_close(gwavi);
  } else if (selfFilter == tr("Movie (*.mp4)")) {
    for (int i = 0; i < m_molecule->coordinate3dCount(); ++i) {
      qApp->processEvents();
      m_molecule->setCoordinate3d(i);
      if (bonding) {
        m_molecule->clearBonds();
        m_molecule->perceiveBondsSimple();
      }
      m_molecule->emitChanged(Molecule::Atoms | Molecule::Modified);
      QString fileName = QString::number(i);
      while (fileName.length() < numberLength)
        fileName.prepend('0');
      fileName.prepend(baseName);
      fileName.append(".png");

      QImage exportImage;
      m_glWidget->raise();
      m_glWidget->repaint();
      if (QOpenGLFramebufferObject::hasOpenGLFramebufferObjects()) {
        exportImage = m_glWidget->grabFramebuffer();
      } else {
        auto* screen = QGuiApplication::primaryScreen();
        auto pixmap = screen->grabWindow(m_glWidget->winId());
        exportImage = pixmap.toImage();
      }

      if (!exportImage.save(fileName)) {
        QMessageBox::warning(qobject_cast<QWidget*>(parent()), tr("Avogadro"),
                             tr("Cannot save file %1.").arg(fileName));
        return;
      }
      QProcess proc;
      QStringList args;
      args << "-y"
           << "-r" << QString::number(m_animationFPS->value()) << "-i"
           << baseName + "%0" + QString::number(numberLength) + "d.png"
           << "-c:v"
           << "libx264"
           << "-r"
           << "30"
           << "-pix_fmt"
           << "yuv420p" << baseName + ".mp4";
      proc.execute("avconv", args);
    }
  }
}

void PlayerTool::sliderPositionChanged(int k)
{
  animate(k - m_currentFrame);
}

void PlayerTool::spinnerPositionChanged(int k)
{
  animate(k - m_currentFrame - 1);
}

void PlayerTool::firstFramePositionChanged(int k)
{
  if (k < 1 || k > m_molecule->coordinate3dCount()) {
    m_firstFrameIdx->setValue(1);
    return;
  }
  m_frameIdx->setMinimum(k);
  if (m_frameIdx->value() < k)
    m_frameIdx->setValue(k);

  m_lastFrameIdx->setMinimum(k);
  if (m_lastFrameIdx->value() < k)
    m_lastFrameIdx->setValue(k);
}

void PlayerTool::lastFramePositionChanged(int k)
{
  if (k < 1 || k > m_molecule->coordinate3dCount()) {
    m_lastFrameIdx->setValue(m_molecule->coordinate3dCount());
    return;
  }
  m_frameIdx->setMaximum(k);
  if (m_frameIdx->value() > k)
    m_frameIdx->setValue(k);
}

void PlayerTool::updateLimits()
{
  int coordCount = m_molecule->coordinate3dCount();

  if (coordCount > 1 && m_slider)
    m_slider->setMaximum(coordCount - 1);
  if (coordCount > 1 && m_frameIdx) {
    m_frameIdx->setMaximum(coordCount);
    m_frameIdx->setSuffix("/" + QString::number(coordCount));
  }
  if (coordCount > 1 && m_firstFrameIdx)
    m_firstFrameIdx->setMaximum(coordCount);
  if (coordCount > 1 && m_lastFrameIdx)
    m_lastFrameIdx->setMaximum(coordCount);

  if (m_firstFrameIdx)
    m_firstFrameIdx->setValue(1);
  if (m_lastFrameIdx)
    m_lastFrameIdx->setValue(coordCount);
}

} // namespace Avogadro::QtPlugins
