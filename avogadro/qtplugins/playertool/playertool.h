/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_PLAYERTOOL_H
#define AVOGADRO_QTPLUGINS_PLAYERTOOL_H

#include <avogadro/qtgui/toolplugin.h>

#include <avogadro/core/array.h>
#include <avogadro/core/avogadrocore.h>
#include <avogadro/core/vector.h>

#include <QtCore/QElapsedTimer>
#include <QtCore/QTimer>

class QComboBox;
class QLabel;
class QSpinBox;
class QCheckBox;
class QOpenGLWidget;
class QPushButton;
class QSlider;
class QWidget;

namespace Avogadro::QtPlugins {

/**
 * @brief PlayerTool enables playback of trajectories.
 */
class PlayerTool : public QtGui::ToolPlugin
{
  Q_OBJECT
public:
  explicit PlayerTool(QObject* p = nullptr);
  ~PlayerTool() override;

  QString name() const override { return tr("Player tool"); }
  QString description() const override { return tr("Play back trajectories"); }
  unsigned char priority() const override { return 80; }
  QAction* activateAction() const override { return m_activateAction; }
  QWidget* toolWidget() const override;
  void setIcon(bool darkTheme = false) override;

  QUndoCommand* mousePressEvent(QMouseEvent* e) override;
  QUndoCommand* mouseReleaseEvent(QMouseEvent* e) override;
  QUndoCommand* mouseDoubleClickEvent(QMouseEvent* e) override;
  QUndoCommand* keyPressEvent(QKeyEvent* e) override;

  /**
   * Registers nextFrame, previousFrame, setCoordinateSet and
   * coordinateSetCount, the scripting / RPC equivalents of the panel's frame
   * controls, and listAnimationSources and setAnimationSource for choosing
   * what they act on. None of them need the tool widget to exist.
   */
  void registerCommands() override;
  bool handleCommand(const QString& command,
                     const QVariantMap& options) override;

public slots:
  void setMolecule(QtGui::Molecule*) override;
  void setGLRenderer(Rendering::GLRenderer* renderer) override;
  void setActiveWidget(QWidget* widget) override;

protected slots:
  /** Pick up conformer changes made elsewhere (e.g. the conformer plot). */
  void moleculeChanged(unsigned int changes);

  /** The molecule's published animation frames changed. */
  void sourcesChanged();

  /** Another animator took over the display: stop playing. */
  void animationPlaybackClaimed(QObject* owner);

  /** The molecule started, stopped or moved the displayed frame. */
  void animationDisplayChanged();

  /** The user picked an entry in the source combo box. */
  void sourceActivated(int index);

  /** Store the displayed geometry of a published source as a new set. */
  void keepFrame();

  void back();
  void forward();
  void play();
  void stop();
  void animate(int advance = 1);
  void animateDue();

  void recordMovie();
  void sliderPositionChanged(int k);
  void spinnerPositionChanged(int k);
  void firstFramePositionChanged(int k);
  void lastFramePositionChanged(int k);
  void updateLimits();

private:
  /** The id of the source that plays the molecule's coordinate sets. */
  static QString trajectoryId() { return QStringLiteral("trajectory"); }

  /** @return True if the current source is a published frame set. */
  bool onPublished() const { return m_source != trajectoryId(); }

  /** @return The number of frames in the current source. */
  int frameTotal() const;

  /** @return The frame shown in the current source. */
  int shownFrame() const
  {
    return onPublished() ? m_sourceFrame : m_currentFrame;
  }

  /**
   * Switch to source @p id. @p userPicked pins the choice against the default
   * rule. @return False if there is no such source.
   */
  bool selectSource(const QString& id, bool userPicked);

  /** Apply the default-source rule, unless the user chose a source. */
  void applyDefaultSource();

  /** Rebuild the combo box and show or hide its row. */
  void rebuildSourceCombo() const;

  /** Enable the controls that only make sense for one kind of source. */
  void updateSourceControls() const;

  /** Stop showing our published frame, restoring the rest positions. */
  void clearOwnDisplay();

  /** Claim the display from other animators, if we do not already hold it. */
  void claimPlayback();

  /** Show frame m_sourceFrame of the published source. */
  void displayPublishedFrame();

  /** Display coordinate set @p frame and update the widgets to match. */
  void setFrame(int frame);

  /** Push m_currentFrame into the slider and spin box without recursing. */
  void syncWidgets();

  /** The {"frame": ..., "count": ...} result every RPC command returns on
   *  success. */
  QVariantMap frameResult() const;

  QAction* m_activateAction;
  QtGui::Molecule* m_molecule;
  Rendering::GLRenderer* m_renderer;
  /** The trajectory frame, tracking the molecule's active coordinate set. */
  int m_currentFrame;
  int m_frameCount;
  /** The source being played: trajectoryId() or a published frame set id. */
  QString m_source = trajectoryId();
  bool m_userPickedSource = false;
  /** The frame shown from a published source. */
  int m_sourceFrame = 0;
  int m_publishedTotal = 0;
  /** True while we are the animator that last claimed the display. */
  bool m_holdsPlayback = false;
  /** Once the source row has appeared it stays for this molecule. */
  mutable bool m_sourceRowShown = false;
  mutable QWidget* m_sourceRow = nullptr;
  mutable QComboBox* m_sourceCombo = nullptr;
  mutable QPushButton* m_keepButton = nullptr;
  bool m_updatingWidgets;
  mutable QWidget* m_toolWidget;
  QTimer m_timer;
  QElapsedTimer m_playClock;
  qint64 m_playTicks = 0;
  double m_playFps = 5.0;
  mutable QSpinBox* m_animationFPS;
  mutable QSpinBox* m_frameIdx;
  mutable QSpinBox* m_firstFrameIdx;
  mutable QSpinBox* m_lastFrameIdx;
  mutable QCheckBox* m_dynamicBonding;
  mutable QOpenGLWidget* m_glWidget;
  mutable QSlider* m_slider;
  mutable QPushButton* playButton;
};

inline void PlayerTool::setGLRenderer(Rendering::GLRenderer* renderer)
{
  m_renderer = renderer;
}

} // namespace Avogadro::QtPlugins

#endif // AVOGADRO_QTPLUGINS_PLAYERTOOL_H
