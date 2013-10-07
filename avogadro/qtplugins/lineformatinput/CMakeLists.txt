include_directories(${CMAKE_CURRENT_BINARY_DIR})

avogadro_plugin(LineFormatInput
  "Enter line formats in a dialog window."
  ExtensionPlugin
  lineformatinput.h
  LineFormatInput
  "lineformatinput.cpp;lineformatinputdialog.cpp"
  "lineformatinputdialog.ui"
)
