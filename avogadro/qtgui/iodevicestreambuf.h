/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTGUI_IODEVICESTREAMBUF_H
#define AVOGADRO_QTGUI_IODEVICESTREAMBUF_H

#include <QtCore/QIODevice>

#include <streambuf>

namespace Avogadro::QtGui {

/**
 * @class IODeviceStreamBuf iodevicestreambuf.h
 * <avogadro/qtgui/iodevicestreambuf.h>
 * @brief A std::streambuf that writes straight to a QIODevice.
 *
 * Use it to give code that writes to a std::ostream (such as the scene
 * exporters) a file or other device without an intermediate copy:
 * @code
 * IODeviceStreamBuf buffer(file);
 * std::ostream stream(&buffer);
 * @endcode
 * Every write is checked: a short write makes the stream fail. The device
 * must be open for writing and outlive the buffer. Output only.
 */
class IODeviceStreamBuf : public std::streambuf
{
public:
  explicit IODeviceStreamBuf(QIODevice& device) : m_device(device) {}

protected:
  std::streamsize xsputn(const char* data, std::streamsize count) override
  {
    std::streamsize done = 0;
    while (done < count) {
      const qint64 written = m_device.write(data + done, count - done);
      if (written <= 0)
        break;
      done += written;
    }
    return done;
  }

  int_type overflow(int_type ch) override
  {
    if (traits_type::eq_int_type(ch, traits_type::eof()))
      return traits_type::not_eof(ch);
    const char c = traits_type::to_char_type(ch);
    return xsputn(&c, 1) == 1 ? ch : traits_type::eof();
  }

private:
  QIODevice& m_device;
};

} // namespace Avogadro::QtGui

#endif // AVOGADRO_QTGUI_IODEVICESTREAMBUF_H
