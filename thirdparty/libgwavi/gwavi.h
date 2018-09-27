/*
 * Copyright (c) 2008-2011, Michael Kohn
 * Copyright (c) 2013, Robin Hahling
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of the author nor the names of its contributors may be
 *   used to endorse or promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef H_GWAVI
#define H_GWAVI

#ifdef __cplusplus
extern "C"
{
#endif

  /* structures */
  struct gwavi_t;
  struct gwavi_audio_t;

  /* Main library functions */
  struct gwavi_t* gwavi_open(const char* filename, unsigned int width,
                             unsigned int height, const char* fourcc,
                             unsigned int fps, struct gwavi_audio_t* audio);
  int gwavi_add_frame(struct gwavi_t* gwavi, const unsigned char* buffer,
                      size_t len);
  int gwavi_add_audio(struct gwavi_t* gwavi, const unsigned char* buffer,
                      size_t len);
  int gwavi_close(struct gwavi_t* gwavi);

  /*
   * If needed, these functions can be called before closing the file to
   * change the framerate, codec, size.
   * Note: AVI can only have a single frame rate, codec, size for the whole file
   * so this affects anything recorded before these functions are called.
   */
  int gwavi_set_framerate(struct gwavi_t* gwavi, unsigned int fps);
  int gwavi_set_codec(struct gwavi_t* gwavi, char* fourcc);
  int gwavi_set_size(struct gwavi_t* gwavi, unsigned int width,
                     unsigned int height);

#ifdef __cplusplus
}
#endif

#endif /* ndef H_GWAVI */
