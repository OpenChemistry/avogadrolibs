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

#ifndef H_GWAVI_UTILS
#define H_GWAVI_UTILS

#include "gwavi.h"
#include "gwavi_private.h"

/*
 * Utility functions for gwavi library.
 */

#ifdef __cplusplus
extern "C"
{
#endif

  /* Functions declaration */
  int write_avi_header(FILE* out, struct gwavi_header_t* avi_header);
  int write_stream_header(FILE* out,
                          struct gwavi_stream_header_t* stream_header);
  int write_stream_format_v(FILE* out,
                            struct gwavi_stream_format_v_t* stream_format_v);
  int write_stream_format_a(FILE* out,
                            struct gwavi_stream_format_a_t* stream_format_a);
  int write_avi_header_chunk(struct gwavi_t* gwavi);
  int write_index(FILE* out, int count, unsigned int* offsets);
  int check_fourcc(const char* fourcc);

#ifdef __cplusplus
}
#endif

#endif /* ndef GWAVI_UTILS_H */
