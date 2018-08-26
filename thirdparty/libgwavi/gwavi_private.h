#ifndef GWAVI_PRIVATE_H
#define GWAVI_PRIVATE_H
/*
 * gwavi_private.h
 *
 * gwavi declarations that shall remain private :-)
 */

#include <stdio.h>

#ifdef __cplusplus
extern "C"
{
#endif

  /* structures */
  struct gwavi_header_t
  {
    unsigned int time_delay; /* dwMicroSecPerFrame */
    unsigned int data_rate;  /* dwMaxBytesPerSec */
    unsigned int reserved;
    unsigned int flags;            /* dwFlags */
    unsigned int number_of_frames; /* dwTotalFrames */
    unsigned int initial_frames;   /* dwInitialFrames */
    unsigned int data_streams;     /* dwStreams */
    unsigned int buffer_size;      /* dwSuggestedBufferSize */
    unsigned int width;            /* dwWidth */
    unsigned int height;           /* dwHeight */
    unsigned int time_scale;
    unsigned int playback_data_rate;
    unsigned int starting_time;
    unsigned int data_length;
  };

  struct gwavi_stream_header_t
  {
    char data_type[5];  /* fccType */
    char codec[5];      /* fccHandler */
    unsigned int flags; /* dwFlags */
    unsigned int priority;
    unsigned int initial_frames; /* dwInitialFrames */
    unsigned int time_scale;     /* dwScale */
    unsigned int data_rate;      /* dwRate */
    unsigned int start_time;     /* dwStart */
    unsigned int data_length;    /* dwLength */
    unsigned int buffer_size;    /* dwSuggestedBufferSize */
    unsigned int video_quality;  /* dwQuality */
    /**
     * Value between 0-10000. If set to -1, drivers use default quality
     * value.
     */
    int audio_quality;
    unsigned int sample_size; /* dwSampleSize */
  };

  struct gwavi_stream_format_v_t
  {
    unsigned int header_size;
    unsigned int width;
    unsigned int height;
    unsigned short int num_planes;
    unsigned short int bits_per_pixel;
    unsigned int compression_type;
    unsigned int image_size;
    unsigned int x_pels_per_meter;
    unsigned int y_pels_per_meter;
    unsigned int colors_used;
    unsigned int colors_important;
    unsigned int* palette;
    unsigned int palette_count;
  };

  struct gwavi_stream_format_a_t
  {
    unsigned short format_type;
    unsigned int channels;
    unsigned int sample_rate;
    unsigned int bytes_per_second;
    unsigned int block_align;
    unsigned int bits_per_sample;
    unsigned short size;
  };

  struct gwavi_t
  {
    FILE* out;
    struct gwavi_header_t avi_header;
    struct gwavi_stream_header_t stream_header_v;
    struct gwavi_stream_format_v_t stream_format_v;
    struct gwavi_stream_header_t stream_header_a;
    struct gwavi_stream_format_a_t stream_format_a;
    long marker;
    int offsets_ptr;
    int offsets_len;
    long offsets_start;
    unsigned int* offsets;
    int offset_count;
  };

  struct gwavi_audio_t
  {
    unsigned int channels;
    unsigned int bits;
    unsigned int samples_per_second;
  };

#ifdef __cplusplus
}
#endif

#endif /* ndef GWAVI_PRIVATE_H */
