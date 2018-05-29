#ifndef STRUCT_ENDIAN_INCLUDED
#define STRUCT_ENDIAN_INCLUDED

#define STRUCT_ENDIAN_NOT_SET 0
#define STRUCT_ENDIAN_BIG 1
#define STRUCT_ENDIAN_LITTLE 2

extern int struct_get_endian(void);

#endif /* !STRUCT_ENDIAN_INCLUDED */
