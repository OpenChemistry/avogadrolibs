#include "struct_endian.h"

int struct_get_endian(void)
{
  int i = 0x00000001;
  if (((char*)&i)[0]) {
    return STRUCT_ENDIAN_LITTLE;
  } else {
    return STRUCT_ENDIAN_BIG;
  }
}
