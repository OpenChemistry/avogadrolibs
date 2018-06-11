add_library(struct STATIC struct.c struct_endian.c)
set_target_properties(struct PROPERTIES POSITION_INDEPENDENT_CODE TRUE)
