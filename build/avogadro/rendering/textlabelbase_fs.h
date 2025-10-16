const char *textlabelbase_fs =
  "uniform sampler2D texture;\n"
  "varying vec2 texc;\n"
  "\n"
  "void main(void)\n"
  "{\n"
  "  gl_FragColor = texture2D(texture, texc);\n"
  "  if (gl_FragColor.a == 0.)\n"
  "    discard;\n"
  "}\n"
  "\n";
