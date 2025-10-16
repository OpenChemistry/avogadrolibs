const char *arrow_vs =
  "attribute vec4 vertex;\n"
  "\n"
  "uniform mat4 modelView;\n"
  "uniform mat4 projection;\n"
  "\n"
  "void main()\n"
  "{\n"
  "  gl_FrontColor = vec4(0.0, 1.0, 0.0, 1.0);\n"
  "  gl_Position = projection * modelView * vertex;\n"
  "}\n"
  "\n";
