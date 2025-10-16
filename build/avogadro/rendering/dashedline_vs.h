const char *dashedline_vs =
  "attribute vec4 vertex;\n"
  "attribute vec4 color;\n"
  "\n"
  "uniform mat4 modelView;\n"
  "uniform mat4 projection;\n"
  "\n"
  "void main()\n"
  "{\n"
  "  gl_FrontColor = color;\n"
  "  gl_Position = projection * modelView * vertex;\n"
  "}\n"
  "\n";
