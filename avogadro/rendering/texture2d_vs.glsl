attribute vec4 vertex;
attribute vec4 texCoord;

varying vec4 texc;
uniform mat4 mvp;

void main(void)
{
  gl_Position = mvp * vertex;
  texc = texCoord;
}
