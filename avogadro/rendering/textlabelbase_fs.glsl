uniform sampler2D texture;
varying vec2 texc;

void main(void)
{
  gl_FragColor = texture2D(texture, texc);
  if (gl_FragColor.a == 0.)
    discard;
}
