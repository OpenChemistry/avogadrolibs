#version 400

in vec4 outColor;
in float fragLineParam;
out vec4 colorOut;

void main()
{
  // Dashed line support: lineParam ranges from 0 to dashCount*2.
  // Each period of 2.0 has a dash [0,1) and a gap [1,2).
  // For solid lines, lineParam is 0 everywhere (never discarded).
  if (fragLineParam > 0.0) {
    float phase = mod(fragLineParam, 2.0);
    if (phase > 1.0)
      discard;
  }
  colorOut = outColor;
}
