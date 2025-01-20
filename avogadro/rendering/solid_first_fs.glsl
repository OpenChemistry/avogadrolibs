#version 120

varying vec2 UV;

uniform sampler2D inRGBTex;
uniform sampler2D inFrontPosTex;
uniform sampler2D inBackPosTex;
uniform sampler2D transferTex;
uniform sampler3D uVolumeData;

uniform float inAoEnabled;
uniform float inAoStrength;
uniform float inEdStrength;

uniform float width;
uniform float height;

uniform float transferMin;
uniform float transferMax;

uniform int   numSteps;
uniform float alphaScale;

void main()
{
  vec4 sceneColor = texture2D(inRGBTex, UV);

  vec3 EntryPoint = texture2D(inFrontPosTex, UV).xyz;
  vec3 exitPoint  = texture2D(inBackPosTex,  UV).xyz;

  if (EntryPoint == exitPoint) {
    gl_FragColor = sceneColor;
    return;
  }

  vec3 dir = exitPoint - EntryPoint;
  float len = length(dir);

  vec3 deltaDir = normalize(dir) * (len / float(numSteps));
  float deltaDirLen = length(deltaDir);

  vec4 colorAcum = vec4(0.0);
  float alphaAcum = 0.0;
  float lengthAcum = 0.0;

  vec3 voxelCoord = EntryPoint;

  for(int i = 0; i < numSteps; i++)
  {
    float intensity = texture3D(uVolumeData, voxelCoord).x;

    vec4 colorSample = texture2D(transferTex, vec2(intensity, 0.5));

    colorSample.a *= alphaScale;

    colorAcum.rgb += (1.0 - colorAcum.a) * colorSample.rgb * colorSample.a;
    colorAcum.a   += (1.0 - colorAcum.a) * colorSample.a;

    voxelCoord += deltaDir;
    lengthAcum += deltaDirLen;

    if (lengthAcum >= len || colorAcum.a >= 0.78) {
      break;
    }
  }
  // colorAcum.rgb = colorAcum.rgb / lengthAcum;
  gl_FragColor = mix(sceneColor, colorAcum, colorAcum.a);
}