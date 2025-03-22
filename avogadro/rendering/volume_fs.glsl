#version 330 core

// Scene color behind the volume:
uniform sampler2D inRGBTex;

// The ray entry/exit attachments from bounding‐box passes:
uniform sampler2D inFrontPosTex;
uniform sampler2D inBackPosTex;

// Our 3D volume (wavefunction):
uniform sampler3D uVolumeData;

// Screen size:
uniform float width;
uniform float height;

// Ray‐march parameters:
uniform int   numSteps;    // e.g. 256
uniform float alphaScale;  // overall alpha multiplier

out vec4 outColor;

void main()
{
  vec2 UV = gl_FragCoord.xy / vec2(width, height);

  vec4 sceneColor = texture(inRGBTex, UV);

  vec3 entryPos = texture(inFrontPosTex, UV).xyz;
  vec3 exitPos  = texture(inBackPosTex,  UV).xyz;

  if (entryPos == exitPos) {
    outColor = sceneColor;
    return;
  }

  vec3 entryPoint = entryPos * 2.0 - 1.0;
  vec3 exitPoint  = exitPos  * 2.0 - 1.0;

  vec3 dir = exitPoint - entryPoint;
  float rayLength = length(dir);
  vec3 stepDir = normalize(dir);

  float stepSize = rayLength / float(numSteps);
  vec3 step = stepDir * stepSize;

  vec4 accumulatedColor = vec4(0.0);
  float accumulatedAlpha = 0.0;
  vec3 currentPosition = entryPoint;

  for (int i = 0; i < numSteps; i++)
  {
    if (accumulatedAlpha > 0.98)
      break;

    vec3 volumeUV = (currentPosition * 0.5) + 0.5;

    if (any(lessThan(volumeUV, vec3(0.0))) ||
        any(greaterThan(volumeUV, vec3(1.0))))
    {
      break;
    }

    float psi = texture(uVolumeData, volumeUV).r;

    float amplitude = abs(psi);
    vec3 colorPos = vec3(1.0, 0.0, 0.0); // red
    vec3 colorNeg = vec3(0.0, 0.0, 1.0); // blue
    vec3 color = (psi >= 0.0) ? colorPos : colorNeg;

    float alphaSample = amplitude * alphaScale;

    vec4 colorSample = vec4(color, alphaSample);

    accumulatedColor.rgb += (1.0 - accumulatedAlpha) 
                            * colorSample.rgb 
                            * colorSample.a;
    accumulatedAlpha      += (1.0 - accumulatedAlpha) 
                            * colorSample.a;
    accumulatedColor.a     = accumulatedAlpha;

    currentPosition += step;
  }

  vec4 outCol = mix(sceneColor, accumulatedColor, accumulatedAlpha);

  outColor = outCol;
}
