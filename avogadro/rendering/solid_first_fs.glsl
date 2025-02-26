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

uniform int numSteps;
uniform float alphaScale;


void main()
{
  // Sample the current scene color.
  vec4 sceneColor = texture2D(inRGBTex, UV);

  // Retrieve the ray’s entry and exit positions.
  vec3 entryPoint = texture2D(inFrontPosTex, UV).xyz;
  vec3 exitPoint  = texture2D(inBackPosTex,  UV).xyz;


  // Remap from [-1,1] to [0,1]
  // entryPoint = entryPoint * 0.5 + 0.5;
  // exitPoint  = exitPoint  * 0.5 + 0.5;

  // If there’s no valid ray, return the scene color.
  if (entryPoint == exitPoint) {
    gl_FragColor = sceneColor;
    return;
  }

  // Compute the ray direction and its total length.
  vec3 dir = exitPoint - entryPoint;
  float rayLength = length(dir);

  // Calculate a normalized step so that we march exactly from entry to exit.
  vec3 step = normalize(dir) * (rayLength / float(numSteps));

  // Initialize the ray marching variables.
  vec4 accumulatedColor = vec4(0.0);
  float accumulatedAlpha = 0.0;
  float accumulatedLength = 0.0;
  vec3 currentPosition = entryPoint;

  // Ray marching loop.
  for (int i = 0; i < numSteps; i++)
  {
    // Early exit if we have reached the end of the ray or opacity is nearly full.
    if (accumulatedLength >= rayLength || accumulatedAlpha >= 1.0)
      break;

    // Sample the volume at the current position.
    // (Assumes the volume data is a scalar intensity in the red channel.)
    float intensity = texture3D(uVolumeData, currentPosition).x;

    // Look up the transfer function using the intensity value.
    // The transfer texture maps the intensity (x coordinate) to a color and opacity.
    vec4 colorSample = texture2D(transferTex, vec2(intensity, 0.5));

    // Apply the alpha correction.
    colorSample.a *= alphaScale;

    // Composite the current sample using front-to-back accumulation.
    accumulatedColor.rgb += (1.0 - accumulatedAlpha) * colorSample.rgb * colorSample.a;
    accumulatedAlpha += (1.0 - accumulatedAlpha) * colorSample.a;
    accumulatedColor.a = accumulatedAlpha;

    // Advance the ray.
    currentPosition += step;
    accumulatedLength += length(step);
  }

  // Composite the computed volume color with the original scene color.
  gl_FragColor = mix(sceneColor, accumulatedColor, accumulatedColor.a);
}
