#version 330 core

// Scene color
uniform sampler2D inRGBTex;       // Original background color
// The entry/exit pos attachments from bounding‐box passes
uniform sampler2D inFrontPosTex;
uniform sampler2D inBackPosTex;

// Transfer function + volume data
uniform sampler2D transferTex;
uniform sampler3D uVolumeData;

// Screen size
uniform float width;
uniform float height;

// Ray‐march parameters
uniform int numSteps;
uniform float alphaScale;

out vec4 outColorr;
void main()
{
  // The usual screen UV:
  vec2 UV = gl_FragCoord.xy / vec2(width, height);

  // Current scene color behind the volume:
  vec4 sceneColor = texture2D(inRGBTex, UV);

  // Ray entry/exit in [0..1] from bounding box pass:
  vec3 entryPos = texture2D(inFrontPosTex, UV).xyz;
  vec3 exitPos  = texture2D(inBackPosTex,  UV).xyz;

  // If they are the same or alpha=0 from the box pass, skip:
  // (One quick check is length(entryPos - exitPos) < epsilon …)
  if (entryPos == exitPos) {
    outColorr = sceneColor;
    return;
  }

  // Convert [0..1] back to [-1..1] if that’s how the 3D volume is laid out.
  vec3 entryPoint = entryPos * 2.0 - 1.0;
  vec3 exitPoint  = exitPos  * 2.0 - 1.0;

  // Ray direction:
  vec3 dir = exitPoint - entryPoint;
  float rayLength = length(dir);
  vec3 stepDir = normalize(dir);

  // We want numSteps from entry to exit:
  float stepSize = rayLength / float(numSteps);
  vec3 step = stepDir * stepSize;

  // Accumulation variables:
  vec4 accumulatedColor = vec4(0.0);
  float accumulatedAlpha = 0.0;
  vec3 currentPosition = entryPoint;

  // March along the ray:
  for (int i = 0; i < numSteps; i++)
  {
    if (accumulatedAlpha >= 0.8)
      break;

    // We must map currentPosition from [-1..1] to [0..1] if our 3D texture
    // is sampled in [0..1] coordinates:
    vec3 volumeUV = (currentPosition * 0.5) + 0.5;

    // Sample intensity from the 3D texture:
    float intensity = texture3D(uVolumeData, volumeUV).r;

    // Transfer lookup:
    vec4 colorSample = texture2D(transferTex, vec2(intensity, 0.5));
    colorSample.a *= alphaScale;

    // Front‐to‐back compositing:
    accumulatedColor.rgb += (1.0 - accumulatedAlpha) * colorSample.rgb * colorSample.a;
    accumulatedAlpha      += (1.0 - accumulatedAlpha) * colorSample.a;
    accumulatedColor.a     = accumulatedAlpha;

    // Advance:
    currentPosition += step;
  }

  // Mix with the original scene:
  outColorr = accumulatedColor;
}
