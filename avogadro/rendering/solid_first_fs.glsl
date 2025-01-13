#version 120

// Interpolated UV from the vertex shader
varying vec2 UV;

// Scene textures
uniform sampler2D inRGBTex;
uniform sampler2D inFrontDepthTex;
uniform sampler2D inBackDepthTex;
uniform sampler2D transferTex;
// The 3D volume data
uniform sampler3D uVolumeData;

// A 2D colormap texture (the “transfer function”)
// uniform sampler2D colormap;

// Some toggles from your pipeline (if needed)
uniform float inAoEnabled;
uniform float inAoStrength;
uniform float inEdStrength;

// Screen size (passed in from C++ code, if needed)
uniform float width;
uniform float height;

// Transfer-function range
uniform float transferMin;
uniform float transferMax;

// How many steps to take, etc.
uniform int   numSteps;       // e.g., 128
uniform float alphaScale;     // e.g., 0.1 or something similar

void main()
{
  // 1) Fetch the scene color
  vec4 sceneColor = texture2D(inRGBTex, UV);

  // 2) Fetch front and back depths 
  float frontDepth = texture2D(inFrontDepthTex, UV).r;
  float backDepth  = texture2D(inBackDepthTex,  UV).r;

  // Basic sanity checks: if the box is clipped or if front/back are invalid
  if (frontDepth >= 1.0 || backDepth >= 1.0 || backDepth <= frontDepth) {
    gl_FragColor = sceneColor;
    return;
  }

  // 3) Compute the total “thickness” in normalized [0..1] Z
  float thickness = (backDepth - frontDepth);

  // Step size for the raymarch
  float stepSize = thickness / float(numSteps);

  // 4) Accumulate color over the ray
  vec4 accumulatedColor = vec4(0.0);

  // Raymarch from frontDepth to backDepth
  for (int i = 0; i < 256; i++) {
    // Parametric Z coordinate in [frontDepth..backDepth]
    float z = frontDepth + (float(i) + 0.5) * stepSize;

    // UVW in volume texture: XY from screen, Z in [0..1] (assuming the volume
    // is also in [0..1] for that axis). You may need to invert or shift if
    // your volume is mapped differently.
    vec3 uvw = vec3(UV, z);

    // Sample the raw density or intensity from the volume
    float rawVal = texture3D(uVolumeData, uvw).r;

    // Map that raw value to [0..1] for a colormap lookup
    float cval = (rawVal - transferMin) / (transferMax - transferMin);
    cval = clamp(cval, 0.0, 1.0);

    // Fetch a color from the colormap — assume 1D colormap along X,
    // picking the center of Y=0.5 if it’s just a 1D gradient stored in a 2D texture
    vec4 sampleColor = texture2D(transferTex, vec2(cval, 0.9));

    // Scale alpha if you want the volume to be more or less transparent
    // (like your ALPHA_SCALE from the original code)
    sampleColor.a *= alphaScale;

    // Standard “over” alpha compositing:
    float remainingAlpha = 1.0 - accumulatedColor.a;
    accumulatedColor.rgb += sampleColor.rgb * sampleColor.a * remainingAlpha;
    accumulatedColor.a   += sampleColor.a * remainingAlpha;

    // Optional early-out if almost fully opaque:
    if (accumulatedColor.a >= 0.95) 
        break;
  }

  // 5) (Optional) If you have toggles for AO or edges:
  //    For demonstration, we do something simple:
  if (inAoEnabled < 0.5) {
    // Example: make the volume darker if AO is disabled
    accumulatedColor.rgb *= 0.5;
  }
  // Scale by AO strength (could be done differently)
  accumulatedColor.rgb *= inAoStrength;

  // 6) Composite final volume color over the original scene
  //    Similar to “1 - alpha” logic you had:
  float oneMinusA = 1.0 - accumulatedColor.a;
  vec3 finalRGB   = accumulatedColor.rgb + oneMinusA * sceneColor.rgb;
  float finalA    = sceneColor.a + oneMinusA * accumulatedColor.a; //This was backwards

  // Write out final pixel color
  gl_FragColor = vec4(finalRGB, finalA);
}
