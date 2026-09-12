//////////////////////////////////////////////////////////////////////
//
// First-stage screen-space fragment shader for the solid pipeline
//
// It offers ambient occlusion and edge detection capabilities.
//
//////////////////////////////////////////////////////////////////////

#version 400
precision highp float;

//
// Input
//

// texture coordinates
in vec2 UV;

out vec4 outColor;

//
// Uniforms
//

// RGB rendered texture
uniform sampler2D inRGBTex;

// RGB color for applying fog
uniform float fogR;
uniform float fogG;
uniform float fogB;
uniform float offset;

// Depth rendered texture
uniform sampler2D inDepthTex;
// 1.0 if enabled, 0.0 if disabled
uniform float inAoEnabled;
// 0.0 if disabled
uniform float inFogStrength;
// 1.0 if enabled, 0.0 if disabled
uniform float inEdStrength;
// amount of offset when zoom-in or zoom-out.
uniform float uoffset;
// Dof strength
uniform float inDofStrength;
// Dof position
uniform float inDofPosition;
// position for other molecules.
uniform float inFogPosition;
// Rendering surface dimensions, in pixels
uniform float width, height;
// Ambient occlusion term from the AO stage, still carrying its sampling
// pattern; blurredAo() below is what removes it.
uniform sampler2D inAoTex;
// Projection matrix, used to turn window depth back into scene units and to
// size the blur's surface test.
uniform mat4 inProjection;

vec3 getNormalAt(vec2 normalUV)
{
  float xpos = texture(inDepthTex, normalUV + vec2(1.0 / width, 0.0)).x;
  float xneg = texture(inDepthTex, normalUV - vec2(1.0 / width, 0.0)).x;
  float ypos = texture(inDepthTex, normalUV + vec2(0.0, 1.0 / height)).x;
  float yneg = texture(inDepthTex, normalUV - vec2(0.0, 1.0 / height)).x;
  float xdelta = xpos - xneg;
  float ydelta = ypos - yneg;
  vec3 r = vec3(xdelta, ydelta, 1.0 / width + 1.0 / height);
  return normalize(r);
}

// Window depth to distance from the camera, in scene units. Derived from the
// projection so it holds for both the perspective and the orthographic camera,
// rather than assuming fixed near and far planes.
float linearDepth(float depth)
{
  float ndc = depth * 2.0 - 1.0;
  float viewZ = (inProjection[3][2] - ndc * inProjection[3][3]) /
                (ndc * inProjection[2][3] - inProjection[2][2]);
  return -viewZ;
}

// Must match AO_TILE in solid_ao_fs.glsl. That stage uses a different kernel
// rotation for each pixel of a tile this size, and averaging a block of the
// same size is exactly what cancels the pattern.
const int AO_BLUR_TILE = 4;

// The steepest surface, in scene units of depth per pixel, still treated as one
// surface by the blur. Anything steeper is taken to be a different surface.
const float AO_BLUR_SLOPE_LIMIT = 16.0;

// Average the ambient occlusion term over the block of pixels that the AO stage
// rotates its kernel across. Every rotation appears exactly once in the block,
// so the sampling pattern averages out instead of showing as a dither. Any
// AO_BLUR_TILE consecutive offsets cover the tile, whatever the alignment.
// Taps sitting on a different surface are dropped, so occlusion does not bleed
// across a silhouette into whatever lies behind it.
float blurredAo(vec2 texCoord)
{
  float centerZ = linearDepth(texture(inDepthTex, texCoord).x);

  // Size the surface test by how much scene distance one pixel covers here,
  // rather than by a fixed number of Angstroms. A fixed distance is only right
  // at one zoom level: it rejects every tap on a steep surface when zoomed out,
  // which brings the dither back in exactly the places the blur exists for.
  // inProjection[2][3] and [3][3] give the perspective divide, which is the
  // view distance for a perspective camera and 1 for an orthographic one.
  float wClip = inProjection[2][3] * -centerZ + inProjection[3][3];
  float pixelSize = 2.0 * wClip / (height * inProjection[1][1]);
  float tolerance = AO_BLUR_SLOPE_LIMIT * pixelSize;

  // The centre tap always belongs, so seed with it and skip it in the loop.
  float total = texture(inAoTex, texCoord).x;
  float weight = 1.0;
  for (int y = -1; y <= AO_BLUR_TILE - 2; y++) {
    for (int x = -1; x <= AO_BLUR_TILE - 2; x++) {
      if (x == 0 && y == 0)
        continue;
      vec2 tapUV = texCoord + vec2(float(x) / width, float(y) / height);
      if (abs(linearDepth(texture(inDepthTex, tapUV).x) - centerZ) < tolerance) {
        total += texture(inAoTex, tapUV).x;
        weight += 1.0;
      }
    }
  }
  return total / weight;
}

float lerp(float a, float b, float f)
{
    return a + f * (b - a);
}

float rand(vec2 co) {
    return fract(sin(dot(co.xy, vec2(12.9898, 78.233))) * 43758.5453);
}

// Legacy depth linearization for the depth-of-field path only. Its near and far
// are hardcoded and do not match the actual camera; calcBlur's focus distance
// and SolidPipeline::adjustOffset are both curve-fitted against that error, so
// the three only make sense together. Use linearDepth() for anything new.
float depthToZ(float depth) {
    float eyeZ = ((height * 0.57735) / 2.0);
    float near = 2.0;
    float far = 8000.0;
    float depthNormalized = 2.0 * depth - 1.0;
    return 2.0 * near * far / (far + near - depthNormalized * (far - near));
}

float calcBlur(float z, float pixelScale) {
    return clamp(abs(z - 39.0), 0.0, 0.5 * pixelScale);
}

vec4 applyBlur(vec2 texCoord) {
    float pixelScale = max(width, height);
    float origZ = depthToZ(texture(inDepthTex, texCoord).x);
    float blurAmt = calcBlur(origZ, pixelScale);
    // Skip blurring if the original depth is less than the threshold
    if (origZ < uoffset * inDofPosition) {
        return texture(inRGBTex, texCoord);
    }
    float total = 1.0;
    vec4 color = texture(inRGBTex, texCoord);
    for (int i = 0; i < 32; i++) {
        float t = (float(i) / float(64));
        float angle = (t * 4.0) * 6.28319;
        float radius = (t * 2. - 1.);
        angle += 1.0 * rand(gl_FragCoord.xy);
        vec2 offset = (vec2(cos(angle), sin(angle)) * radius * 0.05 * inDofStrength) / pixelScale;
        float z = depthToZ(texture(inDepthTex, texCoord + offset).x);
        float sampleBlur = calcBlur(z, pixelScale);
        float weight = 1.0 - smoothstep(0.0, 1.0, abs(z - origZ) / blurAmt);
        vec4 texSample = texture(inRGBTex, texCoord+offset);
        color += weight * texSample;
        total += weight;
}
return color / total;
}

vec4 applyFog(vec2 texCoord) {
    vec4 finalColor = mix(
            texture(inRGBTex, texCoord),
            vec4(vec3(fogR, fogG, fogB), 1.),
            pow(texture(inDepthTex, texCoord.xy).r, uoffset * inFogPosition / 10.0)
        ) + inFogStrength / 100.0;
    return finalColor;
}

float computeEdgeLuminosity(vec3 normal)
{
    return max(0.0, pow(normal.z - 0.1, 1.0 / 3.0));
}

void main() {
    float luminosity = 1.0;
    vec4 color = texture(inRGBTex, UV);
    vec4 finalColor = color; // Initialize finalColor with base color

    // Compute luminosity based on Ambient Occlusion (AO) and Edge Detection
    if (inAoEnabled != 0.0) {
        luminosity *= max(1.2 * (1.0 - inAoEnabled), blurredAo(UV));
    }
    if (inEdStrength != 0.0) {
        luminosity *= max(1.0 - inEdStrength, computeEdgeLuminosity(getNormalAt(UV)));
    }

    // Compute foggedColor if Fog is enabled
    vec4 foggedColor = color;
    if (inFogStrength != 0.0) {
        foggedColor = applyFog(UV);
    }

    // Compute blurredColor if DOF is enabled
    vec4 blurredColor = color;
    if (inDofStrength != 0.0) {
        blurredColor = applyBlur(UV);
    }

    // Determine finalColor based on enabled effects
    if (inAoEnabled != 0.0 || inEdStrength != 0.0 || inDofStrength != 0.0) {
        if (inFogStrength != 0.0 && inDofStrength != 0.0) {
            // Both Fog and DOF are enabled
            vec4 mixedColor = mix(foggedColor, blurredColor, 0.5);
            finalColor = vec4(mixedColor.rgb * luminosity, mixedColor.a);
        } else if (inFogStrength != 0.0) {
            // Only Fog is enabled with ao/edge-detection
            finalColor = vec4(foggedColor.rgb * luminosity, foggedColor.a);
        } else if (inDofStrength != 0.0) {
            // Only DOF is enabled with/without ao/edge
            finalColor = vec4(blurredColor.rgb * luminosity, blurredColor.a);
        } else {
            // Only AO and/or Edge Detection are enabled
            finalColor = vec4(color.rgb * luminosity, color.a);
        }
    } else {
        // Neither AO, DOF, nor Edge Detection is enabled
        if (inFogStrength != 0.0) {
            // Only Fog is enabled
            finalColor = foggedColor;
        } else {
            // No effects are enabled
            finalColor = color;
        }
    }

    // Set the final fragment color
    outColor = finalColor;
    gl_FragDepth = texture(inDepthTex, UV).x;
}
