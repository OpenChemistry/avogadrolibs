//////////////////////////////////////////////////////////////////////
//
// First-stage screen-space fragment shader for the solid pipeline
//
// It offers ambient occlusion, edge detection, depth of field and fog (depth
// cue). They are applied in that order, blur first and fog last, so that the
// fog is the final word on the color: the depth of field only moves color
// around, and the ambient occlusion and outline darken the surface they sit on
// before the fog fades it.
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

// The color the fog fades toward: the background the frame was cleared to,
// including its alpha, so over a transparent background the fog fades the
// molecule to transparent.
uniform float fogR;
uniform float fogG;
uniform float fogB;
uniform float fogA;

// Depth rendered texture
uniform sampler2D inDepthTex;
// 1.0 if enabled, 0.0 if disabled
uniform float inAoEnabled;
// Edge outline: 0.0 when off. Up to 1.0 it fades the outline in; above 1.0 it
// is the outline's half-width in pixels.
uniform float inEdStrength;
// 1.0 evaluates the edge term at four sub-pixel offsets and averages them;
// 0.0 takes a single tap on the pixel centre.
uniform float inEdgeSupersample;
// Fog: the fraction of the fog color mixed in at the back of the scene's depth
// span (0.0 is off), and where the linear ramp starts, in scene radii from the
// scene center. See fogSettings() in solideffects_p.h.
uniform float inFogAmount;
uniform float inFogStartRadii;
// Depth of field: the circle of confusion radius in logical pixels one scene
// radius from the focus (0.0 is off), its maximum, and the focus depth in
// scene radii from the scene center. See depthOfFieldSettings().
uniform float inDofBlur;
uniform float inDofMaxBlur;
uniform float inDofFocusRadii;
// Rendering surface dimensions, in pixels
uniform float width, height;
// Output of the AO and blur stages, at half the resolution of the frame: the
// ambient occlusion term in x and the distance to the surface in scene units in
// y. upsampledAo() below brings it to the frame's resolution.
uniform sampler2D inAoTex;
// The camera matrices and the scene bounds come from the CameraBuffer block
// that the shader library declares: the upsampling uses the projection to size
// its surface test, and depth cue and depth of field use the inverse projection
// to turn window depth into a distance, and the model-view matrix and bounds to
// find the scene's center and radius.

// Screen-space normal from the depth gradient, sampled `radius` pixels either
// side of the fragment. The radius is what sets the outline's width: a pixel
// registers as an edge when its two taps straddle a depth jump, so the band
// that does is about 2 * radius wide.
//
// The z term scales with the radius as well. Across a smoothly curved surface
// the depth difference grows with the radius too, so the two scale together and
// the normal comes out the same: widening thickens the silhouette without also
// darkening the interiors. Drop that factor and a wide radius shades the whole
// molecule instead of outlining it.
vec3 getNormalAt(vec2 normalUV, float radius)
{
  float xpos = texture(inDepthTex, normalUV + vec2(radius / width, 0.0)).x;
  float xneg = texture(inDepthTex, normalUV - vec2(radius / width, 0.0)).x;
  float ypos = texture(inDepthTex, normalUV + vec2(0.0, radius / height)).x;
  float yneg = texture(inDepthTex, normalUV - vec2(0.0, radius / height)).x;
  float xdelta = xpos - xneg;
  float ydelta = ypos - yneg;
  vec3 r = vec3(xdelta, ydelta, radius * (1.0 / width + 1.0 / height));
  return normalize(r);
}

// Distances at or above this are background; just below BACKGROUND_DISTANCE in
// solid_ao_fs.glsl, the sentinel written there.
const float BACKGROUND_THRESHOLD = 65000.0;

// The steepest surface, in scene units of depth per AO texel, still treated as
// one surface. Must match AO_BLUR_SLOPE_LIMIT in solid_aoblur_fs.glsl.
const float AO_BLUR_SLOPE_LIMIT = 16.0;

// Smallest denominator: keeps a degenerate projection or scene from dividing
// by zero.
const float DEPTH_EPSILON = 1e-6;

// Window depth to the distance in front of the camera, in scene units. The
// inverse projection undoes the perspective divide for either projection, so
// this is exact for the orthographic camera as well; both ends of the depth
// range need no assumption about the near and far planes.
float viewDistance(vec2 texCoord, float depth)
{
    vec4 view = inverseProjection *
                vec4(texCoord * 2.0 - 1.0, depth * 2.0 - 1.0, 1.0);
    float w = abs(view.w) > DEPTH_EPSILON ? view.w : DEPTH_EPSILON;
    return -view.z / w;
}

// The occlusion term at a pixel, upsampled from the half-resolution buffer the
// AO and blur stages produce. The four texels nearest the pixel are weighted
// bilinearly, but a texel whose surface is further from this pixel's than the
// tolerance is left out, so the term does not smear across a silhouette: no
// dark halo on the nearer surface from the farther one, and none spilled onto
// the background. If every one of the four is on another surface, as at a
// one-pixel feature, the term of the nearest of them in depth stands in. Only
// when there is no foreground texel at all is there no occlusion.
//
// Both the term and the distance the test needs come from the same texel, so
// each tap is a single fetch.
float upsampledAo(vec2 texCoord, float depth)
{
  ivec2 aoSize = textureSize(inAoTex, 0);
  ivec2 last = aoSize - ivec2(1);
  // Texel centers sit on the corners shared by the 2x2 blocks of pixels they
  // cover, so the pixel's center is a quarter of a texel off from the nearest
  // texel centers, on one side or the other.
  vec2 position = texCoord * vec2(textureSize(inDepthTex, 0)) * 0.5 - 0.5;
  vec2 base = floor(position);
  vec2 frac = position - base;
  ivec2 corner = ivec2(base);

  // The pixel's distance from the camera, and how far apart two texels of the
  // same surface can be in it: the slope limit times the scene length of one
  // texel here. See texelSize() in solid_aoblur_fs.glsl.
  float z = viewDistance(texCoord, depth);
  float wClip = projection[2][3] * -z + projection[3][3];
  float scale = abs(float(aoSize.y) * projection[1][1]);
  float tolerance = AO_BLUR_SLOPE_LIMIT * 2.0 * abs(wClip) /
                    max(scale, DEPTH_EPSILON);

  float total = 0.0;
  float weight = 0.0;
  float nearestTerm = 1.0;
  float nearestGap = 3.4e38;
  for (int i = 0; i < 4; i++) {
    ivec2 offset = ivec2(i & 1, i >> 1);
    ivec2 texel = clamp(corner + offset, ivec2(0), last);
    vec2 tap = texelFetch(inAoTex, texel, 0).xy;
    if (tap.y >= BACKGROUND_THRESHOLD)
      continue;
    float gap = abs(tap.y - z);
    float bilinear = (offset.x == 0 ? 1.0 - frac.x : frac.x) *
                     (offset.y == 0 ? 1.0 - frac.y : frac.y);
    if (gap < tolerance) {
      total += bilinear * tap.x;
      weight += bilinear;
    }
    if (gap < nearestGap) {
      nearestGap = gap;
      nearestTerm = tap.x;
    }
  }
  // No texel on this pixel's surface: take the closest one in depth.
  return weight > DEPTH_EPSILON ? total / weight : nearestTerm;
}

// The scene's center, as a distance in front of the camera.
float sceneCenterDistance()
{
    return -(modelView * vec4(sceneBounds.xyz, 1.0)).z;
}

// Linear fog: nothing in front of the ramp's start, rising to inFogAmount at
// the back of the scene's depth span [center - radius, center + radius]. The
// start can be moved past the back, so the ramp keeps a minimum length.
float fogFactor(float viewDist, float centerDistance, float sceneRadius)
{
    float start = centerDistance + inFogStartRadii * sceneRadius;
    float end = centerDistance + sceneRadius;
    float rampLength = max(end - start, 0.05 * sceneRadius);
    return inFogAmount * clamp((viewDist - start) / rampLength, 0.0, 1.0);
}

// The depth of field's circle of confusion radius at a distance from the
// camera, in device pixels.
float circleOfConfusion(float viewDist, float centerDistance, float sceneRadius)
{
    float focus = centerDistance + inDofFocusRadii * sceneRadius;
    float blur = inDofBlur * abs(viewDist - focus) / sceneRadius;
    return min(blur, inDofMaxBlur) * cameraParams.x;
}

// 32 taps on a golden-angle spiral (Vogel disk) of the unit disk. A fixed
// pattern: no per-pixel or per-frame noise, so a still image is still.
const int DOF_TAPS = 32;
const vec2 DOF_KERNEL[DOF_TAPS] = vec2[](
    vec2(0.1250, 0.0000), vec2(-0.1596, 0.1462),
    vec2(0.0244, -0.2784), vec2(0.2012, 0.2625),
    vec2(-0.3693, -0.0653), vec2(0.3498, -0.2225),
    vec2(-0.1170, 0.4352), vec2(-0.2231, -0.4296),
    vec2(0.4841, 0.1768), vec2(-0.5036, 0.2079),
    vec2(0.2428, -0.5188), vec2(0.1794, 0.5720),
    vec2(-0.5408, -0.3134), vec2(0.6344, -0.1395),
    vec2(-0.3871, 0.5507), vec2(-0.0894, -0.6902),
    vec2(0.5491, 0.4628), vec2(-0.7389, 0.0306),
    vec2(0.5390, -0.5363), vec2(-0.0361, 0.7798),
    vec2(-0.5128, -0.6145), vec2(0.8124, 0.1093),
    vec2(-0.6883, 0.4789), vec2(0.1881, -0.8361),
    vec2(0.4350, 0.7592), vec2(-0.8504, -0.2713),
    vec2(0.8261, -0.3817), vec2(-0.3579, 0.8552),
    vec2(-0.3194, -0.8880), vec2(0.8499, 0.4467),
    vec2(-0.9440, 0.2488), vec2(0.5366, -0.8345));

// Depth of field by gathering: average the taps within the pixel's circle of
// confusion, each weighted by whether its own circle reaches back to this
// pixel. A sharp neighbour then does not smear over a blurred pixel, and the
// background (no geometry) contributes nothing. Pixels in focus are returned
// as they are.
vec4 applyBlur(vec2 texCoord, float viewDist, float centerDistance,
               float sceneRadius)
{
    ivec2 size = textureSize(inDepthTex, 0);
    ivec2 last = size - ivec2(1);
    ivec2 pixel = clamp(ivec2(texCoord * vec2(size)), ivec2(0), last);
    vec4 color = texelFetch(inRGBTex, pixel, 0);
    float radius = circleOfConfusion(viewDist, centerDistance, sceneRadius);
    // Under half a pixel the taps all land on this pixel.
    if (radius < 0.5)
        return color;
    float total = 1.0;
    for (int i = 0; i < DOF_TAPS; i++) {
        vec2 offset = DOF_KERNEL[i] * radius;
        ivec2 tap = clamp(pixel + ivec2(floor(offset + 0.5)), ivec2(0), last);
        float tapDepth = texelFetch(inDepthTex, tap, 0).x;
        if (tapDepth >= 1.0)
            continue;
        vec2 tapUV = (vec2(tap) + 0.5) / vec2(size);
        float tapRadius = circleOfConfusion(viewDistance(tapUV, tapDepth),
                                            centerDistance, sceneRadius);
        // Soft over one pixel, so the weight does not flicker at the edge.
        float weight = clamp(tapRadius - length(offset) + 1.0, 0.0, 1.0);
        color += weight * texelFetch(inRGBTex, tap, 0);
        total += weight;
    }
    return color / total;
}

float computeEdgeLuminosity(vec3 normal)
{
    return max(0.0, pow(normal.z - 0.1, 1.0 / 3.0));
}

// Anti-aliased edge term. The test above is binary per pixel: at a silhouette
// the depth jump swamps the z term, so the normal's z is about 0 and the cube
// root in computeEdgeLuminosity() comes out as a hard 0 or 1. That makes the
// outline stair-step on 1x screens. The taps normally land on texel centres, so
// this evaluates the term at four rotated-grid offsets within the pixel and
// averages them. The depth texture is linearly filtered, so each sub-pixel tap
// interpolates, and a pixel the silhouette only partly covers lands on one of
// five levels (0, 1/4 ... 1) rather than flipping between 0 and 1. The radius
// still sets the outline's width, and the offsets are under a pixel, so the
// outline does not get any wider.
const vec2 EDGE_SS[4] = vec2[](vec2(-0.125, -0.375), vec2(0.375, -0.125),
                               vec2(0.125, 0.375), vec2(-0.375, 0.125));

float edgeLuminosity(vec2 uv, float radius)
{
    float sum = 0.0;
    for (int i = 0; i < 4; i++) {
        sum += computeEdgeLuminosity(
            getNormalAt(uv + EDGE_SS[i] / vec2(width, height), radius));
    }
    return 0.25 * sum;
}

void main() {
    float depth = texture(inDepthTex, UV).x;
    // Background pixels (depth == 1.0) would fail the GL_LESS depth test
    // anyway; discarding upfront skips AO blur, edge detection, fog and DoF.
    if (depth >= 1.0)
        discard;

    float luminosity = 1.0;
    vec4 color = texture(inRGBTex, UV);

    // Luminosity from Ambient Occlusion (AO) and Edge Detection
    if (inAoEnabled != 0.0) {
        luminosity *= max(1.2 * (1.0 - inAoEnabled), upsampledAo(UV, depth));
    }
    if (inEdStrength != 0.0) {
        // Below 1.0 the outline fades in at its original one-pixel width, which
        // is what the checkbox used to switch between. From 1.0 up it is fully
        // dark and the value becomes its half-width in pixels, so 2.5 draws a
        // markedly bolder line than 1.0 without changing its colour.
        float edgeFade = min(inEdStrength, 1.0);
        float edgeRadius = max(inEdStrength, 1.0);
        float edge = (inEdgeSupersample != 0.0)
                       ? edgeLuminosity(UV, edgeRadius)
                       : computeEdgeLuminosity(getNormalAt(UV, edgeRadius));
        luminosity *= max(1.0 - edgeFade, edge);
    }

    // Depth of field first, since it only redistributes the surface color; the
    // luminosity of the pixel it lands on then applies; fog comes last.
    bool useFog = inFogAmount > 0.0;
    bool useDof = inDofBlur > 0.0;
    float sceneRadius = sceneBounds.w;
    // Without a scene extent there is nothing to measure the depths against.
    if (sceneRadius <= DEPTH_EPSILON) {
        useFog = false;
        useDof = false;
    }
    float viewDist = 0.0;
    float centerDistance = 0.0;
    if (useFog || useDof) {
        viewDist = viewDistance(UV, depth);
        centerDistance = sceneCenterDistance();
    }
    if (useDof)
        color = applyBlur(UV, viewDist, centerDistance, sceneRadius);

    vec4 finalColor = vec4(color.rgb * luminosity, color.a);

    if (useFog) {
        float fog = fogFactor(viewDist, centerDistance, sceneRadius);
        finalColor = mix(finalColor, vec4(fogR, fogG, fogB, fogA), fog);
    }

    // Set the final fragment color
    outColor = finalColor;
    gl_FragDepth = depth;
}
