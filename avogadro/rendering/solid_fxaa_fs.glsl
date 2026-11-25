//////////////////////////////////////////////////////////////////////
//
// Optional FXAA stage for the solid pipeline
//
// A luma-based edge filter after Timothy Lottes' FXAA 3.11, at the quality of
// its preset 12 (five taps along the edge, reaching about 20 pixels). It reads
// the composited image, so the ink outlines are smoothed along with the
// silhouettes, and writes it to the framebuffer the pipeline presents to.
//
// The edge directions use the original's naming (N is toward -y, S toward
// +y); only the symmetry matters, not which way the image is flipped.
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

// The composited image, premultiplied, with the background filled in, and
// linear filtering: the filter's half-pixel taps rely on it.
uniform sampler2D inRGBTex;
// Depth of the solid geometry, written back for the passes that follow.
uniform sampler2D inDepthTex;
// Rendering surface dimensions, in pixels
uniform float width, height;
// 1.0 when the background is not opaque, so that coverage counts as contrast.
uniform float inAlphaWeight;

// A contrast below the larger of these is not an edge: an absolute floor for
// dark areas and a fraction of the local maximum luma.
const float EDGE_THRESHOLD = 0.125;
const float EDGE_THRESHOLD_MIN = 0.0625;
// How much of an isolated bright or dark pixel is blended away.
const float SUBPIX = 0.75;

// Steps along the edge after the first tap, in pixels (preset 12).
const int SEARCH_STEPS = 4;
const float SEARCH_STEP[4] = float[](1.5, 2.0, 4.0, 12.0);

// The colour is premultiplied. Geometry as dark as a transparent background
// has no colour contrast with it, so coverage is added when there is one.
float luma(vec4 c)
{
  return dot(c.rgb, vec3(0.299, 0.587, 0.114)) + inAlphaWeight * c.a;
}

vec4 fetch(vec2 p)
{
  return textureLod(inRGBTex, p, 0.0);
}

float lumaAt(vec2 p)
{
  return luma(fetch(p));
}

// A macro, since the offset has to be a compile-time constant.
#define lumaOff(p, o) luma(textureLodOffset(inRGBTex, p, 0.0, o))

void main()
{
  vec2 rcp = vec2(1.0 / width, 1.0 / height);
  float depth = texelFetch(inDepthTex, ivec2(UV * vec2(width, height)), 0).x;

  vec4 centre = fetch(UV);
  float lumaM = luma(centre);
  float lumaS = lumaOff(UV, ivec2(0, 1));
  float lumaE = lumaOff(UV, ivec2(1, 0));
  float lumaN = lumaOff(UV, ivec2(0, -1));
  float lumaW = lumaOff(UV, ivec2(-1, 0));

  float rangeMax = max(max(lumaS, lumaN), max(lumaW, max(lumaE, lumaM)));
  float rangeMin = min(min(lumaS, lumaN), min(lumaW, min(lumaE, lumaM)));
  float range = rangeMax - rangeMin;

  // Not an edge. Background pixels are left as the framebuffer already has
  // them, so a frame that is mostly background is cheap to write.
  if (range < max(EDGE_THRESHOLD_MIN, rangeMax * EDGE_THRESHOLD)) {
    if (depth >= 1.0)
      discard;
    outColor = centre;
    gl_FragDepth = depth;
    return;
  }

  float lumaNW = lumaOff(UV, ivec2(-1, -1));
  float lumaSE = lumaOff(UV, ivec2(1, 1));
  float lumaNE = lumaOff(UV, ivec2(1, -1));
  float lumaSW = lumaOff(UV, ivec2(-1, 1));

  float lumaNS = lumaN + lumaS;
  float lumaWE = lumaW + lumaE;
  float subpixNSWE = lumaNS + lumaWE;
  float edgeHorz1 = -2.0 * lumaM + lumaNS;
  float edgeVert1 = -2.0 * lumaM + lumaWE;

  float lumaNESE = lumaNE + lumaSE;
  float lumaNWNE = lumaNW + lumaNE;
  float edgeHorz2 = -2.0 * lumaE + lumaNESE;
  float edgeVert2 = -2.0 * lumaN + lumaNWNE;

  float lumaNWSW = lumaNW + lumaSW;
  float lumaSWSE = lumaSW + lumaSE;
  float edgeHorz4 = abs(edgeHorz1) * 2.0 + abs(edgeHorz2);
  float edgeVert4 = abs(edgeVert1) * 2.0 + abs(edgeVert2);
  float edgeHorz3 = -2.0 * lumaW + lumaNWSW;
  float edgeVert3 = -2.0 * lumaS + lumaSWSE;
  float edgeHorz = abs(edgeHorz3) + edgeHorz4;
  float edgeVert = abs(edgeVert3) + edgeVert4;

  float subpixNWSWNESE = lumaNWSW + lumaNESE;
  bool horzSpan = edgeHorz >= edgeVert;
  float lengthSign = horzSpan ? rcp.y : rcp.x;
  if (!horzSpan) {
    lumaN = lumaW;
    lumaS = lumaE;
  }
  float subpixA = subpixNSWE * 2.0 + subpixNWSWNESE;

  // Which side of the pixel the steeper gradient is on.
  float gradientN = lumaN - lumaM;
  float gradientS = lumaS - lumaM;
  float lumaNN = lumaN + lumaM;
  float lumaSS = lumaS + lumaM;
  bool pairN = abs(gradientN) >= abs(gradientS);
  float gradient = max(abs(gradientN), abs(gradientS));
  if (pairN)
    lengthSign = -lengthSign;
  float subpixB = subpixA * (1.0 / 12.0) - lumaM;
  float subpixC = clamp(abs(subpixB) / max(range, 1e-6), 0.0, 1.0);
  float subpixD = -2.0 * subpixC + 3.0;
  float subpixF = subpixD * subpixC * subpixC;
  float subpixG = subpixF * subpixF;

  // Start half a pixel across the edge, so each tap averages the two pixels
  // either side of it, and search both ways along it for its ends.
  vec2 posB = UV;
  vec2 offNP = horzSpan ? vec2(rcp.x, 0.0) : vec2(0.0, rcp.y);
  if (horzSpan)
    posB.y += lengthSign * 0.5;
  else
    posB.x += lengthSign * 0.5;

  vec2 posN = posB - offNP;
  vec2 posP = posB + offNP;
  if (!pairN)
    lumaNN = lumaSS;
  float gradientScaled = gradient * 0.25;
  float lumaMM = lumaM - lumaNN * 0.5;
  bool lumaMLTZero = lumaMM < 0.0;

  float lumaEndN = lumaAt(posN) - lumaNN * 0.5;
  float lumaEndP = lumaAt(posP) - lumaNN * 0.5;
  bool doneN = abs(lumaEndN) >= gradientScaled;
  bool doneP = abs(lumaEndP) >= gradientScaled;
  for (int i = 0; i < SEARCH_STEPS; i++) {
    if (doneN && doneP)
      break;
    if (!doneN)
      posN -= offNP * SEARCH_STEP[i];
    if (!doneP)
      posP += offNP * SEARCH_STEP[i];
    if (!doneN)
      lumaEndN = lumaAt(posN) - lumaNN * 0.5;
    if (!doneP)
      lumaEndP = lumaAt(posP) - lumaNN * 0.5;
    doneN = abs(lumaEndN) >= gradientScaled;
    doneP = abs(lumaEndP) >= gradientScaled;
  }

  float dstN = horzSpan ? UV.x - posN.x : UV.y - posN.y;
  float dstP = horzSpan ? posP.x - UV.x : posP.y - UV.y;
  bool directionN = dstN < dstP;
  float lumaEndG = directionN ? lumaEndN : lumaEndP;
  // The nearer end of the edge must change the way that would pull this pixel
  // toward the other side; otherwise the pixel is already on the right side.
  bool goodSpan = (lumaEndG < 0.0) != lumaMLTZero;
  float spanLength = dstP + dstN;
  float dst = directionN ? dstN : dstP;
  float pixelOffset = 0.5 - dst / max(spanLength, 1e-6);
  float pixelOffsetGood = goodSpan ? pixelOffset : 0.0;
  float pixelOffsetSubpix = max(pixelOffsetGood, subpixG * SUBPIX);

  vec2 posM = UV;
  if (horzSpan)
    posM.y += pixelOffsetSubpix * lengthSign;
  else
    posM.x += pixelOffsetSubpix * lengthSign;

  outColor = fetch(posM);
  gl_FragDepth = depth;
}
