#version 400
precision highp float;

in vec2 vNdc;

uniform vec3 positiveColor;
uniform vec3 negativeColor;

// 3D scalar volume (orbital / electron density).
uniform sampler3D uVolumeData;

// Opaque scene depth buffer ([0, 1]) for occlusion by atoms, bonds, and meshes.
uniform sampler2D uSceneDepthTex;
uniform int uHasSceneDepth;

// Inverse of (projection * modelView), mapping NDC [-1, 1]^3 to world space.
uniform mat4 uInvViewProj;

// Maps world space to the volume's unit cube [0, 1]^3 texture coordinates.
// Handles both orthogonal and skewed (triclinic) grids.
uniform mat4 uBoxInverse;
uniform float uBoxDiagonal;

// Ray-march parameters:
uniform int numSteps;   // reference steps across uBoxDiagonal (e.g. 150)
uniform float alphaScale; // overall alpha multiplier

out vec4 colorOut;

vec3 unproject(vec3 ndc)
{
  vec4 world = uInvViewProj * vec4(ndc, 1.0);
  return world.xyz / world.w;
}

// Slab intersection of ray (o + t * d) with the unit cube [0, 1]^3 in volume
// texture space. Because uBoxInverse is affine, t stays in world-space units.
vec2 rayBox(vec3 o, vec3 d)
{
  // Avoid 0 * inf = NaN when the view ray is parallel to a box face.
  vec3 safeD = vec3(abs(d.x) < 1e-8 ? (d.x < 0.0 ? -1e-8 : 1e-8) : d.x,
                    abs(d.y) < 1e-8 ? (d.y < 0.0 ? -1e-8 : 1e-8) : d.y,
                    abs(d.z) < 1e-8 ? (d.z < 0.0 ? -1e-8 : 1e-8) : d.z);
  vec3 invDir = 1.0 / safeD;
  vec3 t0 = -o * invDir;
  vec3 t1 = (vec3(1.0) - o) * invDir;
  vec3 tMin = min(t0, t1);
  vec3 tMax = max(t0, t1);
  return vec2(max(max(tMin.x, tMin.y), tMin.z),
              min(min(tMax.x, tMax.y), tMax.z));
}

void main()
{
  // Reconstruct the exact world-space ray for this pixel, starting on the near
  // clip plane. Works identically for perspective and orthographic cameras,
  // and never depends on rasterized box faces that can be clipped by near/far.
  vec3 nearWorld = unproject(vec3(vNdc, -1.0));
  vec3 farWorld = unproject(vec3(vNdc, 1.0));
  vec3 rayVec = farWorld - nearWorld;
  float raySpan = length(rayVec);
  if (!(raySpan > 0.0))
    discard;
  vec3 rayDir = rayVec / raySpan;
  vec3 rayOrigin = nearWorld;

  // Transform ray into volume texture space [0, 1]^3 once.
  vec3 boxOrigin = (uBoxInverse * vec4(rayOrigin, 1.0)).xyz;
  vec3 boxDir = (uBoxInverse * vec4(rayDir, 0.0)).xyz;

  vec2 tBox = rayBox(boxOrigin, boxDir);
  // Start at the near clip plane (t = 0) if the camera is inside the volume.
  float tEntry = max(tBox.x, 0.0);
  float tExit = tBox.y;

  // Stop at opaque geometry (atoms, bonds, opaque surfaces) so volume lobes
  // behind them are occluded while lobes in front still tint them.
  if (uHasSceneDepth != 0) {
    float sceneDepth = texture(uSceneDepthTex, vNdc * 0.5 + 0.5).x;
    if (sceneDepth < 1.0) {
      vec3 sceneWorld = unproject(vec3(vNdc, sceneDepth * 2.0 - 1.0));
      float tScene = dot(sceneWorld - rayOrigin, rayDir);
      tExit = min(tExit, tScene);
    }
  }

  float rayLength = tExit - tEntry;
  if (!(rayLength > 1e-4) || !(uBoxDiagonal > 0.0))
    discard;

  // Step at a consistent world-space spacing so truncating a ray at an atom
  // preserves physical optical depth instead of concentrating all samples into
  // a short segment.
  float refStep = uBoxDiagonal / float(numSteps);
  int steps = clamp(int(ceil(rayLength / refStep)), 1, numSteps);
  float actualStep = rayLength / float(steps);
  float stepWeight = actualStep / refStep;

  // Step directly in volume texture space (no per-step matrix multiply).
  vec3 volumeUV = boxOrigin + boxDir * (tEntry + 0.5 * actualStep);
  vec3 uvStep = boxDir * actualStep;

  vec3 accumulatedColor = vec3(0.0);
  float accumulatedAlpha = 0.0;

  for (int i = 0; i < steps; ++i) {
    if (accumulatedAlpha > 0.95)
      break;

    vec3 sampleUV = clamp(volumeUV, vec3(0.0), vec3(1.0));
    float psi = texture(uVolumeData, sampleUV).r;

    float amplitude = abs(psi);
    vec3 color = (psi >= 0.0) ? positiveColor : negativeColor;
    float alphaSample = clamp(amplitude * alphaScale * stepWeight, 0.0, 1.0);

    // Front-to-back premultiplied alpha compositing.
    float contrib = (1.0 - accumulatedAlpha) * alphaSample;
    accumulatedColor += contrib * color;
    accumulatedAlpha += contrib;

    volumeUV += uvStep;
  }

  if (accumulatedAlpha <= 0.0)
    discard;

  // Output premultiplied color and alpha for GL_ONE, GL_ONE_MINUS_SRC_ALPHA.
  colorOut = vec4(accumulatedColor, accumulatedAlpha);
}
