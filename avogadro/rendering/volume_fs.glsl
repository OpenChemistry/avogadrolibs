#version 400
precision highp float;

// The ray entry/exit attachments from bounding-box passes:
uniform sampler2D inFrontPosTex;
uniform sampler2D inBackPosTex;
uniform vec3 positiveColor;
uniform vec3 negativeColor;

// Our 3D volume (wavefunction):
uniform sampler3D uVolumeData;

// The box in world space: uBoxMatrix maps the unit cube [0,1]^3 (the texture
// coordinates of the volume) to the world, uBoxInverse maps back. The box is
// a parallelepiped for a skewed grid. uBoxDiagonal is its longest diagonal.
uniform mat4 uBoxMatrix;
uniform mat4 uBoxInverse;
uniform float uBoxDiagonal;

// Camera position for ray computation when back faces are clipped
uniform vec3 uCameraPos;

// View direction for orthographic projection (all rays parallel)
uniform vec3 uViewDir;

// Projection type: 0 = perspective, 1 = orthographic
uniform int uProjectionType;

// Screen size:
uniform float width;
uniform float height;

// Ray-march parameters:
uniform int   numSteps;    // e.g. 256
uniform float alphaScale;  // overall alpha multiplier

out vec4 colorOut;

// Ray-box intersection with the unit cube in volume (texture) space. An
// affine map keeps the ray parameter t, so the ray is transformed into that
// space and the t values are the world-space ones.

// Returns (entry, exit) t values for ray origin + t * dir
vec2 rayBox(vec3 origin, vec3 dir)
{
    vec3 o = (uBoxInverse * vec4(origin, 1.0)).xyz;
    vec3 d = (uBoxInverse * vec4(dir, 0.0)).xyz;
    vec3 invDir = 1.0 / d;
    vec3 t1 = (vec3(0.0) - o) * invDir;
    vec3 t2 = (vec3(1.0) - o) * invDir;
    vec3 tMin = min(t1, t2);
    vec3 tMax = max(t1, t2);
    return vec2(max(max(tMin.x, tMin.y), tMin.z),
                min(min(tMax.x, tMax.y), tMax.z));
}

void main()
{
    vec2 UV = gl_FragCoord.xy / vec2(width, height);

    vec3 entryPos = texture(inFrontPosTex, UV).xyz;
    vec3 exitPos  = texture(inBackPosTex,  UV).xyz;

    // The longest diagonal of the box
    float boxDiagonal = uBoxDiagonal;

    // Check for sentinel values (positions set to -1e6 when no hit)
    bool entryIsSentinel = entryPos.x < -1e5;
    bool exitIsSentinel = exitPos.x < -1e5;

    // Compute ray direction
    vec3 rayDir;
    if (uProjectionType == 1) {
        // Orthographic: all rays are parallel to view direction
        rayDir = uViewDir;
    } else {
        // Perspective: rays diverge from camera position
        if (!entryIsSentinel) {
            rayDir = normalize(entryPos - uCameraPos);
        } else if (!exitIsSentinel) {
            rayDir = normalize(exitPos - uCameraPos);
        } else {
            // Both sentinel - no valid ray
            discard;
        }
    }

    // When either position is sentinel (clipped), compute analytically
    if (entryIsSentinel || exitIsSentinel) {
        if (uProjectionType == 1) {
            // Orthographic: use the valid position as reference point
            vec3 refPoint;
            if (!entryIsSentinel) {
                refPoint = entryPos;
            } else {
                refPoint = exitPos;
            }
            // Trace ray through reference point to find both entry and exit
            // Move reference point back along ray to ensure we're outside the box
            vec3 rayOrigin = refPoint - rayDir * boxDiagonal * 2.0;
            vec2 tBox = rayBox(rayOrigin, rayDir);
            float tEntry = tBox.x;
            float tExit = tBox.y;

            if (tExit <= tEntry) {
                discard; // Ray misses box
            }

            entryPos = rayOrigin + rayDir * tEntry;
            exitPos = rayOrigin + rayDir * tExit;
        } else {
            // Perspective: use camera position as ray origin
            vec2 tBox = rayBox(uCameraPos, rayDir);
            float tEntry = tBox.x;
            float tExit = tBox.y;

            if (tExit <= tEntry || tExit <= 0.0) {
                discard; // Ray misses box or is behind camera
            }

            if (tEntry > 0.0) {
                entryPos = uCameraPos + rayDir * tEntry;
            } else {
                // Camera is inside the box
                entryPos = uCameraPos;
            }
            exitPos = uCameraPos + rayDir * tExit;
        }
        entryIsSentinel = false;
        exitIsSentinel = false;
    }

    vec3 dir = exitPos - entryPos;
    float rayLength = length(dir);

    // Discard if ray length is invalid:
    // - Too short (no real volume to traverse)
    // - Too long (positions are garbage/sentinel values)
    if (rayLength < 0.0001 || rayLength > boxDiagonal * 2.0) {
        discard;
    }

    vec3 stepDir = normalize(dir);
    float stepSize = rayLength / float(numSteps);
    vec3 step = stepDir * stepSize;

    vec3 accumulatedColor = vec3(0.0);
    float accumulatedAlpha = 0.0;
    vec3 currentPosition = entryPos;

    for (int i = 0; i < numSteps; i++)
    {
        if (accumulatedAlpha > 0.95)
            break;

        // Map world position to texture coordinates [0, 1]
        vec3 volumeUV = (uBoxInverse * vec4(currentPosition, 1.0)).xyz;

        // Skip samples that are clearly outside (with small tolerance for edge precision)
        if (any(lessThan(volumeUV, vec3(-0.01))) ||
            any(greaterThan(volumeUV, vec3(1.01))))
        {
            currentPosition += step;
            continue;
        }

        // Clamp to valid range for texture sampling (handles edge precision issues)
        volumeUV = clamp(volumeUV, vec3(0.0), vec3(1.0));

        float psi = texture(uVolumeData, volumeUV).r;

        float amplitude = abs(psi);
        vec3 color = (psi >= 0.0) ? positiveColor : negativeColor;

        float alphaSample = amplitude * alphaScale;

        // Front-to-back compositing with premultiplied alpha
        accumulatedColor += (1.0 - accumulatedAlpha) * color * alphaSample;
        accumulatedAlpha += (1.0 - accumulatedAlpha) * alphaSample;

        currentPosition += step;
    }

    // Output premultiplied color and alpha - let GL blending composite over scene
    colorOut = vec4(accumulatedColor, accumulatedAlpha);
}
