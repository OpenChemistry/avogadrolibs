//////////////////////////////////////////////////////////////////////
//
// First-stage screen-space fragment shader for the solid pipeline
//
// It offers ambient occlusion and edge detection capabilities.
//
//////////////////////////////////////////////////////////////////////

#version 120

//
// Input
//

// texture coordinates
varying vec2 UV;

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
// Shadow strength for SSAO
uniform float inAoStrength;
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

vec3 getNormalAt(vec2 normalUV)
{
    float xpos = texture2D(inDepthTex, normalUV + vec2(1.0 / width, 0.0)).x;
    float xneg = texture2D(inDepthTex, normalUV - vec2(1.0 / width, 0.0)).x;
    float ypos = texture2D(inDepthTex, normalUV + vec2(0.0, 1.0 / height)).x;
    float yneg = texture2D(inDepthTex, normalUV - vec2(0.0, 1.0 / height)).x;
    float xdelta = xpos - xneg;
    float ydelta = ypos - yneg;
    vec3 r = vec3(xdelta, ydelta, 1.0 / width + 1.0 / height);
    return normalize(r);
}

vec3 getNormalNear(vec2 normalUV)
{
    float cent = texture2D(inDepthTex, normalUV).x;
    float xpos = texture2D(inDepthTex, normalUV + vec2(1.0 / width, 0.0)).x;
    float xneg = texture2D(inDepthTex, normalUV - vec2(1.0 / width, 0.0)).x;
    float ypos = texture2D(inDepthTex, normalUV + vec2(0.0, 1.0 / height)).x;
    float yneg = texture2D(inDepthTex, normalUV - vec2(0.0, 1.0 / height)).x;
    float xposdelta = xpos - cent;
    float xnegdelta = cent - xneg;
    float yposdelta = ypos - cent;
    float ynegdelta = cent - yneg;
    float xdelta = abs(xposdelta) > abs(xnegdelta) ? xnegdelta : xposdelta;
    float ydelta = abs(yposdelta) > abs(ynegdelta) ? ynegdelta : yposdelta;
    vec3 r = vec3(xdelta, ydelta, 0.5 / width + 0.5 / height);
    return normalize(r);
}

float lerp(float a, float b, float f)
{
    return a + f * (b - a);
}

float rand(vec2 co) {
    return fract(sin(dot(co.xy, vec2(12.9898, 78.233))) * 43758.5453);
}

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
    float origZ = depthToZ(texture2D(inDepthTex, texCoord).x);
    float blurAmt = calcBlur(origZ, pixelScale);
    // Skip blurring if the original depth is less than the threshold
    if (origZ < uoffset * inDofPosition) {
        return texture2D(inRGBTex, texCoord);
    }
    float total = 1.0;
    vec4 color = texture2D(inRGBTex, texCoord);
    for (int i = 0; i < 32; i++) {
        float t = (float(i) / float(64));
        float angle = (t * 4.0) * 6.28319;
        float radius = (t * 2. - 1.);
        angle += 1.0 * rand(gl_FragCoord.xy);
        vec2 offset = (vec2(cos(angle), sin(angle)) * radius * 0.05 * inDofStrength) / pixelScale;
        float z = depthToZ(texture2D(inDepthTex, texCoord + offset).x);
        float sampleBlur = calcBlur(z, pixelScale);
        float weight = 1.0 - smoothstep(0.0, 1.0, abs(z - origZ) / blurAmt);
        vec4
        sample = texture2D(inRGBTex, texCoord+offset);
        color += weight * sample;
        total += weight;
}
return color / total;
}

vec4 applyFog(vec2 texCoord) {
    vec4 finalColor = mix(
            texture2D(inRGBTex, texCoord),
            vec4(vec3(fogR, fogG, fogB), 1.),
            pow(texture2D(inDepthTex, texCoord.xy).r, uoffset * inFogPosition / 10.0)
        ) + inFogStrength / 100.0;
    return finalColor;
}

const vec2 SSAOkernel[16] = vec2[16](
        vec2(0.072170, 0.081556),
        vec2(-0.035126, 0.056701),
        vec2(-0.034186, -0.083598),
        vec2(-0.056102, -0.009235),
        vec2(0.017487, -0.099822),
        vec2(0.071065, 0.015921),
        vec2(0.040950, 0.079834),
        vec2(-0.087751, 0.065326),
        vec2(0.061108, -0.025829),
        vec2(0.081262, -0.025854),
        vec2(-0.063816, 0.083857),
        vec2(0.043747, -0.068586),
        vec2(-0.089848, 0.049046),
        vec2(-0.065370, 0.058761),
        vec2(0.099581, -0.089322),
        vec2(-0.032077, -0.042826)
    );

float computeSSAOLuminosity(vec3 normal)
{
    float totalOcclusion = 0.0;
    float depth = texture2D(inDepthTex, UV).x;
    float A = (width * UV.x + 10 * height * UV.y) * 2.0 * 3.14159265358979 * 5.0 / 16.0;
    float S = sin(A);
    float C = cos(A);
    mat2 rotation = mat2(
            C, -S,
            S, C
        );
    for (int i = 0; i < 16; i++) {
        vec2 samplePoint = rotation * SSAOkernel[i];
        float occluderDepth = texture2D(inDepthTex, UV + samplePoint).x;
        vec3 occluder = vec3(samplePoint.xy, depth - occluderDepth);
        float d = length(occluder);
        float occlusion = max(0.0, dot(normal, occluder)) * (1.0 / (1.0 + d));
        totalOcclusion += occlusion;
    }

    return max(0.0, 1.2 - inAoStrength * totalOcclusion);
}

float computeEdgeLuminosity(vec3 normal)
{
    return max(0.0, pow(normal.z - 0.1, 1.0 / 3.0));
}

void main() {
    float luminosity = 1.0;
    vec4 color = texture2D(inRGBTex, UV);
    vec4 finalColor = color; // Initialize finalColor with base color

    // Compute luminosity based on Ambient Occlusion (AO) and Edge Detection
    if (inAoEnabled != 0.0) {
        luminosity *= max(1.2 * (1.0 - inAoEnabled), computeSSAOLuminosity(getNormalNear(UV)));
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
    gl_FragColor = finalColor;

    // Set fragment depth
    gl_FragDepth = texture2D(inDepthTex, UV).x;
}
