#version 120

// Scene color behind the volume:
uniform sampler2D inRGBTex;

// The ray entry/exit attachments from bounding‐box passes:
uniform sampler2D inFrontPosTex;
uniform sampler2D inBackPosTex;
uniform vec3 positiveColor;
uniform vec3 negativeColor;
// Our 3D volume (wavefunction):
uniform sampler3D uVolumeData;

// Screen size:
uniform float width;
uniform float height;

// Ray‐march parameters:
uniform int   numSteps;    // e.g. 256
uniform float alphaScale;  // overall alpha multiplier

void main()
{
    vec2 UV = gl_FragCoord.xy / vec2(width, height);

    vec4 sceneColor = texture2D(inRGBTex, UV);

    vec3 entryPos = texture2D(inFrontPosTex, UV).xyz;
    vec3 exitPos  = texture2D(inBackPosTex,  UV).xyz;

    if (entryPos == exitPos) {
        gl_FragColor = sceneColor;
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
        if (accumulatedAlpha > 0.85)
            break;

        vec3 volumeUV = (currentPosition * 0.5) + 0.5;

        if (any(lessThan(volumeUV, vec3(0.0))) ||
            any(greaterThan(volumeUV, vec3(1.0))))
        {
            break;
        }

        float psi = texture3D(uVolumeData, volumeUV).r;

        float amplitude = abs(psi);
        vec3 colorPos = positiveColor; 
        vec3 colorNeg = negativeColor; 
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

    gl_FragColor = outCol;
}
