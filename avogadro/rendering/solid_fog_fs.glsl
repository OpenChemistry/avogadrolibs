#version 120

varying vec2 UV;

uniform sampler2D inRGBTex;

uniform float fogR;
uniform float fogG;
uniform float fogB;

uniform sampler2D inDepthTex;
uniform float inFogStrength;
uniform float uoffset;
uniform float inFogPosition;

vec4 applyFog(vec2 texCoord) {
  vec4 finalColor = mix(
    texture2D(inRGBTex, texCoord),
    vec4(vec3(fogR, fogG, fogB), 1.),
    pow(texture2D(inDepthTex, texCoord.xy).r, uoffset * inFogPosition/10.0)
  ) + inFogStrength / 100.0;

return finalColor;
}


void main() {

    vec4 foggedColor = applyFog(UV);

    gl_FragColor = foggedColor;
    gl_FragDepth = texture2D(inDepthTex, UV).x;

}