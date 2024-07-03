#version 400     
precision highp float; 

in vec3 fnormal;
in vec4 outColor;

out vec4 colorOut;


void main()
{
  vec3 N = normalize(fnormal);
  vec3 L = normalize(vec3(0, 1, 1));
  vec3 E = vec3(0, 0, 1);
  vec3 H = normalize(L + E);
  float df = max(0.0, dot(N, L));
  float sf = max(0.0, dot(N, H));
  vec4 ambient = 0.4 * outColor;
  vec4 diffuse = 0.55 * outColor;
  vec4 specular = 0.5 * (vec4(1, 1, 1, 1) - outColor);
  colorOut = ambient + df * diffuse + pow(sf, 20.0) * specular;
  colorOut.a = 1.0;
}
