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
  sf = pow(sf, 20.0);
  vec4 ambient = outColor / 3.0;
  vec4 diffuse = outColor;
  vec4 specular = outColor * 3.0;
  colorOut = ambient + df * diffuse + sf * specular;
  colorOut.a = outColor.a;
}
