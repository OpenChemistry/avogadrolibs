
varying vec3 fragNormal;
varying vec3 fragPosition;

uniform vec3 color;

varying vec4 fragColor;

void main()
{
  vec3 N = normalize(fragNormal);
  vec3 L = normalize(vec3(0, 1, 1));
  vec3 E = vec3(0, 0, 1);
  vec3 H = normalize(L + E);

  float df = max(0.0, dot(N, L));
  float sf = max(0.0, dot(N, H));

  vec3 ambient = 0.4 * color;
  vec3 diffuse = 0.55 * df * color;
  vec3 specular = 0.5 * (vec3(1,1,1) - color) * pow(sf, 20.0);

  gl_FragColor = vec4(ambient + diffuse + specular, 1.0);
}
