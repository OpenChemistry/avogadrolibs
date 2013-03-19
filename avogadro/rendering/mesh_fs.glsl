varying vec3 fnormal;

void main()
{
  vec3 N = normalize(fnormal);
  vec3 L = normalize(vec3(0, 1, 1));
  vec3 E = vec3(0, 0, 1);
  vec3 H = normalize(L + E);
  float df = max(0.0, dot(N, L));
  float sf = max(0.0, dot(N, H));
  sf = pow(sf, 20.0);
  vec4 ambient = gl_Color / 3.0;
  vec4 diffuse = gl_Color;
  vec4 specular = gl_Color * 3.0;
  gl_FragColor = ambient + df * diffuse + sf * specular;
  gl_FragColor.a = gl_Color.a;
}
