varying vec2 v_texCoord;
varying vec4 eyePosition;
varying vec3 fColor;
uniform mat3 normal;
uniform mat4 projection;
varying float radius;
void main()
{
  // Figure out if we are inside our sphere.
  float zz = 1.0 - v_texCoord.x*v_texCoord.x - v_texCoord.y*v_texCoord.y;
  if (zz <= 0.0)
    discard;

  vec3 N = vec3(v_texCoord, sqrt(zz));
  vec3 L = normalize(vec3(0, 1, 1));
  vec3 E = vec3(0, 0, 1);
  vec3 H = normalize(L + E);
  float df = max(0.0, dot(N, L));
  float sf = max(0.0, dot(N, H));
  sf = pow(sf, 20.0);
  vec3 ambient = fColor / 3.0;
  vec3 diffuse = fColor;
  vec3 specular = fColor * 3.0;
  vec3 color = ambient + df * diffuse + sf * specular;
  vec4 pos = eyePosition;
  pos.z += N.z * radius;//The radius is 1.0
  pos = projection * pos;
  gl_FragDepth = (pos.z / pos.w + 1.0) / 2.0;

//  gl_FragColor = vec4(normalize(position), 1.0);
  gl_FragColor = vec4(color, 1.0);
}
