//#define CONTOUR_LINES
//#define TOON_SHADING

// normalized corner
varying vec2 v_corner;
// color
varying vec3 v_color;
// position in eye-coordinate space
varying vec4 v_eyePos;
// sphere radius
varying float v_radius;
// AO tile offset
varying vec2 v_tileOffset;

// inverse model-view matrix
uniform mat4 u_modelView;
uniform mat3 u_invModelView;
// the projection matrix
uniform mat4 u_projection;
// the texture sampler
uniform sampler2D u_tex;
uniform float u_texScale;

#ifdef CONTOUR_LINES
const float contourWidth = 0.3;
#endif

#ifdef TOON_SHADING
const float levels = 4.0;
#endif

vec2 sphereSurfaceToTextureCoord(in vec3 coord)
{
  vec3 absCoord = abs(coord);
  float d = absCoord.x + absCoord.y + absCoord.z;
  return (coord.z <= 0.0) ? coord.xy / d : sign(coord.xy) * (1.0 - absCoord.yx / d);
}

float cosine(in vec3 a, in vec3 b)
{
  float cos_alpha = max(0.0, dot(a, b));
#ifdef TOON_SHADING
  cos_alpha = floor(cos_alpha * levels) / levels;
#endif
  return cos_alpha;
}

void main()
{
  // figure out if we are inside our sphere
  float zz = 1.0 - v_corner.x * v_corner.x - v_corner.y * v_corner.y;
#ifdef CONTOUR_LINES
  if (zz <= -sqrt(contourWidth)) {
    // fragment outside sphere + contour radius
    discard;
  }
  if (zz <= 0.0) {
    // fragment is part of the contour
    float xi = abs(zz); // [0, contourWidth]
    // eta determines how much the contours are pushed back
    float eta = 0.0004;
    gl_FragColor = vec4(0.0, 0.0, 0.0, 1.0); // black
    gl_FragDepth = gl_FragCoord.z - 10e-10 + eta * xi;
    return;
  }
#else
  if (zz <= 0.0)
    discard;
#endif

  // compute normal in eye coods
  vec3 N = normalize(vec3(v_corner, sqrt(zz)));

  // compute the pixel's depth
  vec4 pos = v_eyePos;
  pos.z += N.z * v_radius; // radius is 1.0
  pos = u_projection * pos;
  gl_FragDepth = (pos.z / pos.w + 1.0) / 2.0;

  // transform to normal to model-space
  vec3 modelN = N;
  modelN = normalize(u_invModelView * modelN);
  // determine (u, v) texture coordinates using gnomonic projection
  vec2 uv = sphereSurfaceToTextureCoord(modelN); // [-1, 1]


  uv = v_tileOffset + uv * u_texScale;

  //gl_FragColor = vec4(v_color, 1.0) * texture2D(u_tex, uv);

  // direction of light source
  vec3 L = normalize(vec3(0, 1, 1));
  // eye direction
  vec3 E = vec3(0, 0, 1);

  // angle between normal and light direction
  float cos_alpha = cosine(N, L);

  // compute ambient color
  vec3 ambient = 0.4 * v_color;
  // compute diffuse color
  vec3 diffuse = 0.55 * v_color * cos_alpha;
  // compute specular color (approximate Fresnel reflection)
  vec3 H = normalize(L + E); // halfway vector between N and E
  float cos_beta = cosine(N, H);
  vec3 specular = 0.5 * (vec3(1, 1, 1) - v_color)* pow(cos_beta, 20.0);

  // final color
  vec3 color = ambient + diffuse + specular;
  gl_FragColor = 1.2 * vec4(color, 1.0) * texture2D(u_tex, uv); // AO + Phong reflection [+ contours]
  //gl_FragColor = vec4(color, 1.0); // Phong reflection [+ contours]
  //gl_FragColor = 1.2 * texture2D(u_tex, uv); // AO [+ contours]
  //gl_FragColor = vec4(1.0, 1.0, 1.0, 1.0); // contours + white atoms
}
