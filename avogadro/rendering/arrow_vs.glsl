
attribute vec3 position;
attribute vec3 normal;

uniform mat4 modelView;
uniform mat4 projection;
uniform mat4 model;

varying vec3 fragNormal;
varying vec3 fragPosition;

void main()
{
  gl_Position = projection * modelView * model * vec4(position, 1.0);
  fragNormal = mat3(model[0].xyz, model[1].xyz, model[2].xyz) * normal;
  fragPosition = vec3(model * vec4(position, 1.0));
}
