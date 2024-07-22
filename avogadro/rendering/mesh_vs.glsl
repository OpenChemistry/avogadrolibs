#version 400
precision highp float;     

in vec3 vertex;
in vec3 normal;
in vec4 color;

uniform mat4 modelView;
uniform mat4 projection;
uniform mat3 normalMatrix;

out vec2 TexCoord_CS_in;
out vec3 WorldPos_CS_in;                                                                        
out vec3 fnormal;

out vec4 outColor;


void main()
{
  outColor = color;
  gl_Position = projection * modelView * vec4(vertex, 1.0);

  WorldPos_CS_in = (modelView * vec4(vertex, 1.0)).xyz;                                  
  TexCoord_CS_in = vertex.xy;
  fnormal = normalize(normalMatrix * normal);

}