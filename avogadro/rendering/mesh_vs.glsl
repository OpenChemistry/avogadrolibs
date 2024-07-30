#version 400
precision highp float;

in vec3 vertex;
in vec3 normal;

uniform mat4 modelView;
uniform mat4 projection;
uniform mat3 normalMatrix;


out vec3 WorldPos_CS_in;   
out vec2 TexCoord_CS_in;                                                                     
out vec3 vsNormal;
out vec3 teVertex;  

void main()
{
    teVertex = vertex;
    WorldPos_CS_in = (modelView * vec4(vertex, 1.0)).xyz;
    TexCoord_CS_in = vertex.xy;
    vsNormal = normalize(normalMatrix * normal);
}
