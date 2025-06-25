#version 400
precision highp float;

in vec3 vertex;
in vec3 normal;
in vec4 color;

uniform mat4 modelView;
uniform mat4 projection;
uniform mat3 normalMatrix;

out vec3 WorldPos_CS_in;   
out vec2 TexCoord_CS_in;                                                                     
out vec3 vsNormal;
out vec3 teVertex; 
out vec4 vsColor;

void main()
{
    vsColor = color;
    teVertex = vertex;
    WorldPos_CS_in = (modelView * vec4(vertex, 1.0)).xyz;
    TexCoord_CS_in = vertex.xy;
    vsNormal = normalize(normalMatrix * normal);
}
