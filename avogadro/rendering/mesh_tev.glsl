#version 410 core
precision highp float;

layout(triangles, equal_spacing, ccw) in;

patch in vec3 WorldPos_B030;
patch in vec3 WorldPos_B021;
patch in vec3 WorldPos_B012;
patch in vec3 WorldPos_B003;
patch in vec3 WorldPos_B102;
patch in vec3 WorldPos_B201;
patch in vec3 WorldPos_B300;
patch in vec3 WorldPos_B210;
patch in vec3 WorldPos_B120;
patch in vec3 WorldPos_B111;

patch in vec2 tcsVertex[3];
patch in vec3 tcsNormal[3];
patch in vec3 tevVertex[3];

out vec2 teVertex;
out vec3 teNormal;
out vec3 WorldPos_FS_in;

uniform mat4 modelView;
uniform mat4 projection;

vec3 interpolate3D(vec3 v0, vec3 v1, vec3 v2)
{
    return gl_TessCoord.x * v0 + gl_TessCoord.y * v1 + gl_TessCoord.z * v2;
}

vec2 interpolate2D(vec2 v0, vec2 v1, vec2 v2)                                                   
{                                                                                               
    return gl_TessCoord.x * v0 + gl_TessCoord.y * v1 + gl_TessCoord.z * v2;   
}                                                                                               

void main()
{
    vec2 p0 = tcsVertex[0];
    vec2 p1 = tcsVertex[1];
    vec2 p2 = tcsVertex[2];

    vec3 n0 = tcsNormal[0];
    vec3 n1 = tcsNormal[1];
    vec3 n2 = tcsNormal[2];

    teVertex = interpolate2D(p0, p1, p2);
    teNormal = normalize(interpolate3D(tcsNormal[0], tcsNormal[1], tcsNormal[2]));

    float u = gl_TessCoord.x;                                                                   
    float v = gl_TessCoord.y;                                      

                    
    float w = gl_TessCoord.z;                                                                   
    float uPow3 = pow(u, 3);                                                                    
    float vPow3 = pow(v, 3);                                                                    
    float wPow3 = pow(w, 3);                                                                    
    float uPow2 = pow(u, 2);                                                                    
    float vPow2 = pow(v, 2);                                                                    
    float wPow2 = pow(w, 2); 
    
    WorldPos_FS_in = WorldPos_B300 * wPow3 + WorldPos_B030 * uPow3 + WorldPos_B003 * vPow3 +                               
                     WorldPos_B210 * 3.0 * wPow2 * u + WorldPos_B120 * 3.0 * w * uPow2 + WorldPos_B201 * 3.0 * wPow2 * v + 
                     WorldPos_B021 * 3.0 * uPow2 * v + WorldPos_B102 * 3.0 * w * vPow2 + WorldPos_B012 * 3.0 * u * vPow2 + 
                     WorldPos_B111 * 6.0 * w * u * v;  


    gl_Position =  projection * vec4(WorldPos_FS_in, 1.0);
}
