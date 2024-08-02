#version 400
precision highp float;

layout(vertices = 1) out;

in vec3 vsNormal[];
in vec3 WorldPos_CS_in[];          
in vec2 TexCoord_CS_in[];
in vec3 teVertex[];
in vec4 vsColor[];

patch out vec3 WorldPos_B030;
patch out vec3 WorldPos_B012;
patch out vec3 WorldPos_B021;
patch out vec3 WorldPos_B003;
patch out vec3 WorldPos_B102;
patch out vec3 WorldPos_B201;
patch out vec3 WorldPos_B300;
patch out vec3 WorldPos_B210;
patch out vec3 WorldPos_B120;
patch out vec3 WorldPos_B111;

patch out vec2 tcsVertex[3];
patch out vec3 tcsNormal[3];
patch out vec3 tevVertex[3];
patch out vec4 tcsColor[3];

vec3 ProjectToPlane(vec3 Point, vec3 PlanePoint, vec3 PlaneNormal)
{
    vec3 v = Point - PlanePoint;
    float Len = dot(v, PlaneNormal);
    vec3 d = Len * PlaneNormal;
    return (Point - d);
}

void CalcPositions()
{
    WorldPos_B030 = WorldPos_CS_in[0];
    WorldPos_B003 = WorldPos_CS_in[1];
    WorldPos_B300 = WorldPos_CS_in[2];

    vec3 EdgeB300 = WorldPos_B003 - WorldPos_B030;
    vec3 EdgeB030 = WorldPos_B300 - WorldPos_B003;
    vec3 EdgeB003 = WorldPos_B030 - WorldPos_B300;

    WorldPos_B021 = WorldPos_B030 + EdgeB300 / 3.0;
    WorldPos_B012 = WorldPos_B030 + EdgeB300 * 2.0 / 3.0;
    WorldPos_B102 = WorldPos_B003 + EdgeB030 / 3.0;
    WorldPos_B201 = WorldPos_B003 + EdgeB030 * 2.0 / 3.0;
    WorldPos_B210 = WorldPos_B300 + EdgeB003 / 3.0;
    WorldPos_B120 = WorldPos_B300 + EdgeB003 * 2.0 / 3.0;

    WorldPos_B021 = ProjectToPlane(WorldPos_B021, WorldPos_B030, normalize(vsNormal[0]));
    WorldPos_B012 = ProjectToPlane(WorldPos_B012, WorldPos_B003, normalize(vsNormal[1]));
    WorldPos_B102 = ProjectToPlane(WorldPos_B102, WorldPos_B003, normalize(vsNormal[1]));
    WorldPos_B201 = ProjectToPlane(WorldPos_B201, WorldPos_B300, normalize(vsNormal[2]));
    WorldPos_B210 = ProjectToPlane(WorldPos_B210, WorldPos_B300, normalize(vsNormal[2]));
    WorldPos_B120 = ProjectToPlane(WorldPos_B120, WorldPos_B030, normalize(vsNormal[0]));

    vec3 Center = (WorldPos_B003 + WorldPos_B030 + WorldPos_B300) / 3.0;
    WorldPos_B111 = (WorldPos_B021 + WorldPos_B012 + WorldPos_B102 +
                     WorldPos_B201 + WorldPos_B210 + WorldPos_B120) / 6.0;
    WorldPos_B111 += (WorldPos_B111 - Center) / 2.0;
}

void main()
{
    for (int i = 0 ; i < 3 ; i++) {
       tcsVertex[i] = TexCoord_CS_in[i];
       tevVertex[i] = teVertex[i];
       tcsNormal[i] = vsNormal[i];
       tcsColor[i] = vsColor[i];

    CalcPositions();

    gl_TessLevelOuter[0] = 50;
    gl_TessLevelOuter[1] = 50;
    gl_TessLevelOuter[2] = 50;
    gl_TessLevelOuter[3] = 50;
    gl_TessLevelInner[0] = 50;
    gl_TessLevelInner[1] = 50;
}
