#version 400
precision highp float;

in vec3 teNormal;
in vec3 vsNormal;
out vec4 colorOut;
// in vec3 vsNormal;


void main()
{
    vec3 N = normalize(teNormal);
    vec3 L = vec3(0.0, 1.0, 1.0);
    vec3 E = vec3(0.0, 0.0, 1.0);
    vec3 H = normalize(L + E);
    float df = max(0.0, dot(N, L));
    float sf = max(0.0, dot(N, H));
    sf = pow(sf, 20.0);
    vec4 ambient = vec4(1.0, 0.0, 0.0, 1.0) / 3.0;
    vec4 diffuse = vec4(1.0, 0.0, 0.0, 1.0);
    vec4 specular = vec4(1.0, 0.0, 0.0, 1.0) * 3.0;
    colorOut = ambient + df * diffuse + sf * specular;
    colorOut.a = vec4(1.0, 0.0, 0.0, 1.0).a;
}
