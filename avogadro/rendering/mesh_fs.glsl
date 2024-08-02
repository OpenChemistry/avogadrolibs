#version 400
precision highp float;

in vec3 teNormal;
in vec4 teColor;

out vec4 colorOut;

void main()
{
    vec3 N = normalize(teNormal); 
    vec3 L = normalize(vec3(0, 1, 1));
    vec3 E = vec3(0, 0, 1);
    vec3 H = normalize(L + E);
    float df = max(0.0, dot(N, L));
    float sf = max(0.0, dot(N, H));
    sf = pow(sf, 20.0);
    vec4 ambient = teColor / 3.0;
    vec4 diffuse = teColor;
    vec4 specular = teColor * 3.0;
    colorOut = ambient + df * diffuse + sf * specular;
    colorOut.a = teColor.a; 
}
