#include <bits/stdc++.h>
using namespace std;

// ================= HELPER =================
string XOR(string a, string b) {
    string res = "";
    for (int i = 0; i < a.size(); i++)
        res += (a[i] == b[i]) ? '0' : '1';
    return res;
}

string shift_left(string k, int shifts) {
    while (shifts--) {
        k = k.substr(1) + k[0];
    }
    return k;
}

// ================= TABLE =================
int IP[64] = {
58,50,42,34,26,18,10,2,
60,52,44,36,28,20,12,4,
62,54,46,38,30,22,14,6,
64,56,48,40,32,24,16,8,
57,49,41,33,25,17,9,1,
59,51,43,35,27,19,11,3,
61,53,45,37,29,21,13,5,
63,55,47,39,31,23,15,7};

int IP_1[64] = {
40,8,48,16,56,24,64,32,
39,7,47,15,55,23,63,31,
38,6,46,14,54,22,62,30,
37,5,45,13,53,21,61,29,
36,4,44,12,52,20,60,28,
35,3,43,11,51,19,59,27,
34,2,42,10,50,18,58,26,
33,1,41,9,49,17,57,25};

int E[48] = {
32,1,2,3,4,5,4,5,
6,7,8,9,8,9,10,11,
12,13,12,13,14,15,16,17,
16,17,18,19,20,21,20,21,
22,23,24,25,24,25,26,27,
28,29,28,29,30,31,32,1};

int P[32] = {
16,7,20,21,29,12,28,17,
1,15,23,26,5,18,31,10,
2,8,24,14,32,27,3,9,
19,13,30,6,22,11,4,25};

// ================= KEY =================
int PC1[56] = {
57,49,41,33,25,17,9,
1,58,50,42,34,26,18,
10,2,59,51,43,35,27,
19,11,3,60,52,44,36,
63,55,47,39,31,23,15,
7,62,54,46,38,30,22,
14,6,61,53,45,37,29,
21,13,5,28,20,12,4};

int PC2[48] = {
14,17,11,24,1,5,
3,28,15,6,21,10,
23,19,12,4,26,8,
16,7,27,20,13,2,
41,52,31,37,47,55,
30,40,51,45,33,48,
44,49,39,56,34,53,
46,42,50,36,29,32};

int shift_table[16] = {
1,1,2,2,2,2,2,2,
1,2,2,2,2,2,2,1};

// ================= SBOX =================
int S[8][4][16] = {{
{14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
{0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
{4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
{15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}},
};

// ================= FUNCTION =================
string permute(string in, int *arr, int n) {
    string out = "";
    for (int i = 0; i < n; i++)
        out += in[arr[i] - 1];
    return out;
}

// ================= KEY GEN =================
vector<string> generate_keys(string key) {
    vector<string> keys;

    key = permute(key, PC1, 56);
    string left = key.substr(0, 28);
    string right = key.substr(28, 28);

    for (int i = 0; i < 16; i++) {
        left = shift_left(left, shift_table[i]);
        right = shift_left(right, shift_table[i]);

        string combined = left + right;
        string round_key = permute(combined, PC2, 48);

        keys.push_back(round_key);
    }

    return keys;
}

// ================= DES =================
string DES(string pt, vector<string> keys) {

    pt = permute(pt, IP, 64);
    string left = pt.substr(0, 32);
    string right = pt.substr(32, 32);

    for (int i = 0; i < 16; i++) {

        string right_expanded = permute(right, E, 48);
        string x = XOR(right_expanded, keys[i]);

        string res = x.substr(0,32); 

        string p = permute(res, P, 32);
        string new_right = XOR(left, p);

        left = right;
        right = new_right;
    }

    string combine = right + left;
    return permute(combine, IP_1, 64);
}

// ================= TRIPLE DES =================
string tripleDES(string pt, string k1, string k2, string k3) {

    vector<string> key1 = generate_keys(k1);
    vector<string> key2 = generate_keys(k2);
    vector<string> key3 = generate_keys(k3);

    string step1 = DES(pt, key1);

    reverse(key2.begin(), key2.end());
    string step2 = DES(step1, key2);

    string step3 = DES(step2, key3);

    return step3;
}

// ================= MAIN =================
int main() {

    string plaintext, key1, key2, key3;

    cout << "Nhap plaintext (binary): ";
    cin >> plaintext;

    cout << "Nhap key1: ";
    cin >> key1;
    cout << "Nhap key2: ";
    cin >> key2;
    cout << "Nhap key3: ";
    cin >> key3;

    // padding
    while (plaintext.size() % 64 != 0)
        plaintext += "0";

    for (int i = 0; i < plaintext.size(); i += 64) {
        string block = plaintext.substr(i, 64);
        string cipher = tripleDES(block, key1, key2, key3);
        cout << "Cipher block: " << cipher << endl;
    }

    return 0;
}
