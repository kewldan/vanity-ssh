// Metal compute kernels for vanity-ssh.
//
// Derives Ed25519 public keys from random seeds exactly like OpenSSH
// (RFC 8032), hashes the OpenSSH public key blob with SHA-256 and compares the
// base64 fingerprint against a pattern.
//
// The host defines WBITS (table window, 8 or 16) and KEYS_PER_THREAD before
// compiling this file.

#include <metal_stdlib>

using namespace metal;

// SHA-512 and SHA-256 round constants and initial hash values.
constant ulong kK512[80] = {
    0x428a2f98d728ae22UL, 0x7137449123ef65cdUL, 0xb5c0fbcfec4d3b2fUL,
    0xe9b5dba58189dbbcUL, 0x3956c25bf348b538UL, 0x59f111f1b605d019UL,
    0x923f82a4af194f9bUL, 0xab1c5ed5da6d8118UL, 0xd807aa98a3030242UL,
    0x12835b0145706fbeUL, 0x243185be4ee4b28cUL, 0x550c7dc3d5ffb4e2UL,
    0x72be5d74f27b896fUL, 0x80deb1fe3b1696b1UL, 0x9bdc06a725c71235UL,
    0xc19bf174cf692694UL, 0xe49b69c19ef14ad2UL, 0xefbe4786384f25e3UL,
    0x0fc19dc68b8cd5b5UL, 0x240ca1cc77ac9c65UL, 0x2de92c6f592b0275UL,
    0x4a7484aa6ea6e483UL, 0x5cb0a9dcbd41fbd4UL, 0x76f988da831153b5UL,
    0x983e5152ee66dfabUL, 0xa831c66d2db43210UL, 0xb00327c898fb213fUL,
    0xbf597fc7beef0ee4UL, 0xc6e00bf33da88fc2UL, 0xd5a79147930aa725UL,
    0x06ca6351e003826fUL, 0x142929670a0e6e70UL, 0x27b70a8546d22ffcUL,
    0x2e1b21385c26c926UL, 0x4d2c6dfc5ac42aedUL, 0x53380d139d95b3dfUL,
    0x650a73548baf63deUL, 0x766a0abb3c77b2a8UL, 0x81c2c92e47edaee6UL,
    0x92722c851482353bUL, 0xa2bfe8a14cf10364UL, 0xa81a664bbc423001UL,
    0xc24b8b70d0f89791UL, 0xc76c51a30654be30UL, 0xd192e819d6ef5218UL,
    0xd69906245565a910UL, 0xf40e35855771202aUL, 0x106aa07032bbd1b8UL,
    0x19a4c116b8d2d0c8UL, 0x1e376c085141ab53UL, 0x2748774cdf8eeb99UL,
    0x34b0bcb5e19b48a8UL, 0x391c0cb3c5c95a63UL, 0x4ed8aa4ae3418acbUL,
    0x5b9cca4f7763e373UL, 0x682e6ff3d6b2b8a3UL, 0x748f82ee5defb2fcUL,
    0x78a5636f43172f60UL, 0x84c87814a1f0ab72UL, 0x8cc702081a6439ecUL,
    0x90befffa23631e28UL, 0xa4506cebde82bde9UL, 0xbef9a3f7b2c67915UL,
    0xc67178f2e372532bUL, 0xca273eceea26619cUL, 0xd186b8c721c0c207UL,
    0xeada7dd6cde0eb1eUL, 0xf57d4f7fee6ed178UL, 0x06f067aa72176fbaUL,
    0x0a637dc5a2c898a6UL, 0x113f9804bef90daeUL, 0x1b710b35131c471bUL,
    0x28db77f523047d84UL, 0x32caab7b40c72493UL, 0x3c9ebe0a15c9bebcUL,
    0x431d67c49c100d4cUL, 0x4cc5d4becb3e42b6UL, 0x597f299cfc657e2aUL,
    0x5fcb6fab3ad6faecUL, 0x6c44198c4a475817UL};
constant ulong kH512[8] = {0x6a09e667f3bcc908UL, 0xbb67ae8584caa73bUL,
                           0x3c6ef372fe94f82bUL, 0xa54ff53a5f1d36f1UL,
                           0x510e527fade682d1UL, 0x9b05688c2b3e6c1fUL,
                           0x1f83d9abfb41bd6bUL, 0x5be0cd19137e2179UL};
constant uint kK256[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu,
    0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u,
    0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u,
    0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u,
    0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
    0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
    0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u,
    0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u, 0x1e376c08u,
    0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu,
    0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};
constant uint kH256[8] = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                          0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};

// Ed25519 base point B and 2d, as field elements in the limb layout below.
constant int kBaseX[10] = {52811034, 25909283, 16144682, 17082669, 27570973,
                           30858332, 40966398, 8378388,  20764389, 8758491};
constant int kBaseY[10] = {40265304, 26843545, 13421772, 20132659, 26843545,
                           6710886,  53687091, 13421772, 40265318, 26843545};
constant int kD2[10] = {45281625, 27714825, 36363642, 13898781, 229458,
                        15978800, 54557047, 27058993, 29715967, 9444199};

// ---------------------------------------------------------------------------
// Field arithmetic modulo p = 2^255 - 19.
//
// An element is ten signed limbs in radix 2^25.5 (26, 25, 26, ... bits), the
// layout used by the ref10 implementation. Every operation returns carried
// limbs, which keeps all products comfortably inside 64 bits.
// ---------------------------------------------------------------------------

struct Fe {
  int v[10];
};

inline int LimbBits(int i) { return (i & 1) ? 25 : 26; }

inline Fe Carry(thread long* t) {
  for (int i = 0; i < 10; ++i) {
    int bits = LimbBits(i);
    long c = (t[i] + (1L << (bits - 1))) >> bits;
    t[i] -= c * (1L << bits);
    if (i < 9) {
      t[i + 1] += c;
    } else {
      t[0] += c * 19;
    }
  }
  long c = (t[0] + (1L << 25)) >> 26;
  t[0] -= c * (1L << 26);
  t[1] += c;
  Fe h;
  for (int i = 0; i < 10; ++i) h.v[i] = (int)t[i];
  return h;
}

inline Fe FeZero() {
  Fe h;
  for (int i = 0; i < 10; ++i) h.v[i] = 0;
  return h;
}

inline Fe FeOne() {
  Fe h = FeZero();
  h.v[0] = 1;
  return h;
}

inline Fe FeConst(constant const int* c) {
  Fe h;
  for (int i = 0; i < 10; ++i) h.v[i] = c[i];
  return h;
}

inline Fe FeLoad(device const int* p) {
  Fe h;
  for (int i = 0; i < 10; ++i) h.v[i] = p[i];
  return h;
}

inline void FeStore(Fe f, device int* p) {
  for (int i = 0; i < 10; ++i) p[i] = f.v[i];
}

inline Fe FeMul(Fe f, Fe g) {
  // Doubling odd*odd limbs and folding 2^255 = 19 is done on 32-bit inputs so
  // that every 64-bit operation is a plain widening multiply-add.
  int f2[10];
  int g19[10];
  for (int i = 0; i < 10; ++i) {
    f2[i] = (i & 1) ? 2 * f.v[i] : f.v[i];
    g19[i] = 19 * g.v[i];
  }
  long t[10] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  for (int i = 0; i < 10; ++i) {
    for (int j = 0; j < 10; ++j) {
      int a = (j & 1) ? f2[i] : f.v[i];
      int b = (i + j >= 10) ? g19[j] : g.v[j];
      t[(i + j) % 10] += (long)a * (long)b;
    }
  }
  return Carry(t);
}

inline Fe FeSq(Fe f) { return FeMul(f, f); }

inline Fe FeSqN(Fe f, int n) {
  for (int i = 0; i < n; ++i) f = FeSq(f);
  return f;
}

inline Fe FeAdd(Fe f, Fe g) {
  long t[10];
  for (int i = 0; i < 10; ++i) t[i] = (long)f.v[i] + g.v[i];
  return Carry(t);
}

inline Fe FeSub(Fe f, Fe g) {
  long t[10];
  for (int i = 0; i < 10; ++i) t[i] = (long)f.v[i] - g.v[i];
  return Carry(t);
}

// z^(p - 2) with the standard ref10 addition chain.
inline Fe FeInvert(Fe z) {
  Fe t0 = FeSq(z);
  Fe t1 = FeSqN(t0, 2);
  t1 = FeMul(z, t1);
  t0 = FeMul(t0, t1);
  Fe t2 = FeSq(t0);
  t1 = FeMul(t1, t2);
  t2 = FeSqN(t1, 5);
  t1 = FeMul(t2, t1);
  t2 = FeSqN(t1, 10);
  t2 = FeMul(t2, t1);
  Fe t3 = FeSqN(t2, 20);
  t2 = FeMul(t3, t2);
  t2 = FeSqN(t2, 10);
  t1 = FeMul(t2, t1);
  t2 = FeSqN(t1, 50);
  t2 = FeMul(t2, t1);
  t3 = FeSqN(t2, 100);
  t2 = FeMul(t3, t2);
  t2 = FeSqN(t2, 50);
  t1 = FeMul(t2, t1);
  t1 = FeSqN(t1, 5);
  return FeMul(t1, t0);
}

// Canonical little-endian encoding of a carried element.
inline void FeToBytes(Fe f, thread uchar* s) {
  long h[10];
  for (int i = 0; i < 10; ++i) h[i] = f.v[i];
  long q = (19 * h[9] + (1L << 24)) >> 25;
  for (int i = 0; i < 10; ++i) q = (h[i] + q) >> LimbBits(i);
  h[0] += 19 * q;
  for (int i = 0; i < 9; ++i) {
    long c = h[i] >> LimbBits(i);
    h[i + 1] += c;
    h[i] -= c * (1L << LimbBits(i));
  }
  h[9] -= (h[9] >> 25) * (1L << 25);
  ulong acc = 0;
  int bits = 0;
  int out = 0;
  for (int i = 0; i < 10; ++i) {
    acc |= (ulong)h[i] << bits;
    bits += LimbBits(i);
    while (bits >= 8) {
      s[out++] = (uchar)(acc & 0xff);
      acc >>= 8;
      bits -= 8;
    }
  }
  s[31] = (uchar)acc;
}

// ---------------------------------------------------------------------------
// Edwards25519 points in extended coordinates (x : y : z : t), xy = zt.
// ---------------------------------------------------------------------------

struct Point {
  Fe x;
  Fe y;
  Fe z;
  Fe t;
};

inline Point PointIdentity() {
  Point p;
  p.x = FeZero();
  p.y = FeOne();
  p.z = FeOne();
  p.t = FeZero();
  return p;
}

inline Point PointDouble(Point p) {
  Fe a = FeSq(p.x);
  Fe b = FeSq(p.y);
  Fe c = FeSq(p.z);
  c = FeAdd(c, c);
  Fe h = FeAdd(a, b);
  Fe e = FeSub(h, FeSq(FeAdd(p.x, p.y)));
  Fe g = FeSub(a, b);
  Fe f = FeAdd(c, g);
  Point r;
  r.x = FeMul(e, f);
  r.y = FeMul(g, h);
  r.z = FeMul(f, g);
  r.t = FeMul(e, h);
  return r;
}

inline Point PointAdd(Point p, Point q) {
  Fe a = FeMul(FeSub(p.y, p.x), FeSub(q.y, q.x));
  Fe b = FeMul(FeAdd(p.y, p.x), FeAdd(q.y, q.x));
  Fe c = FeMul(FeMul(p.t, q.t), FeConst(kD2));
  Fe d = FeMul(p.z, q.z);
  d = FeAdd(d, d);
  Fe e = FeSub(b, a);
  Fe f = FeSub(d, c);
  Fe g = FeAdd(d, c);
  Fe h = FeAdd(b, a);
  Point r;
  r.x = FeMul(e, f);
  r.y = FeMul(g, h);
  r.z = FeMul(f, g);
  r.t = FeMul(e, h);
  return r;
}

// Adds an affine table entry stored as (y + x, y - x, 2dxy). The t coordinate
// of the result is only computed when the caller needs it.
inline Point PointAddPrecomp(Point p, device const int* q, bool need_t) {
  Fe y_plus_x = FeLoad(q);
  Fe y_minus_x = FeLoad(q + 10);
  Fe xy2d = FeLoad(q + 20);
  Fe a = FeMul(FeSub(p.y, p.x), y_minus_x);
  Fe b = FeMul(FeAdd(p.y, p.x), y_plus_x);
  Fe c = FeMul(xy2d, p.t);
  Fe d = FeAdd(p.z, p.z);
  Fe e = FeSub(b, a);
  Fe f = FeSub(d, c);
  Fe g = FeAdd(d, c);
  Fe h = FeAdd(b, a);
  Point r;
  r.x = FeMul(e, f);
  r.y = FeMul(g, h);
  r.z = FeMul(f, g);
  r.t = need_t ? FeMul(e, h) : FeZero();
  return r;
}

inline void StorePoint(Point p, device int* out) {
  FeStore(p.x, out);
  FeStore(p.y, out + 10);
  FeStore(p.z, out + 20);
  FeStore(p.t, out + 30);
}

inline Point LoadPoint(device const int* in) {
  Point p;
  p.x = FeLoad(in);
  p.y = FeLoad(in + 10);
  p.z = FeLoad(in + 20);
  p.t = FeLoad(in + 30);
  return p;
}

// ---------------------------------------------------------------------------
// Hashes, specialised to the fixed-size inputs used here.
// ---------------------------------------------------------------------------

inline ulong Rotr64(ulong x, ulong n) { return rotate(x, 64UL - n); }
inline uint Rotr32(uint x, uint n) { return rotate(x, 32u - n); }

// First 32 bytes of SHA-512 of a 32-byte message.
inline void Sha512Seed(thread const uchar* m, thread uchar* out) {
  ulong w[16];
  for (int i = 0; i < 4; ++i) {
    ulong v = 0;
    for (int b = 0; b < 8; ++b) v = (v << 8) | m[i * 8 + b];
    w[i] = v;
  }
  w[4] = 0x8000000000000000UL;
  for (int i = 5; i < 15; ++i) w[i] = 0;
  w[15] = 256;
  ulong a = kH512[0], b = kH512[1], c = kH512[2], d = kH512[3];
  ulong e = kH512[4], f = kH512[5], g = kH512[6], h = kH512[7];
  for (int i = 0; i < 80; ++i) {
    ulong wi;
    if (i < 16) {
      wi = w[i];
    } else {
      ulong w15 = w[(i - 15) & 15];
      ulong w2 = w[(i - 2) & 15];
      ulong s0 = Rotr64(w15, 1) ^ Rotr64(w15, 8) ^ (w15 >> 7);
      ulong s1 = Rotr64(w2, 19) ^ Rotr64(w2, 61) ^ (w2 >> 6);
      wi = w[i & 15] + s0 + w[(i - 7) & 15] + s1;
      w[i & 15] = wi;
    }
    ulong big_s1 = Rotr64(e, 14) ^ Rotr64(e, 18) ^ Rotr64(e, 41);
    ulong ch = (e & f) ^ (~e & g);
    ulong t1 = h + big_s1 + ch + kK512[i] + wi;
    ulong big_s0 = Rotr64(a, 28) ^ Rotr64(a, 34) ^ Rotr64(a, 39);
    ulong maj = (a & b) ^ (a & c) ^ (b & c);
    ulong t2 = big_s0 + maj;
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }
  ulong r[4] = {a + kH512[0], b + kH512[1], c + kH512[2], d + kH512[3]};
  for (int i = 0; i < 4; ++i) {
    for (int k = 0; k < 8; ++k) out[i * 8 + k] = (uchar)(r[i] >> (56 - 8 * k));
  }
}

// SHA-256 of the 51-byte OpenSSH blob string("ssh-ed25519") || string(pub).
inline void Sha256Blob(thread const uchar* pub, thread uint* out) {
  uchar blob[64];
  const uchar head[19] = {0,   0,   0,   11,  's', 's', 'h', '-', 'e', 'd',
                          '2', '5', '5', '1', '9', 0,   0,   0,   32};
  for (int i = 0; i < 19; ++i) blob[i] = head[i];
  for (int i = 0; i < 32; ++i) blob[19 + i] = pub[i];
  blob[51] = 0x80;
  for (int i = 52; i < 62; ++i) blob[i] = 0;
  blob[62] = (51 * 8) >> 8;
  blob[63] = (51 * 8) & 0xff;
  uint w[16];
  for (int i = 0; i < 16; ++i) {
    w[i] = ((uint)blob[i * 4] << 24) | ((uint)blob[i * 4 + 1] << 16) |
           ((uint)blob[i * 4 + 2] << 8) | (uint)blob[i * 4 + 3];
  }
  uint a = kH256[0], b = kH256[1], c = kH256[2], d = kH256[3];
  uint e = kH256[4], f = kH256[5], g = kH256[6], h = kH256[7];
  for (int i = 0; i < 64; ++i) {
    uint wi;
    if (i < 16) {
      wi = w[i];
    } else {
      uint w15 = w[(i - 15) & 15];
      uint w2 = w[(i - 2) & 15];
      uint s0 = Rotr32(w15, 7) ^ Rotr32(w15, 18) ^ (w15 >> 3);
      uint s1 = Rotr32(w2, 17) ^ Rotr32(w2, 19) ^ (w2 >> 10);
      wi = w[i & 15] + s0 + w[(i - 7) & 15] + s1;
      w[i & 15] = wi;
    }
    uint big_s1 = Rotr32(e, 6) ^ Rotr32(e, 11) ^ Rotr32(e, 25);
    uint ch = (e & f) ^ (~e & g);
    uint t1 = h + big_s1 + ch + kK256[i] + wi;
    uint big_s0 = Rotr32(a, 2) ^ Rotr32(a, 13) ^ Rotr32(a, 22);
    uint maj = (a & b) ^ (a & c) ^ (b & c);
    uint t2 = big_s0 + maj;
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }
  out[0] = a + kH256[0];
  out[1] = b + kH256[1];
  out[2] = c + kH256[2];
  out[3] = d + kH256[3];
  out[4] = e + kH256[4];
  out[5] = f + kH256[5];
  out[6] = g + kH256[6];
  out[7] = h + kH256[7];
}

// ---------------------------------------------------------------------------
// Fixed-base table.
//
// Row i, column j holds j * 2^(WBITS * i) * B in precomputed affine form, so a
// scalar multiplication is 256 / WBITS mixed additions and no doublings.
// ---------------------------------------------------------------------------

constant int kWindows = 256 / WBITS;
constant uint kColumns = 1u << WBITS;

// Thread i writes 2^(WBITS * i) * B in extended coordinates (40 ints).
kernel void RowBases(device int* rows [[buffer(0)]],
                     uint gid [[thread_position_in_grid]]) {
  if (gid >= (uint)kWindows) return;
  Point p;
  p.x = FeConst(kBaseX);
  p.y = FeConst(kBaseY);
  p.z = FeOne();
  p.t = FeMul(p.x, p.y);
  for (uint i = 0; i < gid * WBITS; ++i) p = PointDouble(p);
  StorePoint(p, rows + gid * 40);
}

kernel void BuildTable(device const int* rows [[buffer(0)]],
                       device int* table [[buffer(1)]],
                       uint gid [[thread_position_in_grid]]) {
  uint row = gid >> WBITS;
  uint column = gid & (kColumns - 1);
  device int* out = table + gid * 30;
  if (column == 0) {
    FeStore(FeOne(), out);
    FeStore(FeOne(), out + 10);
    FeStore(FeZero(), out + 20);
    return;
  }
  Point base = LoadPoint(rows + row * 40);
  Point acc = PointIdentity();
  for (int bit = WBITS - 1; bit >= 0; --bit) {
    acc = PointDouble(acc);
    if ((column >> bit) & 1) acc = PointAdd(acc, base);
  }
  Fe zi = FeInvert(acc.z);
  Fe x = FeMul(acc.x, zi);
  Fe y = FeMul(acc.y, zi);
  FeStore(FeAdd(y, x), out);
  FeStore(FeSub(y, x), out + 10);
  FeStore(FeMul(FeMul(x, y), FeConst(kD2)), out + 20);
}

// ---------------------------------------------------------------------------
// Key derivation and search.
// ---------------------------------------------------------------------------

// Seed = base with the 32-bit key index XORed into its first four bytes.
inline void MakeSeed(device const uchar* base, uint index, thread uchar* seed) {
  for (int i = 0; i < 32; ++i) seed[i] = base[i];
  for (int i = 0; i < 4; ++i) seed[i] ^= (uchar)(index >> (8 * i));
}

// [clamp(SHA-512(seed)[0..32])] B, as RFC 8032 derives the public key.
inline Point ScalarMultBase(thread const uchar* seed, device const int* table) {
  uchar a[32];
  Sha512Seed(seed, a);
  a[0] &= 248;
  a[31] &= 127;
  a[31] |= 64;
  Point p = PointIdentity();
  for (int i = 0; i < kWindows; ++i) {
#if WBITS == 16
    uint column = (uint)a[2 * i] | ((uint)a[2 * i + 1] << 8);
#else
    uint column = a[i];
#endif
    device const int* q = table + ((uint)i * kColumns + column) * 30;
    p = PointAddPrecomp(p, q, i < kWindows - 1);
  }
  return p;
}

inline void Digest(Point p, Fe z_inverse, thread uint* digest) {
  Fe x = FeMul(p.x, z_inverse);
  Fe y = FeMul(p.y, z_inverse);
  uchar pub[32];
  uchar x_bytes[32];
  FeToBytes(y, pub);
  FeToBytes(x, x_bytes);
  pub[31] ^= (x_bytes[0] & 1) << 7;
  Sha256Blob(pub, digest);
}

// Derives KEYS_PER_THREAD keys and shares one field inversion between them
// (Montgomery's trick), then hands each fingerprint digest to `visit`, a
// functor called as visit(key_index, digest).
template <typename Visitor>
inline void ForEachDigest(device const uchar* base, device const int* table,
                          uint gid, Visitor visit) {
  Point points[KEYS_PER_THREAD];
  Fe prefix[KEYS_PER_THREAD];
  for (int k = 0; k < KEYS_PER_THREAD; ++k) {
    uchar seed[32];
    MakeSeed(base, gid * KEYS_PER_THREAD + k, seed);
    points[k] = ScalarMultBase(seed, table);
    prefix[k] = k == 0 ? points[0].z : FeMul(prefix[k - 1], points[k].z);
  }
  Fe inverse = FeInvert(prefix[KEYS_PER_THREAD - 1]);
  for (int k = KEYS_PER_THREAD - 1; k >= 0; --k) {
    Fe z_inverse = k == 0 ? inverse : FeMul(inverse, prefix[k - 1]);
    if (k > 0) inverse = FeMul(inverse, points[k].z);
    uint digest[8];
    Digest(points[k], z_inverse, digest);
    visit(gid * KEYS_PER_THREAD + k, digest);
  }
}

// Base64 character `position` (0..42) of the unpadded fingerprint, as a 6-bit
// value. The last character carries only 4 digest bits followed by 2 zeros.
inline uint Sextet(thread const uint* digest, uint position) {
  uint bit = 6 * position;
  uint word = bit >> 5;
  uint offset = bit & 31;
  ulong v = ((ulong)digest[word] << 32) | (word < 7 ? digest[word + 1] : 0u);
  return (uint)(v >> (58 - offset)) & 63;
}

struct DigestWriter {
  device uint* out;

  void operator()(uint index, thread uint* digest) const {
    for (int i = 0; i < 8; ++i) out[index * 8 + i] = digest[i];
  }
};

kernel void Digests(device const uchar* base [[buffer(0)]],
                    device const int* table [[buffer(1)]],
                    device uint* out [[buffer(2)]],
                    uint gid [[thread_position_in_grid]]) {
  ForEachDigest(base, table, gid, DigestWriter{out});
}

struct SearchParams {
  uint length;       // Number of pattern characters.
  uint first_start;  // Fingerprint positions the pattern may start at.
  uint last_start;
};

// masks[i] has bit v set when base64 value v is allowed for pattern char i.
// result[0] counts matches, result[1] holds the first matching key index.
struct Matcher {
  device const ulong* masks;
  constant SearchParams* params;
  device atomic_uint* result;

  void operator()(uint index, thread uint* digest) const {
    for (uint start = params->first_start; start <= params->last_start;
         ++start) {
      bool match = true;
      for (uint i = 0; i < params->length && match; ++i) {
        match = ((masks[i] >> Sextet(digest, start + i)) & 1) != 0;
      }
      if (match) {
        if (atomic_fetch_add_explicit(&result[0], 1, memory_order_relaxed) ==
            0) {
          atomic_store_explicit(&result[1], index, memory_order_relaxed);
        }
        return;
      }
    }
  }
};

kernel void Search(device const uchar* base [[buffer(0)]],
                   device const int* table [[buffer(1)]],
                   device const ulong* masks [[buffer(2)]],
                   constant SearchParams* params [[buffer(3)]],
                   device atomic_uint* result [[buffer(4)]],
                   uint gid [[thread_position_in_grid]]) {
  ForEachDigest(base, table, gid, Matcher{masks, params, result});
}
