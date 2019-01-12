package main

import (
    "fmt"
    // "io/ioutil"
    // m "math"
    // "os"
    // "strconv"
    // "reflect"
    "math/big"
    elliptic "crypto/elliptic"
    rand "crypto/rand"
    "crypto/sha256"
)

var s256 *elliptic.CurveParams
var g1 *elliptic.CurveParams
var g2 *elliptic.CurveParams

func initS256() {
  // See SEC 2 section 2.7.1
  // curve parameters taken from:
  // http://www.secg.org/collateral/sec2_final.pdf
  s256 = &elliptic.CurveParams{Name: "secp256k1"}
  s256.P, _ = new(big.Int).SetString("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 0)
  s256.N, _ = new(big.Int).SetString("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 0)
  s256.A = new(big.Int)
  s256.B, _ = new(big.Int).SetString("0x0000000000000000000000000000000000000000000000000000000000000007", 0)
  s256.Gx, _ = new(big.Int).SetString("0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 0)
  s256.Gy, _ = new(big.Int).SetString("0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 0)
  s256.BitSize = 256
}

func initBLS12_381_G1() {
  g1 = &elliptic.CurveParams{Name: "BLS12-381 G1"}
  g1.P, _ = new(big.Int).SetString("0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab", 0)
  g1.N, _ = new(big.Int).SetString("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 0)
  g1.B, _ = new(big.Int).SetString("0x0000000000000000000000000000000000000000000000000000000000000004", 0)
  g1.A, _ = new(big.Int).SetString("0", 0)
  // g1.Gx, _ = new(big.Int).SetString("0x17F1D3A73197D7942695638C4FA9AC0FC3688C4F9774B905A14E3A3F171BAC586C55E83FF97A1AEFFB3AF00ADB22C6BB", 0)
  // g1.Gy, _ = new(big.Int).SetString("0x8B3F481E3AAA0F1A09E30ED741D8AE4FCF5E095D5D00AF600DB18CB2C04B3EDD03CC744A2888AE40CAA232946C5E7E1", 0)
  g1.Gx, _ = new(big.Int).SetString("3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507", 10)
  g1.Gy, _ = new(big.Int).SetString("1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569", 10)
  g1.BitSize = 381
}

func initBLS12_381_G2() {
  g2 = &elliptic.CurveParams{Name: "BLS12-381 G2"}
  g2.P, _ = new(big.Int).SetString("0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab", 0)
  g2.N, _ = new(big.Int).SetString("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 0)
  g2.B, _ = new(big.Int).SetString("0x0000000000000000000000000000000000000000000000000000000000000004", 0)
  g1.A, _ = new(big.Int).SetString("0", 0)
  // g2.Gx, _ = new(big.Int).SetString("0x13E02B6052719F607DACD3A088274F65596BD0D09920B61AB5DA61BBDC7F5049334CF11213945D57E5AC7D055D042B7E", 0)
  // g2.Gy, _ = new(big.Int).SetString("0x606C4A02EA734CC32ACD2B02BC28B99CB3E287E85A763AF267492AB572E99AB3F370D275CEC1DA1AAA9075FF05F79BE", 0)
  g2.Gx, _ = new(big.Int).SetString("3059144344244213709971259814753781636986470325476647558659373206291635324768958432433509563104347017837885763365758", 10)
  g2.Gy, _ = new(big.Int).SetString("927553665492332455747201965776037880757740193453592970025027978793976877002675564980949289727957565575433344219582", 10)
  g2.BitSize = 381
}

func S256() elliptic.Curve {
	return s256
}
func BLS12_381_G1() elliptic.Curve {
	return g1
}
func BLS12_381_G2() elliptic.Curve {
	return g2
}

// type Key struct {
//   priv []byte
//   x big.Int
//   y big.Int
// }

func H(curve elliptic.Curve, x []byte) (*big.Int, *big.Int) {
  h := sha256.New()
  h.Write([]byte{0})
	h.Write(x)
  z := h.Sum(nil)

  return curve.ScalarBaseMult(z)
}

func PadM(M []byte) []byte {
  if len(M) % 2 == 0 {
    return M
  } else {
    return append(M, 0)
  }
}

// func VectorizeM([]byte) [][]byte {
//
// }

func main() {
  initS256()
  initBLS12_381_G1()
  initBLS12_381_G2()
  G1 := BLS12_381_G1()
  secp256k1 := S256()
  p256 := elliptic.P256()
  p384 := elliptic.P384()
  // G2 := BLS12_381_G2()
  // s1, x1, y1, _ := elliptic.GenerateKey(G1, rand.Reader)
  // s2, x2, y2, _ := elliptic.GenerateKey(G2, rand.Reader)
  s1, _, _, err := elliptic.GenerateKey(G1, rand.Reader)
  test_key, _, _, _ := elliptic.GenerateKey(secp256k1, rand.Reader)
  test_key2, _, _, _ := elliptic.GenerateKey(p256, rand.Reader)
  test_key3, _, _, _ := elliptic.GenerateKey(p384, rand.Reader)

  if err != nil {
    fmt.Println(err)
  }
  // s2, _, _, _ := elliptic.GenerateKey(G2, rand.Reader)
  // alpha, _, _, _ := elliptic.GenerateKey(G1, rand.Reader)

  // Q1x, Q1y := G2.ScalarBaseMult(s1)
  // Q2x, Q2y := G2.ScalarBaseMult(s2)

  // var alphas [][]byte

  fmt.Println(G1)
  fmt.Println(secp256k1)
  fmt.Println(p384)

  var M [][][]byte
  var m1 [][]byte
  var m2 [][]byte

  d := 65
  t := 4
  lorem := PadM([]byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Maecenas quis commodo dui, accumsan laoreet mauris. Duis a urna id justo mattis mollis. Vestibulum rhoncus, eros quis tincidunt consequat, ex eros commodo elit, eget consectetur eros ligula non urna. Cras non malesuada mauris. Mauris eu hendrerit leo. Orci varius natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. Sed vel magna lacus. Ut at dui ut odio bibendum consectetur nec eu libero. Morbi in pretium magna. In eget hendrerit ipsum."))

  ax, ay := G1.ScalarBaseMult(s1)
  isonp := G1.IsOnCurve(ax, ay)
  fmt.Println(isonp)

  bx, by := secp256k1.ScalarBaseMult(test_key)
  isonp2 := secp256k1.IsOnCurve(bx, by)
  fmt.Println(isonp2)

  cx, cy := p256.ScalarBaseMult(test_key2)
  isonp3 := p256.IsOnCurve(cx, cy)
  fmt.Println(isonp3)

  dx, dy := p384.ScalarBaseMult(test_key3)
  isonp4 := p384.IsOnCurve(dx, dy)
  fmt.Println(isonp4)

  // for i := 1; i < t + 1; i++ {
  //   // tmpAlpha := new(big.Int).Exp(new(big.Int).SetBytes(alpha), big.NewInt(int64(i)), nil)
  //   // ax, ay := G1.ScalarBaseMult(tmpAlpha.Bytes())
  //   ax, ay := G1.ScalarBaseMult(alpha)
  //
  //   isonp := G1.IsOnCurve(ax, ay)
  //   fmt.Println(isonp)
  //
  //   alphas = append(alphas, elliptic.Marshal(G1, ax, ay))
  // }

  // fmt.Println(alphas)

  row1 := lorem[0:d * t]
  row2 := lorem[d * t:]

  m11 := row1[0:d]
  m12 := row1[d:2 * d]
  m13 := row1[2 * d:3 * d]
  m14 := row1[3 * d:4 * d]

  m21 := row2[0:d]
  m22 := row2[d:2 * d]
  m23 := row2[2 * d:3 * d]
  m24 := row2[3 * d:4 * d]

  m1 = append(m1, m11, m12, m13, m14)
  m2 = append(m2, m21, m22, m23, m24)

  M = append(M, m1, m2)

  // fmt.Println(lorem)
  // Tag(G1, s1, s2, "1", M[0], "idstring", alphas)
}

func Tag(curve elliptic.Curve, s1 []byte, s2 []byte, index string, mi [][]byte, id string, alphas [][]byte) {

  // var sum big.Int
  // Bx, By := H(curve, []byte(id + index))
  p1, p2 := elliptic.Unmarshal(curve, alphas[0])
  // test := curve.IsOnCurve(ajx, ajy)
  fmt.Println(p1, p2)
  // ftx, fty := curve.ScalarMult(Bx, By, s1)
  //
  //
  // sx := big.NewInt(0)
  // sy := big.NewInt(0)
  // for j := 0; j < len(mi); j++ {
  //   ajx, ajy := elliptic.Unmarshal(curve, alphas[j])
  //   x, y := curve.ScalarMult(ajx, ajy, mi[j])
  //
  //   sx, sy = curve.Add(sx, sy, x, y)
  // }
  //
  // fmt.Println(ftx, fty)
  // fmt.Println(sx, sy)
}
