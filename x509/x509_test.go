// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"gitee.com/zhaochuninhefei/gmgo/ecdsa_ext"
	"gitee.com/zhaochuninhefei/gmgo/utils"
	"gitee.com/zhaochuninhefei/zcgolog/zclog"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"gitee.com/zhaochuninhefei/gmgo/internal/testenv"
	"gitee.com/zhaochuninhefei/gmgo/sm2"
)

func TestMain(m *testing.M) {
	zclog.Level = zclog.LOG_LEVEL_DEBUG
	zclog.Debug("TestMain")
	os.Exit(m.Run())
}

func TestParsePKCS1PrivateKey(t *testing.T) {
	block, _ := pem.Decode([]byte(pemPrivateKey))
	priv, err := ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Errorf("Failed to parse private key: %s", err)
		return
	}
	if priv.PublicKey.N.Cmp(rsaPrivateKey.PublicKey.N) != 0 ||
		priv.PublicKey.E != rsaPrivateKey.PublicKey.E ||
		priv.D.Cmp(rsaPrivateKey.D) != 0 ||
		priv.Primes[0].Cmp(rsaPrivateKey.Primes[0]) != 0 ||
		priv.Primes[1].Cmp(rsaPrivateKey.Primes[1]) != 0 {
		t.Errorf("got:%+v want:%+v", priv, rsaPrivateKey)
	}

	// This private key includes an invalid prime that
	// rsa.PrivateKey.Validate should reject.
	data := []byte("0\x16\x02\x00\x02\x02\u007f\x00\x02\x0200\x02\x0200\x02\x02\x00\x01\x02\x02\u007f\x00")
	if _, err := ParsePKCS1PrivateKey(data); err == nil {
		t.Errorf("parsing invalid private key did not result in an error")
	}
}

func TestPKCS1MismatchPublicKeyFormat(t *testing.T) {

	const pkixPublicKey = "30820122300d06092a864886f70d01010105000382010f003082010a0282010100dd5a0f37d3ca5232852ccc0e81eebec270e2f2c6c44c6231d852971a0aad00aa7399e9b9de444611083c59ea919a9d76c20a7be131a99045ec19a7bb452d647a72429e66b87e28be9e8187ed1d2a2a01ef3eb2360706bd873b07f2d1f1a72337aab5ec94e983e39107f52c480d404915e84d75a3db2cfd601726a128cb1d7f11492d4bdb53272e652276667220795c709b8a9b4af6489cbf48bb8173b8fb607c834a71b6e8bf2d6aab82af3c8ad7ce16d8dcf58373a6edc427f7484d09744d4c08f4e19ed07adbf6cb31243bc5d0d1145e77a08a6fc5efd208eca67d6abf2d6f38f58b6fdd7c28774fb0cc03fc4935c6e074842d2e1479d3d8787249258719f90203010001"
	const errorContains = "use ParsePKIXPublicKey instead"
	derBytes, _ := hex.DecodeString(pkixPublicKey)
	_, err := ParsePKCS1PublicKey(derBytes)
	if err != nil && !strings.Contains(err.Error(), errorContains) {
		t.Errorf("expected error containing %q, got %s", errorContains, err)
	}
}

func testParsePKIXPublicKey(t *testing.T, pemBytes string) (pub interface{}) {
	block, _ := pem.Decode([]byte(pemBytes))
	pub, err := ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse public key: %s", err)
	}

	pubBytes2, err := MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Errorf("Failed to marshal public key for the second time: %s", err)
		return
	}
	if !bytes.Equal(pubBytes2, block.Bytes) {
		t.Errorf("Reserialization of public key didn't match. got %x, want %x", pubBytes2, block.Bytes)
	}
	return
}

func TestParsePKIXPublicKey(t *testing.T) {
	t.Run("RSA", func(t *testing.T) {
		pub := testParsePKIXPublicKey(t, pemPublicKey)
		_, ok := pub.(*rsa.PublicKey)
		if !ok {
			t.Errorf("Value returned from ParsePKIXPublicKey was not an RSA public key")
		}
	})
	t.Run("Ed25519", func(t *testing.T) {
		pub := testParsePKIXPublicKey(t, pemEd25519Key)
		_, ok := pub.(ed25519.PublicKey)
		if !ok {
			t.Errorf("Value returned from ParsePKIXPublicKey was not an Ed25519 public key")
		}
	})
}

var pemPublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3VoPN9PKUjKFLMwOge6+
wnDi8sbETGIx2FKXGgqtAKpzmem53kRGEQg8WeqRmp12wgp74TGpkEXsGae7RS1k
enJCnma4fii+noGH7R0qKgHvPrI2Bwa9hzsH8tHxpyM3qrXslOmD45EH9SxIDUBJ
FehNdaPbLP1gFyahKMsdfxFJLUvbUycuZSJ2ZnIgeVxwm4qbSvZInL9Iu4FzuPtg
fINKcbbovy1qq4KvPIrXzhbY3PWDc6btxCf3SE0JdE1MCPThntB62/bLMSQ7xdDR
FF53oIpvxe/SCOymfWq/LW849Ytv3Xwod0+wzAP8STXG4HSELS4UedPYeHJJJYcZ
+QIDAQAB
-----END PUBLIC KEY-----
`

var pemPrivateKey = testingKey(`
-----BEGIN RSA TESTING KEY-----
MIICXAIBAAKBgQCxoeCUW5KJxNPxMp+KmCxKLc1Zv9Ny+4CFqcUXVUYH69L3mQ7v
IWrJ9GBfcaA7BPQqUlWxWM+OCEQZH1EZNIuqRMNQVuIGCbz5UQ8w6tS0gcgdeGX7
J7jgCQ4RK3F/PuCM38QBLaHx988qG8NMc6VKErBjctCXFHQt14lerd5KpQIDAQAB
AoGAYrf6Hbk+mT5AI33k2Jt1kcweodBP7UkExkPxeuQzRVe0KVJw0EkcFhywKpr1
V5eLMrILWcJnpyHE5slWwtFHBG6a5fLaNtsBBtcAIfqTQ0Vfj5c6SzVaJv0Z5rOd
7gQF6isy3t3w9IF3We9wXQKzT6q5ypPGdm6fciKQ8RnzREkCQQDZwppKATqQ41/R
vhSj90fFifrGE6aVKC1hgSpxGQa4oIdsYYHwMzyhBmWW9Xv/R+fPyr8ZwPxp2c12
33QwOLPLAkEA0NNUb+z4ebVVHyvSwF5jhfJxigim+s49KuzJ1+A2RaSApGyBZiwS
rWvWkB471POAKUYt5ykIWVZ83zcceQiNTwJBAMJUFQZX5GDqWFc/zwGoKkeR49Yi
MTXIvf7Wmv6E++eFcnT461FlGAUHRV+bQQXGsItR/opIG7mGogIkVXa3E1MCQARX
AAA7eoZ9AEHflUeuLn9QJI/r0hyQQLEtrpwv6rDT1GCWaLII5HJ6NUFVf4TTcqxo
6vdM4QGKTJoO+SaCyP0CQFdpcxSAuzpFcKv0IlJ8XzS/cy+mweCMwyJ1PFEc4FX6
wg/HcAJWY60xZTJDFN+Qfx8ZQvBEin6c2/h+zZi5IVY=
-----END RSA TESTING KEY-----
`)

// pemEd25519Key is the example from RFC 8410, Secrion 4.
var pemEd25519Key = `
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=
-----END PUBLIC KEY-----
`

func TestPKIXMismatchPublicKeyFormat(t *testing.T) {

	const pkcs1PublicKey = "308201080282010100817cfed98bcaa2e2a57087451c7674e0c675686dc33ff1268b0c2a6ee0202dec710858ee1c31bdf5e7783582e8ca800be45f3275c6576adc35d98e26e95bb88ca5beb186f853b8745d88bc9102c5f38753bcda519fb05948d5c77ac429255ff8aaf27d9f45d1586e95e2e9ba8a7cb771b8a09dd8c8fed3f933fd9b439bc9f30c475953418ef25f71a2b6496f53d94d39ce850aa0cc75d445b5f5b4f4ee4db78ab197a9a8d8a852f44529a007ac0ac23d895928d60ba538b16b0b087a7f903ed29770e215019b77eaecc360f35f7ab11b6d735978795b2c4a74e5bdea4dc6594cd67ed752a108e666729a753ab36d6c4f606f8760f507e1765be8cd744007e629020103"
	const errorContains = "use ParsePKCS1PublicKey instead"
	derBytes, _ := hex.DecodeString(pkcs1PublicKey)
	_, err := ParsePKIXPublicKey(derBytes)
	if err != nil && !strings.Contains(err.Error(), errorContains) {
		t.Errorf("expected error containing %q, got %s", errorContains, err)
	}
}

var testPrivateKey *rsa.PrivateKey

func init() {
	block, _ := pem.Decode([]byte(pemPrivateKey))

	var err error
	if testPrivateKey, err = ParsePKCS1PrivateKey(block.Bytes); err != nil {
		panic("Failed to parse private key: " + err.Error())
	}
}

func bigFromString(s string) *big.Int {
	ret := new(big.Int)
	ret.SetString(s, 10)
	return ret
}

func fromBase10(base10 string) *big.Int {
	i := new(big.Int)
	i.SetString(base10, 10)
	return i
}

//goland:noinspection GoUnusedFunction
func bigFromHexString(s string) *big.Int {
	ret := new(big.Int)
	ret.SetString(s, 16)
	return ret
}

var rsaPrivateKey = &rsa.PrivateKey{
	PublicKey: rsa.PublicKey{
		N: bigFromString("124737666279038955318614287965056875799409043964547386061640914307192830334599556034328900586693254156136128122194531292927142396093148164407300419162827624945636708870992355233833321488652786796134504707628792159725681555822420087112284637501705261187690946267527866880072856272532711620639179596808018872997"),
		E: 65537,
	},
	D: bigFromString("69322600686866301945688231018559005300304807960033948687567105312977055197015197977971637657636780793670599180105424702854759606794705928621125408040473426339714144598640466128488132656829419518221592374964225347786430566310906679585739468938549035854760501049443920822523780156843263434219450229353270690889"),
	Primes: []*big.Int{
		bigFromString("11405025354575369741595561190164746858706645478381139288033759331174478411254205003127028642766986913445391069745480057674348716675323735886284176682955723"),
		bigFromString("10937079261204603443118731009201819560867324167189758120988909645641782263430128449826989846631183550578761324239709121189827307416350485191350050332642639"),
	},
}

func TestMarshalRSAPrivateKey(t *testing.T) {
	priv := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: fromBase10("16346378922382193400538269749936049106320265317511766357599732575277382844051791096569333808598921852351577762718529818072849191122419410612033592401403764925096136759934497687765453905884149505175426053037420486697072448609022753683683718057795566811401938833367954642951433473337066311978821180526439641496973296037000052546108507805269279414789035461158073156772151892452251106173507240488993608650881929629163465099476849643165682709047462010581308719577053905787496296934240246311806555924593059995202856826239801816771116902778517096212527979497399966526283516447337775509777558018145573127308919204297111496233"),
			E: 3,
		},
		D: fromBase10("10897585948254795600358846499957366070880176878341177571733155050184921896034527397712889205732614568234385175145686545381899460748279607074689061600935843283397424506622998458510302603922766336783617368686090042765718290914099334449154829375179958369993407724946186243249568928237086215759259909861748642124071874879861299389874230489928271621259294894142840428407196932444474088857746123104978617098858619445675532587787023228852383149557470077802718705420275739737958953794088728369933811184572620857678792001136676902250566845618813972833750098806496641114644760255910789397593428910198080271317419213080834885003"),
		Primes: []*big.Int{
			fromBase10("1025363189502892836833747188838978207017355117492483312747347695538428729137306368764177201532277413433182799108299960196606011786562992097313508180436744488171474690412562218914213688661311117337381958560443"),
			fromBase10("3467903426626310123395340254094941045497208049900750380025518552334536945536837294961497712862519984786362199788654739924501424784631315081391467293694361474867825728031147665777546570788493758372218019373"),
			fromBase10("4597024781409332673052708605078359346966325141767460991205742124888960305710298765592730135879076084498363772408626791576005136245060321874472727132746643162385746062759369754202494417496879741537284589047"),
		},
	}

	derBytes := MarshalPKCS1PrivateKey(priv)

	priv2, err := ParsePKCS1PrivateKey(derBytes)
	if err != nil {
		t.Errorf("error parsing serialized key: %s", err)
		return
	}
	if priv.PublicKey.N.Cmp(priv2.PublicKey.N) != 0 ||
		priv.PublicKey.E != priv2.PublicKey.E ||
		priv.D.Cmp(priv2.D) != 0 ||
		len(priv2.Primes) != 3 ||
		priv.Primes[0].Cmp(priv2.Primes[0]) != 0 ||
		priv.Primes[1].Cmp(priv2.Primes[1]) != 0 ||
		priv.Primes[2].Cmp(priv2.Primes[2]) != 0 {
		t.Errorf("got:%+v want:%+v", priv, priv2)
	}
}

func TestMarshalRSAPublicKey(t *testing.T) {
	pub := &rsa.PublicKey{
		N: fromBase10("16346378922382193400538269749936049106320265317511766357599732575277382844051791096569333808598921852351577762718529818072849191122419410612033592401403764925096136759934497687765453905884149505175426053037420486697072448609022753683683718057795566811401938833367954642951433473337066311978821180526439641496973296037000052546108507805269279414789035461158073156772151892452251106173507240488993608650881929629163465099476849643165682709047462010581308719577053905787496296934240246311806555924593059995202856826239801816771116902778517096212527979497399966526283516447337775509777558018145573127308919204297111496233"),
		E: 3,
	}
	derBytes := MarshalPKCS1PublicKey(pub)
	pub2, err := ParsePKCS1PublicKey(derBytes)
	if err != nil {
		t.Errorf("ParsePKCS1PublicKey: %s", err)
	}
	if pub.N.Cmp(pub2.N) != 0 || pub.E != pub2.E {
		t.Errorf("ParsePKCS1PublicKey = %+v, want %+v", pub, pub2)
	}

	// It's never been documented that asn1.Marshal/Unmarshal on rsa.PublicKey works,
	// but it does, and we know of code that depends on it.
	// Lock that in, even though we'd prefer that people use MarshalPKCS1PublicKey and ParsePKCS1PublicKey.
	derBytes2, err := asn1.Marshal(*pub)
	if err != nil {
		t.Errorf("Marshal(rsa.PublicKey): %v", err)
	} else if !bytes.Equal(derBytes, derBytes2) {
		t.Errorf("Marshal(rsa.PublicKey) = %x, want %x", derBytes2, derBytes)
	}
	pub3 := new(rsa.PublicKey)
	rest, err := asn1.Unmarshal(derBytes, pub3)
	if err != nil {
		t.Errorf("Unmarshal(rsa.PublicKey): %v", err)
	}
	if len(rest) != 0 || pub.N.Cmp(pub3.N) != 0 || pub.E != pub3.E {
		t.Errorf("Unmarshal(rsa.PublicKey) = %+v, %q want %+v, %q", pub, rest, pub2, []byte(nil))
	}

	publicKeys := []struct {
		derBytes          []byte
		expectedErrSubstr string
	}{
		{
			derBytes: []byte{
				0x30, 6, // SEQUENCE, 6 bytes
				0x02, 1, // INTEGER, 1 byte
				17,
				0x02, 1, // INTEGER, 1 byte
				3, // 3
			},
		}, {
			derBytes: []byte{
				0x30, 6, // SEQUENCE
				0x02, 1, // INTEGER, 1 byte
				0xff,    // -1
				0x02, 1, // INTEGER, 1 byte
				3,
			},
			expectedErrSubstr: "zero or negative",
		}, {
			derBytes: []byte{
				0x30, 6, // SEQUENCE
				0x02, 1, // INTEGER, 1 byte
				17,
				0x02, 1, // INTEGER, 1 byte
				0xff, // -1
			},
			expectedErrSubstr: "zero or negative",
		}, {
			derBytes: []byte{
				0x30, 6, // SEQUENCE
				0x02, 1, // INTEGER, 1 byte
				17,
				0x02, 1, // INTEGER, 1 byte
				3,
				1,
			},
			expectedErrSubstr: "trailing data",
		}, {
			derBytes: []byte{
				0x30, 9, // SEQUENCE
				0x02, 1, // INTEGER, 1 byte
				17,
				0x02, 4, // INTEGER, 4 bytes
				0x7f, 0xff, 0xff, 0xff,
			},
		}, {
			derBytes: []byte{
				0x30, 10, // SEQUENCE
				0x02, 1, // INTEGER, 1 byte
				17,
				0x02, 5, // INTEGER, 5 bytes
				0x00, 0x80, 0x00, 0x00, 0x00,
			},
			// On 64-bit systems, encoding/asn1 will accept the
			// public exponent, but ParsePKCS1PublicKey will return
			// an error. On 32-bit systems, encoding/asn1 will
			// return the error. The common substring of both error
			// is the word “large”.
			expectedErrSubstr: "large",
		},
	}

	for i, test := range publicKeys {
		shouldFail := len(test.expectedErrSubstr) > 0
		pub, err := ParsePKCS1PublicKey(test.derBytes)
		if shouldFail {
			if err == nil {
				t.Errorf("#%d: unexpected success, got %#v", i, pub)
			} else if !strings.Contains(err.Error(), test.expectedErrSubstr) {
				t.Errorf("#%d: expected error containing %q, got %s", i, test.expectedErrSubstr, err)
			}
		} else {
			if err != nil {
				t.Errorf("#%d: unexpected failure: %s", i, err)
				continue
			}
			reserialized := MarshalPKCS1PublicKey(pub)
			if !bytes.Equal(reserialized, test.derBytes) {
				t.Errorf("#%d: failed to reserialize: got %x, expected %x", i, reserialized, test.derBytes)
			}
		}
	}
}

type matchHostnamesTest struct {
	pattern, host string
	ok            bool
}

var matchHostnamesTests = []matchHostnamesTest{
	{"a.b.c", "a.b.c", true},
	{"a.b.c", "b.b.c", false},
	{"", "b.b.c", false},
	{"a.b.c", "", false},
	{"example.com", "example.com", true},
	{"example.com", "www.example.com", false},
	{"*.example.com", "example.com", false},
	{"*.example.com", "www.example.com", true},
	{"*.example.com", "www.example.com.", true},
	{"*.example.com", "xyz.www.example.com", false},
	{"*.example.com", "https://www.example.com", false}, // Issue 27591
	{"*.example..com", "www.example..com", false},
	{"www.example..com", "www.example..com", true},
	{"*.*.example.com", "xyz.www.example.com", false},
	{"*.www.*.com", "xyz.www.example.com", false},
	{"*bar.example.com", "foobar.example.com", false},
	{"f*.example.com", "foobar.example.com", false},
	{"www.example.com", "*.example.com", false},
	{"", ".", false},
	{".", "", false},
	{".", ".", false},
	{"example.com", "example.com.", true},
	{"example.com.", "example.com", false},
	{"example.com.", "example.com.", true}, // perfect matches allow trailing dots in patterns
	{"*.com.", "example.com.", false},
	{"*.com.", "example.com", false},
	{"*.com", "example.com", true},
	{"*.com", "example.com.", true},
	{"foo:bar", "foo:bar", true},
	{"*.foo:bar", "xxx.foo:bar", false},
	{"*.2.3.4", "1.2.3.4", false},
	{"*.2.3.4", "[1.2.3.4]", false},
	{"*:4860:4860::8888", "2001:4860:4860::8888", false},
	{"*:4860:4860::8888", "[2001:4860:4860::8888]", false},
	{"2001:4860:4860::8888", "2001:4860:4860::8888", false},
	{"2001:4860:4860::8888", "[2001:4860:4860::8888]", false},
	{"[2001:4860:4860::8888]", "2001:4860:4860::8888", false},
	{"[2001:4860:4860::8888]", "[2001:4860:4860::8888]", false},
}

func TestMatchHostnames(t *testing.T) {
	for i, test := range matchHostnamesTests {
		c := &Certificate{DNSNames: []string{test.pattern}}
		r := c.VerifyHostname(test.host) == nil
		if r != test.ok {
			t.Errorf("#%d mismatch got: %t want: %t when matching '%s' against '%s'", i, r, test.ok, test.host, test.pattern)
		}
	}
}

func TestMatchIP(t *testing.T) {
	// Check that pattern matching is working.
	c := &Certificate{
		DNSNames: []string{"*.foo.bar.baz"},
		Subject: pkix.Name{
			CommonName: "*.foo.bar.baz",
		},
	}
	err := c.VerifyHostname("quux.foo.bar.baz")
	if err != nil {
		t.Fatalf("VerifyHostname(quux.foo.bar.baz): %v", err)
	}

	// But check that if we change it to be matching against an IP address,
	// it is rejected.
	c = &Certificate{
		DNSNames: []string{"*.2.3.4"},
		Subject: pkix.Name{
			CommonName: "*.2.3.4",
		},
	}
	err = c.VerifyHostname("1.2.3.4")
	if err == nil {
		t.Fatalf("VerifyHostname(1.2.3.4) should have failed, did not")
	}

	c = &Certificate{
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	err = c.VerifyHostname("127.0.0.1")
	if err != nil {
		t.Fatalf("VerifyHostname(127.0.0.1): %v", err)
	}
	err = c.VerifyHostname("::1")
	if err != nil {
		t.Fatalf("VerifyHostname(::1): %v", err)
	}
	err = c.VerifyHostname("[::1]")
	if err != nil {
		t.Fatalf("VerifyHostname([::1]): %v", err)
	}
}

func TestCertificateParse(t *testing.T) {
	s, _ := base64.StdEncoding.DecodeString(certBytes)
	certs, err := ParseCertificates(s)
	if err != nil {
		t.Error(err)
	}
	if len(certs) != 2 {
		t.Errorf("Wrong number of certs: got %d want 2", len(certs))
		return
	}

	err = certs[0].CheckSignatureFrom(certs[1])
	if err != nil {
		t.Error(err)
	}

	if err := certs[0].VerifyHostname("mail.google.com"); err != nil {
		t.Error(err)
	}

	const expectedExtensions = 10
	if n := len(certs[0].Extensions); n != expectedExtensions {
		t.Errorf("want %d extensions, got %d", expectedExtensions, n)
	}
}

func TestCertificateEqualOnNil(t *testing.T) {
	cNonNil := new(Certificate)
	var cNil1, cNil2 *Certificate
	if !cNil1.Equal(cNil2) {
		t.Error("Nil certificates: cNil1 is not equal to cNil2")
	}
	if !cNil2.Equal(cNil1) {
		t.Error("Nil certificates: cNil2 is not equal to cNil1")
	}
	if cNil1.Equal(cNonNil) {
		t.Error("Unexpectedly cNil1 is equal to cNonNil")
	}
	if cNonNil.Equal(cNil1) {
		t.Error("Unexpectedly cNonNil is equal to cNil1")
	}
}

func TestMismatchedSignatureAlgorithm(t *testing.T) {
	der, _ := pem.Decode([]byte(rsaPSSSelfSignedPEM))
	if der == nil {
		t.Fatal("Failed to find PEM block")
	}

	cert, err := ParseCertificate(der.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	if err = cert.CheckSignature(ECDSAWithSHA256, nil, nil); err == nil {
		t.Fatal("CheckSignature unexpectedly return no error")
	}

	const expectedSubstring = " but have public key of type "
	if !strings.Contains(err.Error(), expectedSubstring) {
		t.Errorf("Expected error containing %q, but got %q", expectedSubstring, err)
	}
}

var certBytes = "MIIE0jCCA7qgAwIBAgIQWcvS+TTB3GwCAAAAAGEAWzANBgkqhkiG9w0BAQsFADBCMQswCQYD" +
	"VQQGEwJVUzEeMBwGA1UEChMVR29vZ2xlIFRydXN0IFNlcnZpY2VzMRMwEQYDVQQDEwpHVFMg" +
	"Q0EgMU8xMB4XDTIwMDQwMTEyNTg1NloXDTIwMDYyNDEyNTg1NlowaTELMAkGA1UEBhMCVVMx" +
	"EzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDU1vdW50YWluIFZpZXcxEzARBgNVBAoT" +
	"Ckdvb2dsZSBMTEMxGDAWBgNVBAMTD21haWwuZ29vZ2xlLmNvbTBZMBMGByqGSM49AgEGCCqG" +
	"SM49AwEHA0IABO+dYiPnkFl+cZVf6mrWeNp0RhQcJSBGH+sEJxjvc+cYlW3QJCnm57qlpFdd" +
	"pz3MPyVejvXQdM6iI1mEWP4C2OujggJmMIICYjAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAww" +
	"CgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUI6pZhnQ/lQgmPDwSKR2A54G7" +
	"AS4wHwYDVR0jBBgwFoAUmNH4bhDrz5vsYJ8YkBug630J/SswZAYIKwYBBQUHAQEEWDBWMCcG" +
	"CCsGAQUFBzABhhtodHRwOi8vb2NzcC5wa2kuZ29vZy9ndHMxbzEwKwYIKwYBBQUHMAKGH2h0" +
	"dHA6Ly9wa2kuZ29vZy9nc3IyL0dUUzFPMS5jcnQwLAYDVR0RBCUwI4IPbWFpbC5nb29nbGUu" +
	"Y29tghBpbmJveC5nb29nbGUuY29tMCEGA1UdIAQaMBgwCAYGZ4EMAQICMAwGCisGAQQB1nkC" +
	"BQMwLwYDVR0fBCgwJjAkoCKgIIYeaHR0cDovL2NybC5wa2kuZ29vZy9HVFMxTzEuY3JsMIIB" +
	"AwYKKwYBBAHWeQIEAgSB9ASB8QDvAHYAsh4FzIuizYogTodm+Su5iiUgZ2va+nDnsklTLe+L" +
	"kF4AAAFxNgmxKgAABAMARzBFAiEA12/OHdTGXQ3qHHC3NvYCyB8aEz/+ZFOLCAI7lhqj28sC" +
	"IG2/7Yz2zK6S6ai+dH7cTMZmoFGo39gtaTqtZAqEQX7nAHUAXqdz+d9WwOe1Nkh90EngMnqR" +
	"mgyEoRIShBh1loFxRVgAAAFxNgmxTAAABAMARjBEAiA7PNq+MFfv6O9mBkxFViS2TfU66yRB" +
	"/njcebWglLQjZQIgOyRKhxlEizncFRml7yn4Bg48ktXKGjo+uiw6zXEINb0wDQYJKoZIhvcN" +
	"AQELBQADggEBADM2Rh306Q10PScsolYMxH1B/K4Nb2WICvpY0yDPJFdnGjqCYym196TjiEvs" +
	"R6etfeHdyzlZj6nh82B4TVyHjiWM02dQgPalOuWQcuSy0OvLh7F1E7CeHzKlczdFPBTOTdM1" +
	"RDTxlvw1bAqc0zueM8QIAyEy3opd7FxAcGQd5WRIJhzLBL+dbbMOW/LTeW7cm/Xzq8cgCybN" +
	"BSZAvhjseJ1L29OlCTZL97IfnX0IlFQzWuvvHy7V2B0E3DHlzM0kjwkkCKDUUp/wajv2NZKC" +
	"TkhEyERacZRKc9U0ADxwsAzHrdz5+5zfD2usEV/MQ5V6d8swLXs+ko0X6swrd4YCiB8wggRK" +
	"MIIDMqADAgECAg0B47SaoY2KqYElaVC4MA0GCSqGSIb3DQEBCwUAMEwxIDAeBgNVBAsTF0ds" +
	"b2JhbFNpZ24gUm9vdCBDQSAtIFIyMRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYDVQQDEwpH" +
	"bG9iYWxTaWduMB4XDTE3MDYxNTAwMDA0MloXDTIxMTIxNTAwMDA0MlowQjELMAkGA1UEBhMC" +
	"VVMxHjAcBgNVBAoTFUdvb2dsZSBUcnVzdCBTZXJ2aWNlczETMBEGA1UEAxMKR1RTIENBIDFP" +
	"MTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANAYz0XUi83TnORA73603WkhG8nP" +
	"PI5MdbkPMRmEPZ48Ke9QDRCTbwWAgJ8qoL0SSwLhPZ9YFiT+MJ8LdHdVkx1L903hkoIQ9lGs" +
	"DMOyIpQPNGuYEEnnC52DOd0gxhwt79EYYWXnI4MgqCMS/9Ikf9Qv50RqW03XUGawr55CYwX7" +
	"4BzEY2Gvn2oz/2KXvUjZ03wUZ9x13C5p6PhteGnQtxAFuPExwjsk/RozdPgj4OxrGYoWxuPN" +
	"pM0L27OkWWA4iDutHbnGjKdTG/y82aSrvN08YdeTFZjugb2P4mRHIEAGTtesl+i5wFkSoUkl" +
	"I+TtcDQspbRjfPmjPYPRzW0krAcCAwEAAaOCATMwggEvMA4GA1UdDwEB/wQEAwIBhjAdBgNV" +
	"HSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4E" +
	"FgQUmNH4bhDrz5vsYJ8YkBug630J/SswHwYDVR0jBBgwFoAUm+IHV2ccHsBqBt5ZtJot39wZ" +
	"hi4wNQYIKwYBBQUHAQEEKTAnMCUGCCsGAQUFBzABhhlodHRwOi8vb2NzcC5wa2kuZ29vZy9n" +
	"c3IyMDIGA1UdHwQrMCkwJ6AloCOGIWh0dHA6Ly9jcmwucGtpLmdvb2cvZ3NyMi9nc3IyLmNy" +
	"bDA/BgNVHSAEODA2MDQGBmeBDAECAjAqMCgGCCsGAQUFBwIBFhxodHRwczovL3BraS5nb29n" +
	"L3JlcG9zaXRvcnkvMA0GCSqGSIb3DQEBCwUAA4IBAQAagD42efvzLqlGN31eVBY1rsdOCJn+" +
	"vdE0aSZSZgc9CrpJy2L08RqO/BFPaJZMdCvTZ96yo6oFjYRNTCBlD6WW2g0W+Gw7228EI4hr" +
	"OmzBYL1on3GO7i1YNAfw1VTphln9e14NIZT1jMmo+NjyrcwPGvOap6kEJ/mjybD/AnhrYbrH" +
	"NSvoVvpPwxwM7bY8tEvq7czhPOzcDYzWPpvKQliLzBYhF0C8otZm79rEFVvNiaqbCSbnMtIN" +
	"bmcgAlsQsJAJnAwfnq3YO+qh/GzoEFwIUhlRKnG7rHq13RXtK8kIKiyKtKYhq2P/11JJUNCJ" +
	"t63yr/tQri/hlQ3zRq2dnPXK"

func parseCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

func parseURI(s string) *url.URL {
	uri, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return uri
}

func TestCreateSelfSignedCertificate(t *testing.T) {
	random := rand.Reader

	ecdsaPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %s", err)
	}

	ed25519Pub, ed25519Priv, err := ed25519.GenerateKey(random)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %s", err)
	}

	tests := []struct {
		name      string
		pub, priv interface{}
		checkSig  bool
		sigAlgo   SignatureAlgorithm
	}{
		{"RSA/RSA", &testPrivateKey.PublicKey, testPrivateKey, true, SHA1WithRSA},
		{"RSA/ECDSA", &testPrivateKey.PublicKey, ecdsaPriv, false, ECDSAWithSHA384},
		{"ECDSA/RSA", &ecdsaPriv.PublicKey, testPrivateKey, false, SHA256WithRSA},
		{"ECDSA/ECDSA", &ecdsaPriv.PublicKey, ecdsaPriv, true, ECDSAWithSHA1},
		{"RSAPSS/RSAPSS", &testPrivateKey.PublicKey, testPrivateKey, true, SHA256WithRSAPSS},
		{"ECDSA/RSAPSS", &ecdsaPriv.PublicKey, testPrivateKey, false, SHA256WithRSAPSS},
		{"RSAPSS/ECDSA", &testPrivateKey.PublicKey, ecdsaPriv, false, ECDSAWithSHA384},
		{"Ed25519", ed25519Pub, ed25519Priv, true, PureEd25519},
	}

	testExtKeyUsage := []ExtKeyUsage{ExtKeyUsageClientAuth, ExtKeyUsageServerAuth}
	testUnknownExtKeyUsage := []asn1.ObjectIdentifier{[]int{1, 2, 3}, []int{2, 59, 1}}
	extraExtensionData := []byte("extra extension")

	for _, test := range tests {
		commonName := "test.example.com"
		//goland:noinspection HttpUrlsUsage
		template := Certificate{
			// SerialNumber is negative to ensure that negative
			// values are parsed. This is due to the prevalence of
			// buggy code that produces certificates with negative
			// serial numbers.
			SerialNumber: big.NewInt(-1),
			Subject: pkix.Name{
				CommonName:   commonName,
				Organization: []string{"Σ Acme Co"},
				Country:      []string{"US"},
				ExtraNames: []pkix.AttributeTypeAndValue{
					{
						Type:  []int{2, 5, 4, 42},
						Value: "Gopher",
					},
					// This should override the Country, above.
					{
						Type:  []int{2, 5, 4, 6},
						Value: "NL",
					},
				},
			},
			NotBefore: time.Unix(1000, 0),
			NotAfter:  time.Unix(100000, 0),

			SignatureAlgorithm: test.sigAlgo,

			SubjectKeyId: []byte{1, 2, 3, 4},
			KeyUsage:     KeyUsageCertSign,

			ExtKeyUsage:        testExtKeyUsage,
			UnknownExtKeyUsage: testUnknownExtKeyUsage,

			BasicConstraintsValid: true,
			IsCA:                  true,

			OCSPServer:            []string{"http://ocsp.example.com"},
			IssuingCertificateURL: []string{"http://crt.example.com/ca1.crt"},

			DNSNames:       []string{"test.example.com"},
			EmailAddresses: []string{"gopher@golang.org"},
			IPAddresses:    []net.IP{net.IPv4(127, 0, 0, 1).To4(), net.ParseIP("2001:4860:0:2001::68")},
			URIs:           []*url.URL{parseURI("https://foo.com/wibble#foo")},

			PolicyIdentifiers:       []asn1.ObjectIdentifier{[]int{1, 2, 3}},
			PermittedDNSDomains:     []string{".example.com", "example.com"},
			ExcludedDNSDomains:      []string{"bar.example.com"},
			PermittedIPRanges:       []*net.IPNet{parseCIDR("192.168.1.1/16"), parseCIDR("1.2.3.4/8")},
			ExcludedIPRanges:        []*net.IPNet{parseCIDR("2001:db8::/48")},
			PermittedEmailAddresses: []string{"foo@example.com"},
			ExcludedEmailAddresses:  []string{".example.com", "example.com"},
			PermittedURIDomains:     []string{".bar.com", "bar.com"},
			ExcludedURIDomains:      []string{".bar2.com", "bar2.com"},

			CRLDistributionPoints: []string{"http://crl1.example.com/ca1.crl", "http://crl2.example.com/ca1.crl"},

			ExtraExtensions: []pkix.Extension{
				{
					Id:    []int{1, 2, 3, 4},
					Value: extraExtensionData,
				},
				// This extension should override the SubjectKeyId, above.
				{
					Id:       oidExtensionSubjectKeyId,
					Critical: false,
					Value:    []byte{0x04, 0x04, 4, 3, 2, 1},
				},
			},
		}

		derBytes, err := CreateCertificate(random, &template, &template, test.pub, test.priv)
		if err != nil {
			t.Errorf("%s: failed to create certificate: %s", test.name, err)
			continue
		}

		cert, err := ParseCertificate(derBytes)
		if err != nil {
			t.Errorf("%s: failed to parse certificate: %s", test.name, err)
			continue
		}

		if len(cert.PolicyIdentifiers) != 1 || !cert.PolicyIdentifiers[0].Equal(template.PolicyIdentifiers[0]) {
			t.Errorf("%s: failed to parse policy identifiers: got:%#v want:%#v", test.name, cert.PolicyIdentifiers, template.PolicyIdentifiers)
		}

		if len(cert.PermittedDNSDomains) != 2 || cert.PermittedDNSDomains[0] != ".example.com" || cert.PermittedDNSDomains[1] != "example.com" {
			t.Errorf("%s: failed to parse name constraints: %#v", test.name, cert.PermittedDNSDomains)
		}

		if len(cert.ExcludedDNSDomains) != 1 || cert.ExcludedDNSDomains[0] != "bar.example.com" {
			t.Errorf("%s: failed to parse name constraint exclusions: %#v", test.name, cert.ExcludedDNSDomains)
		}

		if len(cert.PermittedIPRanges) != 2 || cert.PermittedIPRanges[0].String() != "192.168.0.0/16" || cert.PermittedIPRanges[1].String() != "1.0.0.0/8" {
			t.Errorf("%s: failed to parse IP constraints: %#v", test.name, cert.PermittedIPRanges)
		}

		if len(cert.ExcludedIPRanges) != 1 || cert.ExcludedIPRanges[0].String() != "2001:db8::/48" {
			t.Errorf("%s: failed to parse IP constraint exclusions: %#v", test.name, cert.ExcludedIPRanges)
		}

		if len(cert.PermittedEmailAddresses) != 1 || cert.PermittedEmailAddresses[0] != "foo@example.com" {
			t.Errorf("%s: failed to parse permitted email addreses: %#v", test.name, cert.PermittedEmailAddresses)
		}

		if len(cert.ExcludedEmailAddresses) != 2 || cert.ExcludedEmailAddresses[0] != ".example.com" || cert.ExcludedEmailAddresses[1] != "example.com" {
			t.Errorf("%s: failed to parse excluded email addreses: %#v", test.name, cert.ExcludedEmailAddresses)
		}

		if len(cert.PermittedURIDomains) != 2 || cert.PermittedURIDomains[0] != ".bar.com" || cert.PermittedURIDomains[1] != "bar.com" {
			t.Errorf("%s: failed to parse permitted URIs: %#v", test.name, cert.PermittedURIDomains)
		}

		if len(cert.ExcludedURIDomains) != 2 || cert.ExcludedURIDomains[0] != ".bar2.com" || cert.ExcludedURIDomains[1] != "bar2.com" {
			t.Errorf("%s: failed to parse excluded URIs: %#v", test.name, cert.ExcludedURIDomains)
		}

		if cert.Subject.CommonName != commonName {
			t.Errorf("%s: subject wasn't correctly copied from the template. Got %s, want %s", test.name, cert.Subject.CommonName, commonName)
		}

		if len(cert.Subject.Country) != 1 || cert.Subject.Country[0] != "NL" {
			t.Errorf("%s: ExtraNames didn't override Country", test.name)
		}

		for _, ext := range cert.Extensions {
			if ext.Id.Equal(oidExtensionSubjectAltName) {
				if ext.Critical {
					t.Fatal("SAN extension is marked critical")
				}
			}
		}

		found := false
		for _, atv := range cert.Subject.Names {
			if atv.Type.Equal([]int{2, 5, 4, 42}) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s: Names didn't contain oid 2.5.4.42 from ExtraNames", test.name)
		}

		if cert.Issuer.CommonName != commonName {
			t.Errorf("%s: issuer wasn't correctly copied from the template. Got %s, want %s", test.name, cert.Issuer.CommonName, commonName)
		}

		if cert.SignatureAlgorithm != test.sigAlgo {
			t.Errorf("%s: SignatureAlgorithm wasn't copied from template. Got %v, want %v", test.name, cert.SignatureAlgorithm, test.sigAlgo)
		}

		if !reflect.DeepEqual(cert.ExtKeyUsage, testExtKeyUsage) {
			t.Errorf("%s: extkeyusage wasn't correctly copied from the template. Got %v, want %v", test.name, cert.ExtKeyUsage, testExtKeyUsage)
		}

		if !reflect.DeepEqual(cert.UnknownExtKeyUsage, testUnknownExtKeyUsage) {
			t.Errorf("%s: unknown extkeyusage wasn't correctly copied from the template. Got %v, want %v", test.name, cert.UnknownExtKeyUsage, testUnknownExtKeyUsage)
		}

		if !reflect.DeepEqual(cert.OCSPServer, template.OCSPServer) {
			t.Errorf("%s: OCSP servers differ from template. Got %v, want %v", test.name, cert.OCSPServer, template.OCSPServer)
		}

		if !reflect.DeepEqual(cert.IssuingCertificateURL, template.IssuingCertificateURL) {
			t.Errorf("%s: Issuing certificate URLs differ from template. Got %v, want %v", test.name, cert.IssuingCertificateURL, template.IssuingCertificateURL)
		}

		if !reflect.DeepEqual(cert.DNSNames, template.DNSNames) {
			t.Errorf("%s: SAN DNS names differ from template. Got %v, want %v", test.name, cert.DNSNames, template.DNSNames)
		}

		if !reflect.DeepEqual(cert.EmailAddresses, template.EmailAddresses) {
			t.Errorf("%s: SAN emails differ from template. Got %v, want %v", test.name, cert.EmailAddresses, template.EmailAddresses)
		}

		if len(cert.URIs) != 1 || cert.URIs[0].String() != "https://foo.com/wibble#foo" {
			t.Errorf("%s: URIs differ from template. Got %v, want %v", test.name, cert.URIs, template.URIs)
		}

		if !reflect.DeepEqual(cert.IPAddresses, template.IPAddresses) {
			t.Errorf("%s: SAN IPs differ from template. Got %v, want %v", test.name, cert.IPAddresses, template.IPAddresses)
		}

		if !reflect.DeepEqual(cert.CRLDistributionPoints, template.CRLDistributionPoints) {
			t.Errorf("%s: CRL distribution points differ from template. Got %v, want %v", test.name, cert.CRLDistributionPoints, template.CRLDistributionPoints)
		}

		if !bytes.Equal(cert.SubjectKeyId, []byte{4, 3, 2, 1}) {
			t.Errorf("%s: ExtraExtensions didn't override SubjectKeyId", test.name)
		}

		if !bytes.Contains(derBytes, extraExtensionData) {
			t.Errorf("%s: didn't find extra extension in DER output", test.name)
		}

		if test.checkSig {
			err = cert.CheckSignatureFrom(cert)
			if err != nil {
				t.Errorf("%s: signature verification failed: %s", test.name, err)
			}
		}
	}
}

// Self-signed certificate using ECDSA with SHA1 & secp256r1
var ecdsaSHA1CertPem = `
-----BEGIN CERTIFICATE-----
MIICDjCCAbUCCQDF6SfN0nsnrjAJBgcqhkjOPQQBMIGPMQswCQYDVQQGEwJVUzET
MBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNTW91bnRhaW4gVmlldzEVMBMG
A1UECgwMR29vZ2xlLCBJbmMuMRcwFQYDVQQDDA53d3cuZ29vZ2xlLmNvbTEjMCEG
CSqGSIb3DQEJARYUZ29sYW5nLWRldkBnbWFpbC5jb20wHhcNMTIwNTIwMjAyMDUw
WhcNMjIwNTE4MjAyMDUwWjCBjzELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlm
b3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxFTATBgNVBAoMDEdvb2dsZSwg
SW5jLjEXMBUGA1UEAwwOd3d3Lmdvb2dsZS5jb20xIzAhBgkqhkiG9w0BCQEWFGdv
bGFuZy1kZXZAZ21haWwuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/Wgn
WQDo5+bz71T0327ERgd5SDDXFbXLpzIZDXTkjpe8QTEbsF+ezsQfrekrpDPC4Cd3
P9LY0tG+aI8IyVKdUjAJBgcqhkjOPQQBA0gAMEUCIGlsqMcRqWVIWTD6wXwe6Jk2
DKxL46r/FLgJYnzBEH99AiEA3fBouObsvV1R3oVkb4BQYnD4/4LeId6lAT43YvyV
a/A=
-----END CERTIFICATE-----
`

// Self-signed certificate using ECDSA with SHA256 & secp256r1
var ecdsaSHA256p256CertPem = `
-----BEGIN CERTIFICATE-----
MIICDzCCAbYCCQDlsuMWvgQzhTAKBggqhkjOPQQDAjCBjzELMAkGA1UEBhMCVVMx
EzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxFTAT
BgNVBAoMDEdvb2dsZSwgSW5jLjEXMBUGA1UEAwwOd3d3Lmdvb2dsZS5jb20xIzAh
BgkqhkiG9w0BCQEWFGdvbGFuZy1kZXZAZ21haWwuY29tMB4XDTEyMDUyMTAwMTkx
NloXDTIyMDUxOTAwMTkxNlowgY8xCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxp
Zm9ybmlhMRYwFAYDVQQHDA1Nb3VudGFpbiBWaWV3MRUwEwYDVQQKDAxHb29nbGUs
IEluYy4xFzAVBgNVBAMMDnd3dy5nb29nbGUuY29tMSMwIQYJKoZIhvcNAQkBFhRn
b2xhbmctZGV2QGdtYWlsLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABPMt
2ErhxAty5EJRu9yM+MTy+hUXm3pdW1ensAv382KoGExSXAFWP7pjJnNtHO+XSwVm
YNtqjcAGFKpweoN//kQwCgYIKoZIzj0EAwIDRwAwRAIgIYSaUA/IB81gjbIw/hUV
70twxJr5EcgOo0hLp3Jm+EYCIFDO3NNcgmURbJ1kfoS3N/0O+irUtoPw38YoNkqJ
h5wi
-----END CERTIFICATE-----
`

// Self-signed certificate using ECDSA with SHA256 & secp384r1
var ecdsaSHA256p384CertPem = `
-----BEGIN CERTIFICATE-----
MIICSjCCAdECCQDje/no7mXkVzAKBggqhkjOPQQDAjCBjjELMAkGA1UEBhMCVVMx
EzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxFDAS
BgNVBAoMC0dvb2dsZSwgSW5jMRcwFQYDVQQDDA53d3cuZ29vZ2xlLmNvbTEjMCEG
CSqGSIb3DQEJARYUZ29sYW5nLWRldkBnbWFpbC5jb20wHhcNMTIwNTIxMDYxMDM0
WhcNMjIwNTE5MDYxMDM0WjCBjjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlm
b3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxFDASBgNVBAoMC0dvb2dsZSwg
SW5jMRcwFQYDVQQDDA53d3cuZ29vZ2xlLmNvbTEjMCEGCSqGSIb3DQEJARYUZ29s
YW5nLWRldkBnbWFpbC5jb20wdjAQBgcqhkjOPQIBBgUrgQQAIgNiAARRuzRNIKRK
jIktEmXanNmrTR/q/FaHXLhWRZ6nHWe26Fw7Rsrbk+VjGy4vfWtNn7xSFKrOu5ze
qxKnmE0h5E480MNgrUiRkaGO2GMJJVmxx20aqkXOk59U8yGA4CghE6MwCgYIKoZI
zj0EAwIDZwAwZAIwBZEN8gvmRmfeP/9C1PRLzODIY4JqWub2PLRT4mv9GU+yw3Gr
PU9A3CHMdEcdw/MEAjBBO1lId8KOCh9UZunsSMfqXiVurpzmhWd6VYZ/32G+M+Mh
3yILeYQzllt/g0rKVRk=
-----END CERTIFICATE-----
`

// Self-signed certificate using ECDSA with SHA384 & secp521r1
var ecdsaSHA384p521CertPem = `
-----BEGIN CERTIFICATE-----
MIICljCCAfcCCQDhp1AFD/ahKjAKBggqhkjOPQQDAzCBjjELMAkGA1UEBhMCVVMx
EzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxFDAS
BgNVBAoMC0dvb2dsZSwgSW5jMRcwFQYDVQQDDA53d3cuZ29vZ2xlLmNvbTEjMCEG
CSqGSIb3DQEJARYUZ29sYW5nLWRldkBnbWFpbC5jb20wHhcNMTIwNTIxMTUwNDI5
WhcNMjIwNTE5MTUwNDI5WjCBjjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlm
b3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxFDASBgNVBAoMC0dvb2dsZSwg
SW5jMRcwFQYDVQQDDA53d3cuZ29vZ2xlLmNvbTEjMCEGCSqGSIb3DQEJARYUZ29s
YW5nLWRldkBnbWFpbC5jb20wgZswEAYHKoZIzj0CAQYFK4EEACMDgYYABACqx9Rv
IssRs1LWYcNN+WffwlHw4Tv3y8/LIAA9MF1ZScIonU9nRMxt4a2uGJVCPDw6JHpz
PaYc0E9puLoE9AfKpwFr59Jkot7dBg55SKPEFkddoip/rvmN7NPAWjMBirOwjOkm
8FPthvPhGPqsu9AvgVuHu3PosWiHGNrhh379pva8MzAKBggqhkjOPQQDAwOBjAAw
gYgCQgEHNmswkUdPpHqrVxp9PvLVl+xxPuHBkT+75z9JizyxtqykHQo9Uh6SWCYH
BF9KLolo01wMt8DjoYP5Fb3j5MH7xwJCAbWZzTOp4l4DPkIvAh4LeC4VWbwPPyqh
kBg71w/iEcSY3wUKgHGcJJrObZw7wys91I5kENljqw/Samdr3ka+jBJa
-----END CERTIFICATE-----
`

var ecdsaTests = []struct {
	sigAlgo SignatureAlgorithm
	pemCert string
}{
	{ECDSAWithSHA1, ecdsaSHA1CertPem},
	{ECDSAWithSHA256, ecdsaSHA256p256CertPem},
	{ECDSAWithSHA256, ecdsaSHA256p384CertPem},
	{ECDSAWithSHA384, ecdsaSHA384p521CertPem},
}

func TestECDSA(t *testing.T) {
	for i, test := range ecdsaTests {
		pemBlock, _ := pem.Decode([]byte(test.pemCert))
		cert, err := ParseCertificate(pemBlock.Bytes)
		if err != nil {
			t.Errorf("%d: failed to parse certificate: %s", i, err)
			continue
		}
		if sa := cert.SignatureAlgorithm; sa != test.sigAlgo {
			t.Errorf("%d: signature algorithm is %v, want %v", i, sa, test.sigAlgo)
		}
		if parsedKey, ok := cert.PublicKey.(*ecdsa.PublicKey); !ok {
			t.Errorf("%d: wanted an ECDSA public key but found: %#v", i, parsedKey)
		}
		if pka := cert.PublicKeyAlgorithm; pka != ECDSA {
			t.Errorf("%d: public key algorithm is %v, want ECDSA", i, pka)
		}
		if err = cert.CheckSignatureFrom(cert); err != nil {
			t.Errorf("%d: certificate verification failed: %s", i, err)
		}
	}
}

// Self-signed certificate using DSA with SHA1
var dsaCertPem = `-----BEGIN CERTIFICATE-----
MIIEDTCCA82gAwIBAgIJALHPghaoxeDhMAkGByqGSM44BAMweTELMAkGA1UEBhMC
VVMxCzAJBgNVBAgTAk5DMQ8wDQYDVQQHEwZOZXd0b24xFDASBgNVBAoTC0dvb2ds
ZSwgSW5jMRIwEAYDVQQDEwlKb24gQWxsaWUxIjAgBgkqhkiG9w0BCQEWE2pvbmFs
bGllQGdvb2dsZS5jb20wHhcNMTEwNTE0MDMwMTQ1WhcNMTEwNjEzMDMwMTQ1WjB5
MQswCQYDVQQGEwJVUzELMAkGA1UECBMCTkMxDzANBgNVBAcTBk5ld3RvbjEUMBIG
A1UEChMLR29vZ2xlLCBJbmMxEjAQBgNVBAMTCUpvbiBBbGxpZTEiMCAGCSqGSIb3
DQEJARYTam9uYWxsaWVAZ29vZ2xlLmNvbTCCAbcwggEsBgcqhkjOOAQBMIIBHwKB
gQC8hLUnQ7FpFYu4WXTj6DKvXvz8QrJkNJCVMTpKAT7uBpobk32S5RrPKXocd4gN
8lyGB9ggS03EVlEwXvSmO0DH2MQtke2jl9j1HLydClMf4sbx5V6TV9IFw505U1iW
jL7awRMgxge+FsudtJK254FjMFo03ZnOQ8ZJJ9E6AEDrlwIVAJpnBn9moyP11Ox5
Asc/5dnjb6dPAoGBAJFHd4KVv1iTVCvEG6gGiYop5DJh28hUQcN9kul+2A0yPUSC
X93oN00P8Vh3eYgSaCWZsha7zDG53MrVJ0Zf6v/X/CoZNhLldeNOepivTRAzn+Rz
kKUYy5l1sxYLHQKF0UGNCXfFKZT0PCmgU+PWhYNBBMn6/cIh44vp85ideo5CA4GE
AAKBgFmifCafzeRaohYKXJgMGSEaggCVCRq5xdyDCat+wbOkjC4mfG01/um3G8u5
LxasjlWRKTR/tcAL7t0QuokVyQaYdVypZXNaMtx1db7YBuHjj3aP+8JOQRI9xz8c
bp5NDJ5pISiFOv4p3GZfqZPcqckDt78AtkQrmnal2txhhjF6o4HeMIHbMB0GA1Ud
DgQWBBQVyyr7hO11ZFFpWX50298Sa3V+rzCBqwYDVR0jBIGjMIGggBQVyyr7hO11
ZFFpWX50298Sa3V+r6F9pHsweTELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAk5DMQ8w
DQYDVQQHEwZOZXd0b24xFDASBgNVBAoTC0dvb2dsZSwgSW5jMRIwEAYDVQQDEwlK
b24gQWxsaWUxIjAgBgkqhkiG9w0BCQEWE2pvbmFsbGllQGdvb2dsZS5jb22CCQCx
z4IWqMXg4TAMBgNVHRMEBTADAQH/MAkGByqGSM44BAMDLwAwLAIUPtn/5j8Q1jJI
7ggOIsgrhgUdjGQCFCsmDq1H11q9+9Wp9IMeGrTSKHIM
-----END CERTIFICATE-----
`

// func TestParseCertificateWithDsaPublicKey(t *testing.T) {
// 	expectedKey := &dsa.PublicKey{
// 		Parameters: dsa.Parameters{
// 			P: bigFromHexString("00BC84B52743B169158BB85974E3E832AF5EFCFC42B264349095313A4A013EEE069A1B937D92E51ACF297A1C77880DF25C8607D8204B4DC45651305EF4A63B40C7D8C42D91EDA397D8F51CBC9D0A531FE2C6F1E55E9357D205C39D395358968CBEDAC11320C607BE16CB9DB492B6E78163305A34DD99CE43C64927D13A0040EB97"),
// 			Q: bigFromHexString("009A67067F66A323F5D4EC7902C73FE5D9E36FA74F"),
// 			G: bigFromHexString("009147778295BF5893542BC41BA806898A29E43261DBC85441C37D92E97ED80D323D44825FDDE8374D0FF15877798812682599B216BBCC31B9DCCAD527465FEAFFD7FC2A193612E575E34E7A98AF4D10339FE47390A518CB9975B3160B1D0285D1418D0977C52994F43C29A053E3D685834104C9FAFDC221E38BE9F3989D7A8E42"),
// 		},
// 		Y: bigFromHexString("59A27C269FCDE45AA2160A5C980C19211A820095091AB9C5DC8309AB7EC1B3A48C2E267C6D35FEE9B71BCBB92F16AC8E559129347FB5C00BEEDD10BA8915C90698755CA965735A32DC7575BED806E1E38F768FFBC24E41123DC73F1C6E9E4D0C9E692128853AFE29DC665FA993DCA9C903B7BF00B6442B9A76A5DADC6186317A"),
// 	}
// 	pemBlock, _ := pem.Decode([]byte(dsaCertPem))
// 	cert, err := ParseCertificate(pemBlock.Bytes)
// 	if err != nil {
// 		t.Fatalf("Failed to parse certificate: %s", err)
// 	}
// 	if cert.PublicKeyAlgorithm != DSA {
// 		t.Errorf("Parsed key algorithm was not DSA")
// 	}
// 	parsedKey, ok := cert.PublicKey.(*dsa.PublicKey)
// 	if !ok {
// 		t.Fatalf("Parsed key was not a DSA key: %s", err)
// 	}
// 	if expectedKey.Y.Cmp(parsedKey.Y) != 0 ||
// 		expectedKey.P.Cmp(parsedKey.P) != 0 ||
// 		expectedKey.Q.Cmp(parsedKey.Q) != 0 ||
// 		expectedKey.G.Cmp(parsedKey.G) != 0 {
// 		t.Fatal("Parsed key differs from expected key")
// 	}
// }

func TestParseCertificateWithDSASignatureAlgorithm(t *testing.T) {
	pemBlock, _ := pem.Decode([]byte(dsaCertPem))
	cert, err := ParseCertificate(pemBlock.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %s", err)
	}
	if cert.SignatureAlgorithm != DSAWithSHA1 {
		t.Errorf("Parsed signature algorithm was not DSAWithSHA1")
	}
}

func TestVerifyCertificateWithDSASignature(t *testing.T) {
	pemBlock, _ := pem.Decode([]byte(dsaCertPem))
	cert, err := ParseCertificate(pemBlock.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %s", err)
	}
	// test cert is self-signed
	if err = cert.CheckSignatureFrom(cert); err == nil {
		t.Fatalf("Expected error verifying DSA certificate")
	}
}

var rsaPSSSelfSignedPEM = `-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----`

// openssl req -newkey rsa:2048 -keyout test.key -sha256 -sigopt \
// rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 -sigopt rsa_mgf1_md:sha256 \
// -x509 -days 3650 -nodes -subj '/C=US/ST=CA/L=SF/O=Test/CN=Test' -out \
// test.pem
var rsaPSSSelfSignedOpenSSL110PEM = `-----BEGIN CERTIFICATE-----
MIIDwDCCAnigAwIBAgIJAM9LAMHTE5xpMD0GCSqGSIb3DQEBCjAwoA0wCwYJYIZI
AWUDBAIBoRowGAYJKoZIhvcNAQEIMAsGCWCGSAFlAwQCAaIDAgEgMEUxCzAJBgNV
BAYTAlVTMQswCQYDVQQIDAJDQTELMAkGA1UEBwwCU0YxDTALBgNVBAoMBFRlc3Qx
DTALBgNVBAMMBFRlc3QwHhcNMTgwMjIyMjIxMzE4WhcNMjgwMjIwMjIxMzE4WjBF
MQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ0ExCzAJBgNVBAcMAlNGMQ0wCwYDVQQK
DARUZXN0MQ0wCwYDVQQDDARUZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEA4Zrsydod+GoTAJLLutWNF87qhhVPBsK1zB1Gj+NAAe4+VbrZ1E41H1wp
qITx7DA8DRtJEf+NqrTAnAdZWBG/tAOA5LfXVax0ZSQtLnYLSeylLoMtDyY3eFAj
TmuTOoyVy6raktowCnHCh01NsstqqTfrx6SbmzOmDmKTkq/I+7K0MCVsn41xRDVM
+ShD0WGFGioEGoiWnFSWupxJDA3Q6jIDEygVwNKHwnhv/2NgG2kqZzrZSQA67en0
iKAXtoDNPpmyD5oS9YbEJ+2Nbm7oLeON30i6kZvXKIzJXx+UWViazHZqnsi5rQ8G
RHF+iVFXsqd0MzDKmkKOT5FDhrsbKQIDAQABo1MwUTAdBgNVHQ4EFgQU9uFY/nlg
gLH00NBnr/o7QvpN9ugwHwYDVR0jBBgwFoAU9uFY/nlggLH00NBnr/o7QvpN9ugw
DwYDVR0TAQH/BAUwAwEB/zA9BgkqhkiG9w0BAQowMKANMAsGCWCGSAFlAwQCAaEa
MBgGCSqGSIb3DQEBCDALBglghkgBZQMEAgGiAwIBIAOCAQEAhJzpwxBNGKvzKWDe
WLqv6RMrl/q4GcH3b7M9wjxe0yOm4F+Tb2zJ7re4h+D39YkJf8cX1NV9UQVu6z4s
Fvo2kmlR0qZOXAg5augmCQ1xS0WHFoF6B52anNzHkZQbAIYJ3kGoFsUHzs7Sz7F/
656FsRpHA9UzJQ3avPPMrA4Y4aoJ7ANJ6XIwTrdWrhULOVuvYRLCl4CdTVztVFX6
wxX8nS1ISYd8jXPUMgsBKVbWufvLoIymMJW8CZbpprVZel5zFn0bmPrON8IHS30w
Gs+ITJjKEnZgXmAQ25SLKVzkZkBcGANs2GsdHNJ370Puisy0FIPD2NXR5uASAf7J
+w9fjQ==
-----END CERTIFICATE-----`

func TestRSAPSSSelfSigned(t *testing.T) {
	for i, pemBlock := range []string{rsaPSSSelfSignedPEM, rsaPSSSelfSignedOpenSSL110PEM} {
		der, _ := pem.Decode([]byte(pemBlock))
		if der == nil {
			t.Errorf("#%d: failed to find PEM block", i)
			continue
		}

		cert, err := ParseCertificate(der.Bytes)
		if err != nil {
			t.Errorf("#%d: failed to parse: %s", i, err)
			continue
		}

		if err = cert.CheckSignatureFrom(cert); err != nil {
			t.Errorf("#%d: signature check failed: %s", i, err)
			continue
		}
	}
}

const ed25519Certificate = `
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            0c:83:d8:21:2b:82:cb:23:98:23:63:e2:f7:97:8a:43:5b:f3:bd:92
        Signature Algorithm: ED25519
        Issuer: CN = Ed25519 test certificate
        Validity
            Not Before: May  6 17:27:16 2019 GMT
            Not After : Jun  5 17:27:16 2019 GMT
        Subject: CN = Ed25519 test certificate
        Subject Public Key Info:
            Public Key Algorithm: ED25519
                ED25519 Public-Key:
                pub:
                    36:29:c5:6c:0d:4f:14:6c:81:d0:ff:75:d3:6a:70:
                    5f:69:cd:0f:4d:66:d5:da:98:7e:82:49:89:a3:8a:
                    3c:fa
        X509v3 extensions:
            X509v3 Subject Key Identifier:
                09:3B:3A:9D:4A:29:D8:95:FF:68:BE:7B:43:54:72:E0:AD:A2:E3:AE
            X509v3 Authority Key Identifier:
                keyid:09:3B:3A:9D:4A:29:D8:95:FF:68:BE:7B:43:54:72:E0:AD:A2:E3:AE

            X509v3 Basic Constraints: critical
                CA:TRUE
    Signature Algorithm: ED25519
         53:a5:58:1c:2c:3b:2a:9e:ac:9d:4e:a5:1d:5f:5d:6d:a6:b5:
         08:de:12:82:f3:97:20:ae:fa:d8:98:f4:1a:83:32:6b:91:f5:
         24:1d:c4:20:7f:2c:e2:4d:da:13:3b:6d:54:1a:d2:a8:28:dc:
         60:b9:d4:f4:78:4b:3c:1c:91:00
-----BEGIN CERTIFICATE-----
MIIBWzCCAQ2gAwIBAgIUDIPYISuCyyOYI2Pi95eKQ1vzvZIwBQYDK2VwMCMxITAf
BgNVBAMMGEVkMjU1MTkgdGVzdCBjZXJ0aWZpY2F0ZTAeFw0xOTA1MDYxNzI3MTZa
Fw0xOTA2MDUxNzI3MTZaMCMxITAfBgNVBAMMGEVkMjU1MTkgdGVzdCBjZXJ0aWZp
Y2F0ZTAqMAUGAytlcAMhADYpxWwNTxRsgdD/ddNqcF9pzQ9NZtXamH6CSYmjijz6
o1MwUTAdBgNVHQ4EFgQUCTs6nUop2JX/aL57Q1Ry4K2i464wHwYDVR0jBBgwFoAU
CTs6nUop2JX/aL57Q1Ry4K2i464wDwYDVR0TAQH/BAUwAwEB/zAFBgMrZXADQQBT
pVgcLDsqnqydTqUdX11tprUI3hKC85cgrvrYmPQagzJrkfUkHcQgfyziTdoTO21U
GtKoKNxgudT0eEs8HJEA
-----END CERTIFICATE-----`

func TestEd25519SelfSigned(t *testing.T) {
	der, _ := pem.Decode([]byte(ed25519Certificate))
	if der == nil {
		t.Fatalf("Failed to find PEM block")
	}

	cert, err := ParseCertificate(der.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse: %s", err)
	}

	if cert.PublicKeyAlgorithm != Ed25519 {
		t.Fatalf("Parsed key algorithm was not Ed25519")
	}
	parsedKey, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("Parsed key was not an Ed25519 key: %s", err)
	}
	if len(parsedKey) != ed25519.PublicKeySize {
		t.Fatalf("Invalid Ed25519 key")
	}

	if err = cert.CheckSignatureFrom(cert); err != nil {
		t.Fatalf("Signature check failed: %s", err)
	}
}

const pemCertificate = `-----BEGIN CERTIFICATE-----
MIIDATCCAemgAwIBAgIRAKQkkrFx1T/dgB/Go/xBM5swDQYJKoZIhvcNAQELBQAw
EjEQMA4GA1UEChMHQWNtZSBDbzAeFw0xNjA4MTcyMDM2MDdaFw0xNzA4MTcyMDM2
MDdaMBIxEDAOBgNVBAoTB0FjbWUgQ28wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQDAoJtjG7M6InsWwIo+l3qq9u+g2rKFXNu9/mZ24XQ8XhV6PUR+5HQ4
jUFWC58ExYhottqK5zQtKGkw5NuhjowFUgWB/VlNGAUBHtJcWR/062wYrHBYRxJH
qVXOpYKbIWwFKoXu3hcpg/CkdOlDWGKoZKBCwQwUBhWE7MDhpVdQ+ZljUJWL+FlK
yQK5iRsJd5TGJ6VUzLzdT4fmN2DzeK6GLeyMpVpU3sWV90JJbxWQ4YrzkKzYhMmB
EcpXTG2wm+ujiHU/k2p8zlf8Sm7VBM/scmnMFt0ynNXop4FWvJzEm1G0xD2t+e2I
5Utr04dOZPCgkm++QJgYhtZvgW7ZZiGTAgMBAAGjUjBQMA4GA1UdDwEB/wQEAwIF
oDATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMBsGA1UdEQQUMBKC
EHRlc3QuZXhhbXBsZS5jb20wDQYJKoZIhvcNAQELBQADggEBADpqKQxrthH5InC7
X96UP0OJCu/lLEMkrjoEWYIQaFl7uLPxKH5AmQPH4lYwF7u7gksR7owVG9QU9fs6
1fK7II9CVgCd/4tZ0zm98FmU4D0lHGtPARrrzoZaqVZcAvRnFTlPX5pFkPhVjjai
/mkxX9LpD8oK1445DFHxK5UjLMmPIIWd8EOi+v5a+hgGwnJpoW7hntSl8kHMtTmy
fnnktsblSUV4lRCit0ymC7Ojhe+gzCCwkgs5kDzVVag+tnl/0e2DloIjASwOhpbH
KVcg7fBd484ht/sS+l0dsB4KDOSpd8JzVDMF8OZqlaydizoJO0yWr9GbCN1+OKq5
EhLrEqU=
-----END CERTIFICATE-----`

const ed25519CRLCertificate = `
Certificate:
Data:
	Version: 3 (0x2)
	Serial Number:
		7a:07:a0:9d:14:04:16:fc:1f:d8:e5:fe:d1:1d:1f:8d
	Signature Algorithm: ED25519
	Issuer: CN = Ed25519 CRL Test CA
	Validity
		Not Before: Oct 30 01:20:20 2019 GMT
		Not After : Dec 31 23:59:59 9999 GMT
	Subject: CN = Ed25519 CRL Test CA
	Subject Public Key Info:
		Public Key Algorithm: ED25519
			ED25519 Public-Key:
			pub:
				95:73:3b:b0:06:2a:31:5a:b6:a7:a6:6e:ef:71:df:
				ac:6f:6b:39:03:85:5e:63:4b:f8:a6:0f:68:c6:6f:
				75:21
	X509v3 extensions:
		X509v3 Key Usage: critical
			Digital Signature, Certificate Sign, CRL Sign
		X509v3 Extended Key Usage: 
			TLS Web Client Authentication, TLS Web Server Authentication, OCSP Signing
		X509v3 Basic Constraints: critical
			CA:TRUE
		X509v3 Subject Key Identifier: 
			B7:17:DA:16:EA:C5:ED:1F:18:49:44:D3:D2:E3:A0:35:0A:81:93:60
		X509v3 Authority Key Identifier: 
			keyid:B7:17:DA:16:EA:C5:ED:1F:18:49:44:D3:D2:E3:A0:35:0A:81:93:60

Signature Algorithm: ED25519
	 fc:3e:14:ea:bb:70:c2:6f:38:34:70:bc:c8:a7:f4:7c:0d:1e:
	 28:d7:2a:9f:22:8a:45:e8:02:76:84:1e:2d:64:2d:1e:09:b5:
	 29:71:1f:95:8a:4e:79:87:51:60:9a:e7:86:40:f6:60:c7:d1:
	 ee:68:76:17:1d:90:cc:92:93:07
-----BEGIN CERTIFICATE-----
MIIBijCCATygAwIBAgIQegegnRQEFvwf2OX+0R0fjTAFBgMrZXAwHjEcMBoGA1UE
AxMTRWQyNTUxOSBDUkwgVGVzdCBDQTAgFw0xOTEwMzAwMTIwMjBaGA85OTk5MTIz
MTIzNTk1OVowHjEcMBoGA1UEAxMTRWQyNTUxOSBDUkwgVGVzdCBDQTAqMAUGAytl
cAMhAJVzO7AGKjFatqembu9x36xvazkDhV5jS/imD2jGb3Uho4GNMIGKMA4GA1Ud
DwEB/wQEAwIBhjAnBgNVHSUEIDAeBggrBgEFBQcDAgYIKwYBBQUHAwEGCCsGAQUF
BwMJMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFLcX2hbqxe0fGElE09LjoDUK
gZNgMB8GA1UdIwQYMBaAFLcX2hbqxe0fGElE09LjoDUKgZNgMAUGAytlcANBAPw+
FOq7cMJvODRwvMin9HwNHijXKp8iikXoAnaEHi1kLR4JtSlxH5WKTnmHUWCa54ZA
9mDH0e5odhcdkMySkwc=
-----END CERTIFICATE-----`

var ed25519CRLKey = testingKey(`-----BEGIN TEST KEY-----
MC4CAQAwBQYDK2VwBCIEINdKh2096vUBYu4EIFpjShsUSh3vimKya1sQ1YTT4RZG
-----END TEST KEY-----`)

func TestCRLCreation(t *testing.T) {
	block, _ := pem.Decode([]byte(pemPrivateKey))
	privRSA, _ := ParsePKCS1PrivateKey(block.Bytes)
	block, _ = pem.Decode([]byte(pemCertificate))
	certRSA, _ := ParseCertificate(block.Bytes)

	block, _ = pem.Decode([]byte(ed25519CRLKey))
	privEd25519, _ := ParsePKCS8PrivateKey(block.Bytes)
	block, _ = pem.Decode([]byte(ed25519CRLCertificate))
	certEd25519, _ := ParseCertificate(block.Bytes)

	tests := []struct {
		name string
		priv interface{}
		cert *Certificate
	}{
		{"RSA CA", privRSA, certRSA},
		{"Ed25519 CA", privEd25519, certEd25519},
	}

	loc := time.FixedZone("Oz/Atlantis", int((2 * time.Hour).Seconds()))

	now := time.Unix(1000, 0).In(loc)
	nowUTC := now.UTC()
	expiry := time.Unix(10000, 0)

	revokedCerts := []pkix.RevokedCertificate{
		{
			SerialNumber:   big.NewInt(1),
			RevocationTime: nowUTC,
		},
		{
			SerialNumber: big.NewInt(42),
			// RevocationTime should be converted to UTC before marshaling.
			RevocationTime: now,
		},
	}
	expectedCerts := []pkix.RevokedCertificate{
		{
			SerialNumber:   big.NewInt(1),
			RevocationTime: nowUTC,
		},
		{
			SerialNumber:   big.NewInt(42),
			RevocationTime: nowUTC,
		},
	}

	for _, test := range tests {
		crlBytes, err := test.cert.CreateCRL(rand.Reader, test.priv, revokedCerts, now, expiry)
		if err != nil {
			t.Errorf("%s: error creating CRL: %s", test.name, err)
		}

		parsedCRL, err := ParseDERCRL(crlBytes)
		if err != nil {
			t.Errorf("%s: error reparsing CRL: %s", test.name, err)
		}
		if !reflect.DeepEqual(parsedCRL.TBSCertList.RevokedCertificates, expectedCerts) {
			t.Errorf("%s: RevokedCertificates mismatch: got %v; want %v.", test.name,
				parsedCRL.TBSCertList.RevokedCertificates, expectedCerts)
		}
	}
}

func fromBase64(in string) []byte {
	out := make([]byte, base64.StdEncoding.DecodedLen(len(in)))
	n, err := base64.StdEncoding.Decode(out, []byte(in))
	if err != nil {
		panic("failed to base64 decode")
	}
	return out[:n]
}

func TestParseDERCRL(t *testing.T) {
	derBytes := fromBase64(derCRLBase64)
	certList, err := ParseDERCRL(derBytes)
	if err != nil {
		t.Errorf("error parsing: %s", err)
		return
	}
	numCerts := len(certList.TBSCertList.RevokedCertificates)
	expected := 88
	if numCerts != expected {
		t.Errorf("bad number of revoked certificates. got: %d want: %d", numCerts, expected)
	}

	if certList.HasExpired(time.Unix(1302517272, 0)) {
		t.Errorf("CRL has expired (but shouldn't have)")
	}

	// Can't check the signature here without a package cycle.
}

func TestCRLWithoutExpiry(t *testing.T) {
	derBytes := fromBase64("MIHYMIGZMAkGByqGSM44BAMwEjEQMA4GA1UEAxMHQ2FybERTUxcNOTkwODI3MDcwMDAwWjBpMBMCAgDIFw05OTA4MjIwNzAwMDBaMBMCAgDJFw05OTA4MjIwNzAwMDBaMBMCAgDTFw05OTA4MjIwNzAwMDBaMBMCAgDSFw05OTA4MjIwNzAwMDBaMBMCAgDUFw05OTA4MjQwNzAwMDBaMAkGByqGSM44BAMDLwAwLAIUfmVSdjP+NHMX0feW+aDU2G1cfT0CFAJ6W7fVWxjBz4fvftok8yqDnDWh")
	certList, err := ParseDERCRL(derBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !certList.TBSCertList.NextUpdate.IsZero() {
		t.Errorf("NextUpdate is not the zero value")
	}
}

func TestParsePEMCRL(t *testing.T) {
	pemBytes := fromBase64(pemCRLBase64)
	certList, err := ParseCRL(pemBytes)
	if err != nil {
		t.Errorf("error parsing: %s", err)
		return
	}
	numCerts := len(certList.TBSCertList.RevokedCertificates)
	expected := 2
	if numCerts != expected {
		t.Errorf("bad number of revoked certificates. got: %d want: %d", numCerts, expected)
	}

	if certList.HasExpired(time.Unix(1302517272, 0)) {
		t.Errorf("CRL has expired (but shouldn't have)")
	}

	// Can't check the signature here without a package cycle.
}

func TestImports(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in -short mode")
	}
	testenv.MustHaveGoRun(t)

	if out, err := exec.Command(testenv.GoToolPath(t), "run", "x509_test_import.go").CombinedOutput(); err != nil {
		t.Errorf("failed to run x509_test_import.go: %s\n%s", err, out)
	}
}

const derCRLBase64 = "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"

const pemCRLBase64 = "LS0tLS1CRUdJTiBYNTA5IENSTC0tLS0tDQpNSUlCOWpDQ0FWOENBUUV3RFFZSktvWklodmNOQVFFRkJRQXdiREVhTUJnR0ExVUVDaE1SVWxOQklGTmxZM1Z5DQphWFI1SUVsdVl5NHhIakFjQmdOVkJBTVRGVkpUUVNCUWRXSnNhV01nVW05dmRDQkRRU0IyTVRFdU1Dd0dDU3FHDQpTSWIzRFFFSkFSWWZjbk5oYTJWdmJuSnZiM1J6YVdkdVFISnpZWE5sWTNWeWFYUjVMbU52YlJjTk1URXdNakl6DQpNVGt5T0RNd1doY05NVEV3T0RJeU1Ua3lPRE13V2pDQmpEQktBaEVBckRxb2g5RkhKSFhUN09QZ3V1bjQrQmNODQpNRGt4TVRBeU1UUXlOekE1V2pBbU1Bb0dBMVVkRlFRRENnRUpNQmdHQTFVZEdBUVJHQTh5TURBNU1URXdNakUwDQpNalExTlZvd1BnSVJBTEd6blowOTVQQjVhQU9MUGc1N2ZNTVhEVEF5TVRBeU16RTBOVEF4TkZvd0dqQVlCZ05WDQpIUmdFRVJnUE1qQXdNakV3TWpNeE5EVXdNVFJhb0RBd0xqQWZCZ05WSFNNRUdEQVdnQlQxVERGNlVRTS9MTmVMDQpsNWx2cUhHUXEzZzltekFMQmdOVkhSUUVCQUlDQUlRd0RRWUpLb1pJaHZjTkFRRUZCUUFEZ1lFQUZVNUFzNk16DQpxNVBSc2lmYW9iUVBHaDFhSkx5QytNczVBZ2MwYld5QTNHQWR4dXI1U3BQWmVSV0NCamlQL01FSEJXSkNsQkhQDQpHUmNxNXlJZDNFakRrYUV5eFJhK2k2N0x6dmhJNmMyOUVlNks5cFNZd2ppLzdSVWhtbW5Qclh0VHhsTDBsckxyDQptUVFKNnhoRFJhNUczUUE0Q21VZHNITnZicnpnbUNZcHZWRT0NCi0tLS0tRU5EIFg1MDkgQ1JMLS0tLS0NCg0K"

func TestCreateCertificateRequest(t *testing.T) {
	random := rand.Reader

	ecdsa256Priv, err := ecdsa_ext.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %s", err)
	}

	ecdsa384Priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %s", err)
	}

	ecdsa521Priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %s", err)
	}

	_, ed25519Priv, err := ed25519.GenerateKey(random)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %s", err)
	}

	sm2Priv, err := sm2.GenerateKey(random)
	if err != nil {
		t.Fatalf("Failed to generate SM2 key: %s", err)
	}

	tests := []struct {
		name    string
		priv    interface{}
		sigAlgo SignatureAlgorithm
	}{
		{"RSA", testPrivateKey, SHA1WithRSA},
		{"ECDSA-EXT-256", ecdsa256Priv, ECDSAEXTWithSHA256},
		{"ECDSA-384", ecdsa384Priv, ECDSAWithSHA1},
		{"ECDSA-521", ecdsa521Priv, ECDSAWithSHA1},
		{"Ed25519", ed25519Priv, PureEd25519},
		{"SM2", sm2Priv, SM2WithSM3},
	}

	for _, test := range tests {
		zclog.Debugf("开始测试 %s", test.name)
		template := CertificateRequest{
			Subject: pkix.Name{
				CommonName:   "test.example.com",
				Organization: []string{"Σ Acme Co"},
			},
			SignatureAlgorithm: test.sigAlgo,
			DNSNames:           []string{"test.example.com"},
			EmailAddresses:     []string{"gopher@golang.org"},
			IPAddresses:        []net.IP{net.IPv4(127, 0, 0, 1).To4(), net.ParseIP("2001:4860:0:2001::68")},
		}

		derBytes, err := CreateCertificateRequest(random, &template, test.priv)
		if err != nil {
			t.Errorf("%s: failed to create certificate request: %s", test.name, err)
			continue
		}

		out, err := ParseCertificateRequest(derBytes)
		if err != nil {
			t.Errorf("%s: failed to create certificate request: %s", test.name, err)
			continue
		}

		err = out.CheckSignature()
		if err != nil {
			t.Errorf("%s: failed to check certificate request signature: %s", test.name, err)
			continue
		}

		if out.Subject.CommonName != template.Subject.CommonName {
			t.Errorf("%s: output subject common name and template subject common name don't match", test.name)
		} else if len(out.Subject.Organization) != len(template.Subject.Organization) {
			t.Errorf("%s: output subject organisation and template subject organisation don't match", test.name)
		} else if len(out.DNSNames) != len(template.DNSNames) {
			t.Errorf("%s: output DNS names and template DNS names don't match", test.name)
		} else if len(out.EmailAddresses) != len(template.EmailAddresses) {
			t.Errorf("%s: output email addresses and template email addresses don't match", test.name)
		} else if len(out.IPAddresses) != len(template.IPAddresses) {
			t.Errorf("%s: output IP addresses and template IP addresses names don't match", test.name)
		}
	}
}

func marshalAndParseCSR(t *testing.T, template *CertificateRequest) *CertificateRequest {
	derBytes, err := CreateCertificateRequest(rand.Reader, template, testPrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	csr, err := ParseCertificateRequest(derBytes)
	if err != nil {
		t.Fatal(err)
	}

	return csr
}

func TestCertificateRequestOverrides(t *testing.T) {
	sanContents, err := marshalSANs([]string{"foo.example.com"}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	template := CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "test.example.com",
			Organization: []string{"Σ Acme Co"},
		},
		DNSNames: []string{"test.example.com"},

		// An explicit extension should override the DNSNames from the
		// template.
		ExtraExtensions: []pkix.Extension{
			{
				Id:       oidExtensionSubjectAltName,
				Value:    sanContents,
				Critical: true,
			},
		},
	}

	csr := marshalAndParseCSR(t, &template)

	if len(csr.DNSNames) != 1 || csr.DNSNames[0] != "foo.example.com" {
		t.Errorf("Extension did not override template. Got %v\n", csr.DNSNames)
	}

	if len(csr.Extensions) != 1 || !csr.Extensions[0].Id.Equal(oidExtensionSubjectAltName) || !csr.Extensions[0].Critical {
		t.Errorf("SAN extension was not faithfully copied, got %#v", csr.Extensions)
	}

	// If there is already an attribute with X.509 extensions then the
	// extra extensions should be added to it rather than creating a CSR
	// with two extension attributes.

	//goland:noinspection GoDeprecation
	template.Attributes = []pkix.AttributeTypeAndValueSET{
		{
			Type: oidExtensionRequest,
			Value: [][]pkix.AttributeTypeAndValue{
				{
					{
						Type:  oidExtensionAuthorityInfoAccess,
						Value: []byte("foo"),
					},
				},
			},
		},
	}

	csr = marshalAndParseCSR(t, &template)
	//goland:noinspection GoDeprecation
	if l := len(csr.Attributes); l != 1 {
		t.Errorf("incorrect number of attributes: %d\n", l)
	}

	//goland:noinspection GoDeprecation
	if !csr.Attributes[0].Type.Equal(oidExtensionRequest) ||
		len(csr.Attributes[0].Value) != 1 ||
		len(csr.Attributes[0].Value[0]) != 2 {
		t.Errorf("bad attributes: %#v\n", csr.Attributes)
	}

	sanContents2, err := marshalSANs([]string{"foo2.example.com"}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Extensions in Attributes should override those in ExtraExtensions.
	//goland:noinspection GoDeprecation
	template.Attributes[0].Value[0] = append(template.Attributes[0].Value[0], pkix.AttributeTypeAndValue{
		Type:  oidExtensionSubjectAltName,
		Value: sanContents2,
	})

	csr = marshalAndParseCSR(t, &template)

	if len(csr.DNSNames) != 1 || csr.DNSNames[0] != "foo2.example.com" {
		t.Errorf("Attributes did not override ExtraExtensions. Got %v\n", csr.DNSNames)
	}
}

func TestParseCertificateRequest(t *testing.T) {
	for _, csrBase64 := range csrBase64Array {
		csrBytes := fromBase64(csrBase64)
		csr, err := ParseCertificateRequest(csrBytes)
		if err != nil {
			t.Fatalf("failed to parse CSR: %s", err)
		}

		if len(csr.EmailAddresses) != 1 || csr.EmailAddresses[0] != "gopher@golang.org" {
			t.Errorf("incorrect email addresses found: %v", csr.EmailAddresses)
		}

		if len(csr.DNSNames) != 1 || csr.DNSNames[0] != "test.example.com" {
			t.Errorf("incorrect DNS names found: %v", csr.DNSNames)
		}

		if len(csr.Subject.Country) != 1 || csr.Subject.Country[0] != "AU" {
			t.Errorf("incorrect Subject name: %v", csr.Subject)
		}

		found := false
		for _, e := range csr.Extensions {
			if e.Id.Equal(oidExtensionBasicConstraints) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("basic constraints extension not found in CSR")
		}
	}
}

func TestCriticalFlagInCSRRequestedExtensions(t *testing.T) {
	// This CSR contains an extension request where the extensions have a
	// critical flag in them. In the past we failed to handle this.
	const csrBase64 = "MIICrTCCAZUCAQIwMzEgMB4GA1UEAwwXU0NFUCBDQSBmb3IgRGV2ZWxlciBTcmwxDzANBgNVBAsMBjQzNTk3MTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALFMAJ7Zy9YyfgbNlbUWAW0LalNRMPs7aXmLANsCpjhnw3lLlfDPaLeWyKh1nK5I5ojaJOW6KIOSAcJkDUe3rrE0wR0RVt3UxArqs0R/ND3u5Q+bDQY2X1HAFUHzUzcdm5JRAIA355v90teMckaWAIlkRQjDE22Lzc6NAl64KOd1rqOUNj8+PfX6fSo20jm94Pp1+a6mfk3G/RUWVuSm7owO5DZI/Fsi2ijdmb4NUar6K/bDKYTrDFkzcqAyMfP3TitUtBp19Mp3B1yAlHjlbp/r5fSSXfOGHZdgIvp0WkLuK2u5eQrX5l7HMB/5epgUs3HQxKY6ljhh5wAjDwz//LsCAwEAAaA1MDMGCSqGSIb3DQEJDjEmMCQwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQEFBQADggEBAAMq3bxJSPQEgzLYR/yaVvgjCDrc3zUbIwdOis6Go06Q4RnjH5yRaSZAqZQTDsPurQcnz2I39VMGEiSkFJFavf4QHIZ7QFLkyXadMtALc87tm17Ej719SbHcBSSZayR9VYJUNXRLayI6HvyUrmqcMKh+iX3WY3ICr59/wlM0tYa8DYN4yzmOa2Onb29gy3YlaF5A2AKAMmk003cRT9gY26mjpv7d21czOSSeNyVIoZ04IR9ee71vWTMdv0hu/af5kSjQ+ZG5/Qgc0+mnECLz/1gtxt1srLYbtYQ/qAY8oX1DCSGFS61tN/vl+4cxGMD/VGcGzADRLRHSlVqy2Qgss6Q="

	csrBytes := fromBase64(csrBase64)
	csr, err := ParseCertificateRequest(csrBytes)
	if err != nil {
		t.Fatalf("failed to parse CSR: %s", err)
	}

	expected := []struct {
		Id    asn1.ObjectIdentifier
		Value []byte
	}{
		{oidExtensionBasicConstraints, fromBase64("MAYBAf8CAQA=")},
		{oidExtensionKeyUsage, fromBase64("AwIChA==")},
	}

	if n := len(csr.Extensions); n != len(expected) {
		t.Fatalf("expected to find %d extensions but found %d", len(expected), n)
	}

	for i, extension := range csr.Extensions {
		if !extension.Id.Equal(expected[i].Id) {
			t.Fatalf("extension #%d has unexpected type %v (expected %v)", i, extension.Id, expected[i].Id)
		}

		if !bytes.Equal(extension.Value, expected[i].Value) {
			t.Fatalf("extension #%d has unexpected contents %x (expected %x)", i, extension.Value, expected[i].Value)
		}
	}
}

// serialiseAndParse generates a self-signed certificate from template and
// returns a parsed version of it.
func serialiseAndParse(t *testing.T, template *Certificate) *Certificate {
	derBytes, err := CreateCertificate(rand.Reader, template, template, &testPrivateKey.PublicKey, testPrivateKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %s", err)
		return nil
	}

	cert, err := ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %s", err)
		return nil
	}

	return cert
}

func TestMaxPathLenNotCA(t *testing.T) {
	template := &Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Σ Acme Co",
		},
		NotBefore: time.Unix(1000, 0),
		NotAfter:  time.Unix(100000, 0),

		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	if m := serialiseAndParse(t, template).MaxPathLen; m != -1 {
		t.Errorf("MaxPathLen should be -1 when IsCa is false, got %d", m)
	}

	template.MaxPathLen = -1
	if m := serialiseAndParse(t, template).MaxPathLen; m != -1 {
		t.Errorf("MaxPathLen should be -1 when IsCa is false and MaxPathLen set to -1, got %d", m)
	}

	template.MaxPathLen = 5
	if _, err := CreateCertificate(rand.Reader, template, template, &testPrivateKey.PublicKey, testPrivateKey); err == nil {
		t.Error("specifying a MaxPathLen when IsCA is false should fail")
	}

	template.MaxPathLen = 0
	template.MaxPathLenZero = true
	if _, err := CreateCertificate(rand.Reader, template, template, &testPrivateKey.PublicKey, testPrivateKey); err == nil {
		t.Error("setting MaxPathLenZero when IsCA is false should fail")
	}

	template.BasicConstraintsValid = false
	if m := serialiseAndParse(t, template).MaxPathLen; m != 0 {
		t.Errorf("Bad MaxPathLen should be ignored if BasicConstraintsValid is false, got %d", m)
	}
}

func TestMaxPathLen(t *testing.T) {
	template := &Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Σ Acme Co",
		},
		NotBefore: time.Unix(1000, 0),
		NotAfter:  time.Unix(100000, 0),

		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	cert1 := serialiseAndParse(t, template)
	if m := cert1.MaxPathLen; m != -1 {
		t.Errorf("Omitting MaxPathLen didn't turn into -1, got %d", m)
	}
	if cert1.MaxPathLenZero {
		t.Errorf("Omitting MaxPathLen resulted in MaxPathLenZero")
	}

	template.MaxPathLen = 1
	cert2 := serialiseAndParse(t, template)
	if m := cert2.MaxPathLen; m != 1 {
		t.Errorf("Setting MaxPathLen didn't work. Got %d but set 1", m)
	}
	if cert2.MaxPathLenZero {
		t.Errorf("Setting MaxPathLen resulted in MaxPathLenZero")
	}

	template.MaxPathLen = 0
	template.MaxPathLenZero = true
	cert3 := serialiseAndParse(t, template)
	if m := cert3.MaxPathLen; m != 0 {
		t.Errorf("Setting MaxPathLenZero didn't work, got %d", m)
	}
	if !cert3.MaxPathLenZero {
		t.Errorf("Setting MaxPathLen to zero didn't result in MaxPathLenZero")
	}
}

func TestNoAuthorityKeyIdInSelfSignedCert(t *testing.T) {
	template := &Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Σ Acme Co",
		},
		NotBefore: time.Unix(1000, 0),
		NotAfter:  time.Unix(100000, 0),

		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{1, 2, 3, 4},
	}

	if cert := serialiseAndParse(t, template); len(cert.AuthorityKeyId) != 0 {
		t.Fatalf("self-signed certificate contained default authority key id")
	}

	template.AuthorityKeyId = []byte{1, 2, 3, 4}
	if cert := serialiseAndParse(t, template); len(cert.AuthorityKeyId) == 0 {
		t.Fatalf("self-signed certificate erased explicit authority key id")
	}
}

func TestNoSubjectKeyIdInCert(t *testing.T) {
	template := &Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Σ Acme Co",
		},
		NotBefore: time.Unix(1000, 0),
		NotAfter:  time.Unix(100000, 0),

		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	if cert := serialiseAndParse(t, template); len(cert.SubjectKeyId) == 0 {
		t.Fatalf("self-signed certificate did not generate subject key id using the public key")
	}

	template.IsCA = false
	if cert := serialiseAndParse(t, template); len(cert.SubjectKeyId) != 0 {
		t.Fatalf("self-signed certificate generated subject key id when it isn't a CA")
	}

	template.SubjectKeyId = []byte{1, 2, 3, 4}
	if cert := serialiseAndParse(t, template); len(cert.SubjectKeyId) == 0 {
		t.Fatalf("self-signed certificate erased explicit subject key id")
	}
}

func TestASN1BitLength(t *testing.T) {
	tests := []struct {
		bytes  []byte
		bitLen int
	}{
		{nil, 0},
		{[]byte{0x00}, 0},
		{[]byte{0x00, 0x00}, 0},
		{[]byte{0xf0}, 4},
		{[]byte{0x88}, 5},
		{[]byte{0xff}, 8},
		{[]byte{0xff, 0x80}, 9},
		{[]byte{0xff, 0x81}, 16},
	}

	for i, test := range tests {
		if got := asn1BitLength(test.bytes); got != test.bitLen {
			t.Errorf("#%d: calculated bit-length of %d for %x, wanted %d", i, got, test.bytes, test.bitLen)
		}
	}
}

func TestVerifyEmptyCertificate(t *testing.T) {
	if _, err := new(Certificate).Verify(VerifyOptions{}); err != errNotParsed {
		t.Errorf("Verifying empty certificate resulted in unexpected error: %q (wanted %q)", err, errNotParsed)
	}
}

func TestInsecureAlgorithmErrorString(t *testing.T) {
	tests := []struct {
		sa   SignatureAlgorithm
		want string
	}{
		{MD2WithRSA, "x509: cannot verify signature: insecure algorithm MD2-RSA"},
		{-1, "x509: cannot verify signature: insecure algorithm -1"},
		{0, "x509: cannot verify signature: insecure algorithm 0"},
		{9999, "x509: cannot verify signature: insecure algorithm 9999"},
	}
	for i, tt := range tests {
		if got := fmt.Sprint(InsecureAlgorithmError(tt.sa)); got != tt.want {
			t.Errorf("%d. mismatch.\n got: %s\nwant: %s\n", i, got, tt.want)
		}
	}
}

// These CSR was generated with OpenSSL:
//
//	openssl req -out CSR.csr -new -sha256 -nodes -keyout privateKey.key -config openssl.cnf
//
// With openssl.cnf containing the following sections:
//
//	[ v3_req ]
//	basicConstraints = CA:FALSE
//	keyUsage = nonRepudiation, digitalSignature, keyEncipherment
//	subjectAltName = email:gopher@golang.org,DNS:test.example.com
//	[ req_attributes ]
//	challengePassword = ignored challenge
//	unstructuredName  = ignored unstructured name
var csrBase64Array = [...]string{
	// Just [ v3_req ]
	"MIIDHDCCAgQCAQAwfjELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEUMBIGA1UEAwwLQ29tbW9uIE5hbWUxITAfBgkqhkiG9w0BCQEWEnRlc3RAZW1haWwuYWRkcmVzczCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK1GY4YFx2ujlZEOJxQVYmsjUnLsd5nFVnNpLE4cV+77sgv9NPNlB8uhn3MXt5leD34rm/2BisCHOifPucYlSrszo2beuKhvwn4+2FxDmWtBEMu/QA16L5IvoOfYZm/gJTsPwKDqvaR0tTU67a9OtxwNTBMI56YKtmwd/o8d3hYv9cg+9ZGAZ/gKONcg/OWYx/XRh6bd0g8DMbCikpWgXKDsvvK1Nk+VtkDO1JxuBaj4Lz/p/MifTfnHoqHxWOWl4EaTs4Ychxsv34/rSj1KD1tJqorIv5Xv2aqv4sjxfbrYzX4kvS5SC1goIovLnhj5UjmQ3Qy8u65eow/LLWw+YFcCAwEAAaBZMFcGCSqGSIb3DQEJDjFKMEgwCQYDVR0TBAIwADALBgNVHQ8EBAMCBeAwLgYDVR0RBCcwJYERZ29waGVyQGdvbGFuZy5vcmeCEHRlc3QuZXhhbXBsZS5jb20wDQYJKoZIhvcNAQELBQADggEBAB6VPMRrchvNW61Tokyq3ZvO6/NoGIbuwUn54q6l5VZW0Ep5Nq8juhegSSnaJ0jrovmUgKDN9vEo2KxuAtwG6udS6Ami3zP+hRd4k9Q8djJPb78nrjzWiindLK5Fps9U5mMoi1ER8ViveyAOTfnZt/jsKUaRsscY2FzE9t9/o5moE6LTcHUS4Ap1eheR+J72WOnQYn3cifYaemsA9MJuLko+kQ6xseqttbh9zjqd9fiCSh/LNkzos9c+mg2yMADitaZinAh+HZi50ooEbjaT3erNq9O6RqwJlgD00g6MQdoz9bTAryCUhCQfkIaepmQ7BxS0pqWNW3MMwfDwx/Snz6g=",
	// Both [ v3_req ] and [ req_attributes ]
	"MIIDaTCCAlECAQAwfjELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEUMBIGA1UEAwwLQ29tbW9uIE5hbWUxITAfBgkqhkiG9w0BCQEWEnRlc3RAZW1haWwuYWRkcmVzczCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK1GY4YFx2ujlZEOJxQVYmsjUnLsd5nFVnNpLE4cV+77sgv9NPNlB8uhn3MXt5leD34rm/2BisCHOifPucYlSrszo2beuKhvwn4+2FxDmWtBEMu/QA16L5IvoOfYZm/gJTsPwKDqvaR0tTU67a9OtxwNTBMI56YKtmwd/o8d3hYv9cg+9ZGAZ/gKONcg/OWYx/XRh6bd0g8DMbCikpWgXKDsvvK1Nk+VtkDO1JxuBaj4Lz/p/MifTfnHoqHxWOWl4EaTs4Ychxsv34/rSj1KD1tJqorIv5Xv2aqv4sjxfbrYzX4kvS5SC1goIovLnhj5UjmQ3Qy8u65eow/LLWw+YFcCAwEAAaCBpTAgBgkqhkiG9w0BCQcxEwwRaWdub3JlZCBjaGFsbGVuZ2UwKAYJKoZIhvcNAQkCMRsMGWlnbm9yZWQgdW5zdHJ1Y3R1cmVkIG5hbWUwVwYJKoZIhvcNAQkOMUowSDAJBgNVHRMEAjAAMAsGA1UdDwQEAwIF4DAuBgNVHREEJzAlgRFnb3BoZXJAZ29sYW5nLm9yZ4IQdGVzdC5leGFtcGxlLmNvbTANBgkqhkiG9w0BAQsFAAOCAQEAgxe2N5O48EMsYE7o0rZBB0wi3Ov5/yYfnmmVI22Y3sP6VXbLDW0+UWIeSccOhzUCcZ/G4qcrfhhx6gTZTeA01nP7TdTJURvWAH5iFqj9sQ0qnLq6nEcVHij3sG6M5+BxAIVClQBk6lTCzgphc835Fjj6qSLuJ20XHdL5UfUbiJxx299CHgyBRL+hBUIPfz8p+ZgamyAuDLfnj54zzcRVyLlrmMLNPZNll1Q70RxoU6uWvLH8wB8vQe3Q/guSGubLyLRTUQVPh+dw1L4t8MKFWfX/48jwRM4gIRHFHPeAAE9D9YAoqdIvj/iFm/eQ++7DP8MDwOZWsXeB6jjwHuLmkQ==",
}

var md5cert = `
-----BEGIN CERTIFICATE-----
MIIB4TCCAUoCCQCfmw3vMgPS5TANBgkqhkiG9w0BAQQFADA1MQswCQYDVQQGEwJB
VTETMBEGA1UECBMKU29tZS1TdGF0ZTERMA8GA1UEChMITUQ1IEluYy4wHhcNMTUx
MjAzMTkyOTMyWhcNMjkwODEyMTkyOTMyWjA1MQswCQYDVQQGEwJBVTETMBEGA1UE
CBMKU29tZS1TdGF0ZTERMA8GA1UEChMITUQ1IEluYy4wgZ8wDQYJKoZIhvcNAQEB
BQADgY0AMIGJAoGBANrq2nhLQj5mlXbpVX3QUPhfEm/vdEqPkoWtR/jRZIWm4WGf
Wpq/LKHJx2Pqwn+t117syN8l4U5unyAi1BJSXjBwPZNd7dXjcuJ+bRLV7FZ/iuvs
cfYyQQFTxan4TaJMd0x1HoNDbNbjHa02IyjjYE/r3mb/PIg+J2t5AZEh80lPAgMB
AAEwDQYJKoZIhvcNAQEEBQADgYEAjGzp3K3ey/YfKHohf33yHHWd695HQxDAP+wY
cs9/TAyLR+gJzJP7d18EcDDLJWVi7bhfa4EAD86di05azOh9kWSn4b3o9QYRGCSw
GNnI3Zk0cwNKA49hZntKKiy22DhRk7JAHF01d6Bu3KkHkmENrtJ+zj/+159WAnUa
qViorq4=
-----END CERTIFICATE-----
`

func TestMD5(t *testing.T) {
	pemBlock, _ := pem.Decode([]byte(md5cert))
	cert, err := ParseCertificate(pemBlock.Bytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %s", err)
	}
	if sa := cert.SignatureAlgorithm; sa != MD5WithRSA {
		t.Errorf("signature algorithm is %v, want %v", sa, MD5WithRSA)
	}
	if err = cert.CheckSignatureFrom(cert); err == nil {
		t.Fatalf("certificate verification succeeded incorrectly")
	}
	if _, ok := err.(InsecureAlgorithmError); !ok {
		t.Fatalf("certificate verification returned %v (%T), wanted InsecureAlgorithmError", err, err)
	}
}

// certMissingRSANULL contains an RSA public key where the AlgorithmIdentifier
// parameters are omitted rather than being an ASN.1 NULL.
const certMissingRSANULL = `
-----BEGIN CERTIFICATE-----
MIIB7TCCAVigAwIBAgIBADALBgkqhkiG9w0BAQUwJjEQMA4GA1UEChMHQWNtZSBD
bzESMBAGA1UEAxMJMTI3LjAuMC4xMB4XDTExMTIwODA3NTUxMloXDTEyMTIwNzA4
MDAxMlowJjEQMA4GA1UEChMHQWNtZSBDbzESMBAGA1UEAxMJMTI3LjAuMC4xMIGc
MAsGCSqGSIb3DQEBAQOBjAAwgYgCgYBO0Hsx44Jk2VnAwoekXh6LczPHY1PfZpIG
hPZk1Y/kNqcdK+izIDZFI7Xjla7t4PUgnI2V339aEu+H5Fto5OkOdOwEin/ekyfE
ARl6vfLcPRSr0FTKIQzQTW6HLlzF0rtNS0/Otiz3fojsfNcCkXSmHgwa2uNKWi7e
E5xMQIhZkwIDAQABozIwMDAOBgNVHQ8BAf8EBAMCAKAwDQYDVR0OBAYEBAECAwQw
DwYDVR0jBAgwBoAEAQIDBDALBgkqhkiG9w0BAQUDgYEANh+zegx1yW43RmEr1b3A
p0vMRpqBWHyFeSnIyMZn3TJWRSt1tukkqVCavh9a+hoV2cxVlXIWg7nCto/9iIw4
hB2rXZIxE0/9gzvGnfERYraL7KtnvshksBFQRlgXa5kc0x38BvEO5ZaoDPl4ILdE
GFGNEH5PlGffo05wc46QkYU=
-----END CERTIFICATE-----`

func TestRSAMissingNULLParameters(t *testing.T) {
	block, _ := pem.Decode([]byte(certMissingRSANULL))
	if _, err := ParseCertificate(block.Bytes); err == nil {
		t.Error("unexpected success when parsing certificate with missing RSA NULL parameter")
	} else if !strings.Contains(err.Error(), "missing NULL") {
		t.Errorf("unrecognised error when parsing certificate with missing RSA NULL parameter: %s", err)
	}
}

const certISOOID = `
-----BEGIN CERTIFICATE-----
MIIB5TCCAVKgAwIBAgIQtwyL3RPWV7dJQp34HwZG9DAJBgUrDgMCHQUAMBExDzAN
BgNVBAMTBm15dGVzdDAeFw0xNjA4MDkyMjExMDVaFw0zOTEyMzEyMzU5NTlaMBEx
DzANBgNVBAMTBm15dGVzdDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEArzIH
GsyDB3ohIGkkvijF2PTRUX1bvOtY1eUUpjwHyu0twpAKSuaQv2Ha+/63+aHe8O86
BT+98wjXFX6RFSagtAujo80rIF2dSm33BGt18pDN8v6zp93dnAm0jRaSQrHJ75xw
5O+S1oEYR1LtUoFJy6qB104j6aINBAgOiLIKiMkCAwEAAaNGMEQwQgYDVR0BBDsw
OYAQVuYVQ/WDjdGSkZRlTtJDNKETMBExDzANBgNVBAMTBm15dGVzdIIQtwyL3RPW
V7dJQp34HwZG9DAJBgUrDgMCHQUAA4GBABngrSkH7vG5lY4sa4AZF59lAAXqBVJE
J4TBiKC62hCdZv18rBleP6ETfhbPg7pTs8p4ebQbpmtNxRS9Lw3MzQ8Ya5Ybwzj2
NwBSyCtCQl7mrEg4nJqJl4A2EUhnET/oVxU0oTV/SZ3ziGXcY1oG1s6vidV7TZTu
MCRtdSdaM7g3
-----END CERTIFICATE-----`

func TestISOOIDInCertificate(t *testing.T) {
	block, _ := pem.Decode([]byte(certISOOID))
	if cert, err := ParseCertificate(block.Bytes); err != nil {
		t.Errorf("certificate with ISO OID failed to parse: %s", err)
	} else if cert.SignatureAlgorithm == UnknownSignatureAlgorithm {
		t.Errorf("ISO OID not recognised in certificate")
	}
}

// certMultipleRDN contains a RelativeDistinguishedName with two elements (the
// common name and serial number). This particular certificate was the first
// such certificate in the “Pilot” Certificate Transparency log.
const certMultipleRDN = `
-----BEGIN CERTIFICATE-----
MIIFRzCCBC+gAwIBAgIEOl59NTANBgkqhkiG9w0BAQUFADA9MQswCQYDVQQGEwJz
aTEbMBkGA1UEChMSc3RhdGUtaW5zdGl0dXRpb25zMREwDwYDVQQLEwhzaWdvdi1j
YTAeFw0xMjExMTYxMDUyNTdaFw0xNzExMTYxMjQ5MDVaMIGLMQswCQYDVQQGEwJz
aTEbMBkGA1UEChMSc3RhdGUtaW5zdGl0dXRpb25zMRkwFwYDVQQLExB3ZWItY2Vy
dGlmaWNhdGVzMRAwDgYDVQQLEwdTZXJ2ZXJzMTIwFAYDVQQFEw0xMjM2NDg0MDEw
MDEwMBoGA1UEAxMTZXBvcnRhbC5tc3MuZWR1cy5zaTCCASIwDQYJKoZIhvcNAQEB
BQADggEPADCCAQoCggEBAMrNkZH9MPuBTjMGNk3sJX8V+CkFx/4ru7RTlLS6dlYM
098dtSfJ3s2w0p/1NB9UmR8j0yS0Kg6yoZ3ShsSO4DWBtcQD8820a6BYwqxxQTNf
HSRZOc+N/4TQrvmK6t4k9Aw+YEYTMrWOU4UTeyhDeCcUsBdh7HjfWsVaqNky+2sv
oic3zP5gF+2QfPkvOoHT3FLR8olNhViIE6Kk3eFIEs4dkq/ZzlYdLb8pHQoj/sGI
zFmA5AFvm1HURqOmJriFjBwaCtn8AVEYOtQrnUCzJYu1ex8azyS2ZgYMX0u8A5Z/
y2aMS/B2W+H79WcgLpK28vPwe7vam0oFrVytAd+u65ECAwEAAaOCAf4wggH6MA4G
A1UdDwEB/wQEAwIFoDBABgNVHSAEOTA3MDUGCisGAQQBr1kBAwMwJzAlBggrBgEF
BQcCARYZaHR0cDovL3d3dy5jYS5nb3Yuc2kvY3BzLzAfBgNVHREEGDAWgRRwb2Rw
b3JhLm1pemtzQGdvdi5zaTCB8QYDVR0fBIHpMIHmMFWgU6BRpE8wTTELMAkGA1UE
BhMCc2kxGzAZBgNVBAoTEnN0YXRlLWluc3RpdHV0aW9uczERMA8GA1UECxMIc2ln
b3YtY2ExDjAMBgNVBAMTBUNSTDM5MIGMoIGJoIGGhldsZGFwOi8veDUwMC5nb3Yu
c2kvb3U9c2lnb3YtY2Esbz1zdGF0ZS1pbnN0aXR1dGlvbnMsYz1zaT9jZXJ0aWZp
Y2F0ZVJldm9jYXRpb25MaXN0P2Jhc2WGK2h0dHA6Ly93d3cuc2lnb3YtY2EuZ292
LnNpL2NybC9zaWdvdi1jYS5jcmwwKwYDVR0QBCQwIoAPMjAxMjExMTYxMDUyNTda
gQ8yMDE3MTExNjEyNDkwNVowHwYDVR0jBBgwFoAUHvjUU2uzgwbpBAZXAvmlv8ZY
PHIwHQYDVR0OBBYEFGI1Duuu+wTGDZka/xHNbwcbM69ZMAkGA1UdEwQCMAAwGQYJ
KoZIhvZ9B0EABAwwChsEVjcuMQMCA6gwDQYJKoZIhvcNAQEFBQADggEBAHny0K1y
BQznrzDu3DDpBcGYguKU0dvU9rqsV1ua4nxkriSMWjgsX6XJFDdDW60I3P4VWab5
ag5fZzbGqi8kva/CzGgZh+CES0aWCPy+4Gb8lwOTt+854/laaJvd6kgKTER7z7U9
9C86Ch2y4sXNwwwPJ1A9dmrZJZOcJjS/WYZgwaafY2Hdxub5jqPE5nehwYUPVu9R
uH6/skk4OEKcfOtN0hCnISOVuKYyS4ANARWRG5VGHIH06z3lGUVARFRJ61gtAprd
La+fgSS+LVZ+kU2TkeoWAKvGq8MAgDq4D4Xqwekg7WKFeuyusi/NI5rm40XgjBMF
DF72IUofoVt7wo0=
-----END CERTIFICATE-----`

func TestMultipleRDN(t *testing.T) {
	block, _ := pem.Decode([]byte(certMultipleRDN))
	cert, err := ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("certificate with two elements in an RDN failed to parse: %v", err)
	}

	if want := "eportal.mss.edus.si"; cert.Subject.CommonName != want {
		t.Errorf("got common name of %q, but want %q", cert.Subject.CommonName, want)
	}

	if want := "1236484010010"; cert.Subject.SerialNumber != want {
		t.Errorf("got serial number of %q, but want %q", cert.Subject.SerialNumber, want)
	}
}

func TestSystemCertPool(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("not implemented on Windows; Issue 16736, 18609")
	}
	a, err := SystemCertPool()
	if err != nil {
		t.Fatal(err)
	}
	b, err := SystemCertPool()
	if err != nil {
		t.Fatal(err)
	}
	if !certPoolEqual(a, b) {
		t.Fatal("two calls to SystemCertPool had different results")
	}
	if ok := b.AppendCertsFromPEM([]byte(`
-----BEGIN CERTIFICATE-----
MIIDBjCCAe6gAwIBAgIRANXM5I3gjuqDfTp/PYrs+u8wDQYJKoZIhvcNAQELBQAw
EjEQMA4GA1UEChMHQWNtZSBDbzAeFw0xODAzMjcxOTU2MjFaFw0xOTAzMjcxOTU2
MjFaMBIxEDAOBgNVBAoTB0FjbWUgQ28wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQDK+9m3rjsO2Djes6bIYQZ3eV29JF09ZrjOrEHLtaKrD6/acsoSoTsf
cQr+rzzztdB5ijWXCS64zo/0OiqBeZUNZ67jVdToa9qW5UYe2H0Y+ZNdfA5GYMFD
yk/l3/uBu3suTZPfXiW2TjEi27Q8ruNUIZ54DpTcs6y2rBRFzadPWwn/VQMlvRXM
jrzl8Y08dgnYmaAHprxVzwMXcQ/Brol+v9GvjaH1DooHqkn8O178wsPQNhdtvN01
IXL46cYdcUwWrE/GX5u+9DaSi+0KWxAPQ+NVD5qUI0CKl4714yGGh7feXMjJdHgl
VG4QJZlJvC4FsURgCHJT6uHGIelnSwhbAgMBAAGjVzBVMA4GA1UdDwEB/wQEAwIF
oDATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMCAGA1UdEQQZMBeC
FVRlc3RTeXN0ZW1DZXJ0UG9vbC5nbzANBgkqhkiG9w0BAQsFAAOCAQEAwuSRx/VR
BKh2ICxZjL6jBwk/7UlU1XKbhQD96RqkidDNGEc6eLZ90Z5XXTurEsXqdm5jQYPs
1cdcSW+fOSMl7MfW9e5tM66FaIPZl9rKZ1r7GkOfgn93xdLAWe8XHd19xRfDreub
YC8DVqgLASOEYFupVSl76ktPfxkU5KCvmUf3P2PrRybk1qLGFytGxfyice2gHSNI
gify3K/+H/7wCkyFW4xYvzl7WW4mXxoqPRPjQt1J423DhnnQ4G1P8V/vhUpXNXOq
N9IEPnWuihC09cyx/WMQIUlWnaQLHdfpPS04Iez3yy2PdfXJzwfPrja7rNE+skK6
pa/O1nF0AfWOpw==
-----END CERTIFICATE-----
	`)); !ok {
		t.Fatal("AppendCertsFromPEM failed")
	}
	if reflect.DeepEqual(a, b) {
		t.Fatal("changing one pool modified the other")
	}
}

const emptyNameConstraintsPEM = `
-----BEGIN CERTIFICATE-----
MIIC1jCCAb6gAwIBAgICEjQwDQYJKoZIhvcNAQELBQAwKDEmMCQGA1UEAxMdRW1w
dHkgbmFtZSBjb25zdHJhaW50cyBpc3N1ZXIwHhcNMTMwMjAxMDAwMDAwWhcNMjAw
NTMwMTA0ODM4WjAhMR8wHQYDVQQDExZFbXB0eSBuYW1lIGNvbnN0cmFpbnRzMIIB
IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwriElUIt3LCqmJObs+yDoWPD
F5IqgWk6moIobYjPfextZiYU6I3EfvAwoNxPDkN2WowcocUZMJbEeEq5ebBksFnx
f12gBxlIViIYwZAzu7aFvhDMyPKQI3C8CG0ZSC9ABZ1E3umdA3CEueNOmP/TChNq
Cl23+BG1Qb/PJkpAO+GfpWSVhTcV53Mf/cKvFHcjGNrxzdSoq9fyW7a6gfcGEQY0
LVkmwFWUfJ0wT8kaeLr0E0tozkIfo01KNWNzv6NcYP80QOBRDlApWu9ODmEVJHPD
blx4jzTQ3JLa+4DvBNOjVUOp+mgRmjiW0rLdrxwOxIqIOwNjweMCp/hgxX/hTQID
AQABoxEwDzANBgNVHR4EBjAEoAChADANBgkqhkiG9w0BAQsFAAOCAQEAWG+/zUMH
QhP8uNCtgSHyim/vh7wminwAvWgMKxlkLBFns6nZeQqsOV1lABY7U0Zuoqa1Z5nb
6L+iJa4ElREJOi/erLc9uLwBdDCAR0hUTKD7a6i4ooS39DTle87cUnj0MW1CUa6H
v5SsvpYW+1XleYJk/axQOOTcy4Es53dvnZsjXH0EA/QHnn7UV+JmlE3rtVxcYp6M
LYPmRhTioROA/drghicRkiu9hxdPyxkYS16M5g3Zj30jdm+k/6C6PeNtN9YmOOga
nCOSyFYfGhqOANYzpmuV+oIedAsPpIbfIzN8njYUs1zio+1IoI4o8ddM9sCbtPU8
o+WoY6IsCKXV/g==
-----END CERTIFICATE-----`

func TestEmptyNameConstraints(t *testing.T) {
	block, _ := pem.Decode([]byte(emptyNameConstraintsPEM))
	_, err := ParseCertificate(block.Bytes)
	if err == nil {
		t.Fatal("unexpected success")
	}

	const expected = "empty name constraints"
	if str := err.Error(); !strings.Contains(str, expected) {
		t.Errorf("expected %q in error but got %q", expected, str)
	}
}

func TestPKIXNameString(t *testing.T) {
	der, err := base64.StdEncoding.DecodeString(certBytes)
	if err != nil {
		t.Fatal(err)
	}
	certs, err := ParseCertificates(der)
	if err != nil {
		t.Fatal(err)
	}

	// Check that parsed non-standard attributes are printed.
	//goland:noinspection GoRedundantConversion
	rdns := pkix.Name{
		Locality: []string{"Gophertown"},
		ExtraNames: []pkix.AttributeTypeAndValue{
			{Type: asn1.ObjectIdentifier([]int{1, 2, 3, 4, 5}), Value: "golang.org"}},
	}.ToRDNSequence()
	nn := pkix.Name{}
	nn.FillFromRDNSequence(&rdns)

	// Check that zero-length non-nil ExtraNames hide Names.
	extra := []pkix.AttributeTypeAndValue{
		{Type: asn1.ObjectIdentifier([]int{1, 2, 3, 4, 5}), Value: "backing array"}}
	extraNotNil := pkix.Name{
		Locality:   []string{"Gophertown"},
		ExtraNames: extra[:0],
		Names: []pkix.AttributeTypeAndValue{
			{Type: asn1.ObjectIdentifier([]int{1, 2, 3, 4, 5}), Value: "golang.org"}},
	}

	tests := []struct {
		dn   pkix.Name
		want string
	}{
		{nn, "L=Gophertown,1.2.3.4.5=#130a676f6c616e672e6f7267"},
		{extraNotNil, "L=Gophertown"},
		{pkix.Name{
			CommonName:         "Steve Kille",
			Organization:       []string{"Isode Limited"},
			OrganizationalUnit: []string{"RFCs"},
			Locality:           []string{"Richmond"},
			Province:           []string{"Surrey"},
			StreetAddress:      []string{"The Square"},
			PostalCode:         []string{"TW9 1DT"},
			SerialNumber:       "RFC 2253",
			Country:            []string{"GB"},
		}, "SERIALNUMBER=RFC 2253,CN=Steve Kille,OU=RFCs,O=Isode Limited,POSTALCODE=TW9 1DT,STREET=The Square,L=Richmond,ST=Surrey,C=GB"},
		{certs[0].Subject,
			"CN=mail.google.com,O=Google LLC,L=Mountain View,ST=California,C=US"},
		{pkix.Name{
			Organization: []string{"#Google, Inc. \n-> 'Alphabet\" "},
			Country:      []string{"US"},
		}, "O=\\#Google\\, Inc. \n-\\> 'Alphabet\\\"\\ ,C=US"},
		{pkix.Name{
			CommonName:   "foo.com",
			Organization: []string{"Gopher Industries"},
			ExtraNames: []pkix.AttributeTypeAndValue{
				{Type: asn1.ObjectIdentifier([]int{2, 5, 4, 3}), Value: "bar.com"}},
		}, "CN=bar.com,O=Gopher Industries"},
		{pkix.Name{
			Locality: []string{"Gophertown"},
			ExtraNames: []pkix.AttributeTypeAndValue{
				{Type: asn1.ObjectIdentifier([]int{1, 2, 3, 4, 5}), Value: "golang.org"}},
		}, "1.2.3.4.5=#130a676f6c616e672e6f7267,L=Gophertown"},
		// If there are no ExtraNames, the Names are printed instead.
		{pkix.Name{
			Locality: []string{"Gophertown"},
			Names: []pkix.AttributeTypeAndValue{
				{Type: asn1.ObjectIdentifier([]int{1, 2, 3, 4, 5}), Value: "golang.org"}},
		}, "L=Gophertown,1.2.3.4.5=#130a676f6c616e672e6f7267"},
		// If there are both, print only the ExtraNames.
		{pkix.Name{
			Locality: []string{"Gophertown"},
			ExtraNames: []pkix.AttributeTypeAndValue{
				{Type: asn1.ObjectIdentifier([]int{1, 2, 3, 4, 5}), Value: "golang.org"}},
			Names: []pkix.AttributeTypeAndValue{
				{Type: asn1.ObjectIdentifier([]int{1, 2, 3, 4, 6}), Value: "example.com"}},
		}, "1.2.3.4.5=#130a676f6c616e672e6f7267,L=Gophertown"},
	}

	for i, test := range tests {
		if got := test.dn.String(); got != test.want {
			t.Errorf("#%d: String() = \n%s\n, want \n%s", i, got, test.want)
		}
	}

	if extra[0].Value != "backing array" {
		t.Errorf("the backing array of an empty ExtraNames got modified by String")
	}
}

func TestRDNSequenceString(t *testing.T) {
	// Test some extra cases that get lost in pkix.Name conversions such as
	// multi-valued attributes.

	var (
		oidCountry            = []int{2, 5, 4, 6}
		oidOrganization       = []int{2, 5, 4, 10}
		oidOrganizationalUnit = []int{2, 5, 4, 11}
		oidCommonName         = []int{2, 5, 4, 3}
	)

	tests := []struct {
		seq  pkix.RDNSequence
		want string
	}{
		{
			seq: pkix.RDNSequence{
				pkix.RelativeDistinguishedNameSET{
					pkix.AttributeTypeAndValue{Type: oidCountry, Value: "US"},
				},
				pkix.RelativeDistinguishedNameSET{
					pkix.AttributeTypeAndValue{Type: oidOrganization, Value: "Widget Inc."},
				},
				pkix.RelativeDistinguishedNameSET{
					pkix.AttributeTypeAndValue{Type: oidOrganizationalUnit, Value: "Sales"},
					pkix.AttributeTypeAndValue{Type: oidCommonName, Value: "J. Smith"},
				},
			},
			want: "OU=Sales+CN=J. Smith,O=Widget Inc.,C=US",
		},
	}

	for i, test := range tests {
		if got := test.seq.String(); got != test.want {
			t.Errorf("#%d: String() = \n%s\n, want \n%s", i, got, test.want)
		}
	}
}

const criticalNameConstraintWithUnknownTypePEM = `
-----BEGIN CERTIFICATE-----
MIIC/TCCAeWgAwIBAgICEjQwDQYJKoZIhvcNAQELBQAwKDEmMCQGA1UEAxMdRW1w
dHkgbmFtZSBjb25zdHJhaW50cyBpc3N1ZXIwHhcNMTMwMjAxMDAwMDAwWhcNMjAw
NTMwMTA0ODM4WjAhMR8wHQYDVQQDExZFbXB0eSBuYW1lIGNvbnN0cmFpbnRzMIIB
IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwriElUIt3LCqmJObs+yDoWPD
F5IqgWk6moIobYjPfextZiYU6I3EfvAwoNxPDkN2WowcocUZMJbEeEq5ebBksFnx
f12gBxlIViIYwZAzu7aFvhDMyPKQI3C8CG0ZSC9ABZ1E3umdA3CEueNOmP/TChNq
Cl23+BG1Qb/PJkpAO+GfpWSVhTcV53Mf/cKvFHcjGNrxzdSoq9fyW7a6gfcGEQY0
LVkmwFWUfJ0wT8kaeLr0E0tozkIfo01KNWNzv6NcYP80QOBRDlApWu9ODmEVJHPD
blx4jzTQ3JLa+4DvBNOjVUOp+mgRmjiW0rLdrxwOxIqIOwNjweMCp/hgxX/hTQID
AQABozgwNjA0BgNVHR4BAf8EKjAooCQwIokgIACrzQAAAAAAAAAAAAAAAP////8A
AAAAAAAAAAAAAAChADANBgkqhkiG9w0BAQsFAAOCAQEAWG+/zUMHQhP8uNCtgSHy
im/vh7wminwAvWgMKxlkLBFns6nZeQqsOV1lABY7U0Zuoqa1Z5nb6L+iJa4ElREJ
Oi/erLc9uLwBdDCAR0hUTKD7a6i4ooS39DTle87cUnj0MW1CUa6Hv5SsvpYW+1Xl
eYJk/axQOOTcy4Es53dvnZsjXH0EA/QHnn7UV+JmlE3rtVxcYp6MLYPmRhTioROA
/drghicRkiu9hxdPyxkYS16M5g3Zj30jdm+k/6C6PeNtN9YmOOganCOSyFYfGhqO
ANYzpmuV+oIedAsPpIbfIzN8njYUs1zio+1IoI4o8ddM9sCbtPU8o+WoY6IsCKXV
/g==
-----END CERTIFICATE-----`

func TestCriticalNameConstraintWithUnknownType(t *testing.T) {
	block, _ := pem.Decode([]byte(criticalNameConstraintWithUnknownTypePEM))
	cert, err := ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("unexpected parsing failure: %s", err)
	}

	if l := len(cert.UnhandledCriticalExtensions); l != 1 {
		t.Fatalf("expected one unhandled critical extension, but found %d", l)
	}
}

const badIPMaskPEM = `
-----BEGIN CERTIFICATE-----
MIICzzCCAbegAwIBAgICEjQwDQYJKoZIhvcNAQELBQAwHTEbMBkGA1UEAxMSQmFk
IElQIG1hc2sgaXNzdWVyMB4XDTEzMDIwMTAwMDAwMFoXDTIwMDUzMDEwNDgzOFow
FjEUMBIGA1UEAxMLQmFkIElQIG1hc2swggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQDCuISVQi3csKqYk5uz7IOhY8MXkiqBaTqagihtiM997G1mJhTojcR+
8DCg3E8OQ3ZajByhxRkwlsR4Srl5sGSwWfF/XaAHGUhWIhjBkDO7toW+EMzI8pAj
cLwIbRlIL0AFnUTe6Z0DcIS5406Y/9MKE2oKXbf4EbVBv88mSkA74Z+lZJWFNxXn
cx/9wq8UdyMY2vHN1Kir1/JbtrqB9wYRBjQtWSbAVZR8nTBPyRp4uvQTS2jOQh+j
TUo1Y3O/o1xg/zRA4FEOUCla704OYRUkc8NuXHiPNNDcktr7gO8E06NVQ6n6aBGa
OJbSst2vHA7Eiog7A2PB4wKn+GDFf+FNAgMBAAGjIDAeMBwGA1UdHgEB/wQSMBCg
DDAKhwgBAgME//8BAKEAMA0GCSqGSIb3DQEBCwUAA4IBAQBYb7/NQwdCE/y40K2B
IfKKb++HvCaKfAC9aAwrGWQsEWezqdl5Cqw5XWUAFjtTRm6iprVnmdvov6IlrgSV
EQk6L96stz24vAF0MIBHSFRMoPtrqLiihLf0NOV7ztxSePQxbUJRroe/lKy+lhb7
VeV5gmT9rFA45NzLgSznd2+dmyNcfQQD9AeeftRX4maUTeu1XFxinowtg+ZGFOKh
E4D92uCGJxGSK72HF0/LGRhLXozmDdmPfSN2b6T/oLo942031iY46BqcI5LIVh8a
Go4A1jOma5X6gh50Cw+kht8jM3yeNhSzXOKj7Uigjijx10z2wJu09Tyj5ahjoiwI
pdX+
-----END CERTIFICATE-----`

func TestBadIPMask(t *testing.T) {
	block, _ := pem.Decode([]byte(badIPMaskPEM))
	_, err := ParseCertificate(block.Bytes)
	if err == nil {
		t.Fatalf("unexpected success")
	}

	const expected = "contained invalid mask"
	if !strings.Contains(err.Error(), expected) {
		t.Fatalf("expected %q in error but got: %s", expected, err)
	}
}

const additionalGeneralSubtreePEM = `
-----BEGIN CERTIFICATE-----
MIIG4TCCBMmgAwIBAgIRALss+4rLw2Ia7tFFhxE8g5cwDQYJKoZIhvcNAQELBQAw
bjELMAkGA1UEBhMCTkwxIDAeBgNVBAoMF01pbmlzdGVyaWUgdmFuIERlZmVuc2ll
MT0wOwYDVQQDDDRNaW5pc3RlcmllIHZhbiBEZWZlbnNpZSBDZXJ0aWZpY2F0aWUg
QXV0b3JpdGVpdCAtIEcyMB4XDTEzMDMwNjEyMDM0OVoXDTEzMTEzMDEyMDM1MFow
bDELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUNlcnRpUGF0aCBMTEMxIjAgBgNVBAsT
GUNlcnRpZmljYXRpb24gQXV0aG9yaXRpZXMxITAfBgNVBAMTGENlcnRpUGF0aCBC
cmlkZ2UgQ0EgLSBHMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANLW
4kXiRqvwBhJfN9uz12FA+P2D34MPxOt7TGXljm2plJ2CLzvaH8/ymsMdSWdJBS1M
8FmwvNL1w3A6ZuzksJjPikAu8kY3dcp3mrkk9eCPORDAwGtfsXwZysLiuEaDWpbD
dHOaHnI6qWU0N6OI+hNX58EjDpIGC1WQdho1tHOTPc5Hf5/hOpM/29v/wr7kySjs
Z+7nsvkm5rNhuJNzPsLsgzVaJ5/BVyOplZy24FKM8Y43MjR4osZm+a2e0zniqw6/
rvcjcGYabYaznZfQG1GXoyf2Vea+CCgpgUhlVafgkwEs8izl8rIpvBzXiFAgFQuG
Ituoy92PJbDs430fA/cCAwEAAaOCAnowggJ2MEUGCCsGAQUFBwEBBDkwNzA1Bggr
BgEFBQcwAoYpaHR0cDovL2NlcnRzLmNhLm1pbmRlZi5ubC9taW5kZWYtY2EtMi5w
N2MwHwYDVR0jBBgwFoAUzln9WSPz2M64Rl2HYf2/KD8StmQwDwYDVR0TAQH/BAUw
AwEB/zCB6QYDVR0gBIHhMIHeMEgGCmCEEAGHawECBQEwOjA4BggrBgEFBQcCARYs
aHR0cDovL2Nwcy5kcC5jYS5taW5kZWYubmwvbWluZGVmLWNhLWRwLWNwcy8wSAYK
YIQQAYdrAQIFAjA6MDgGCCsGAQUFBwIBFixodHRwOi8vY3BzLmRwLmNhLm1pbmRl
Zi5ubC9taW5kZWYtY2EtZHAtY3BzLzBIBgpghBABh2sBAgUDMDowOAYIKwYBBQUH
AgEWLGh0dHA6Ly9jcHMuZHAuY2EubWluZGVmLm5sL21pbmRlZi1jYS1kcC1jcHMv
MDkGA1UdHwQyMDAwLqAsoCqGKGh0dHA6Ly9jcmxzLmNhLm1pbmRlZi5ubC9taW5k
ZWYtY2EtMi5jcmwwDgYDVR0PAQH/BAQDAgEGMEYGA1UdHgEB/wQ8MDqhODA2pDEw
LzELMAkGA1UEBhMCTkwxIDAeBgNVBAoTF01pbmlzdGVyaWUgdmFuIERlZmVuc2ll
gQFjMF0GA1UdIQRWMFQwGgYKYIQQAYdrAQIFAQYMKwYBBAGBu1MBAQECMBoGCmCE
EAGHawECBQIGDCsGAQQBgbtTAQEBAjAaBgpghBABh2sBAgUDBgwrBgEEAYG7UwEB
AQIwHQYDVR0OBBYEFNDCjBM3M3ZKkag84ei3/aKc0d0UMA0GCSqGSIb3DQEBCwUA
A4ICAQAQXFn9jF90/DNFf15JhoGtta/0dNInb14PMu3PAjcdrXYCDPpQZOArTUng
5YT1WuzfmjnXiTsziT3my0r9Mxvz/btKK/lnVOMW4c2q/8sIsIPnnW5ZaRGrsANB
dNDZkzMYmeG2Pfgvd0AQSOrpE/TVgWfu/+MMRWwX9y6VbooBR7BLv7zMuVH0WqLn
6OMFth7fqsThlfMSzkE/RDSaU6n3wXAWT1SIqBITtccRjSUQUFm/q3xrb2cwcZA6
8vdS4hzNd+ttS905ay31Ks4/1Wrm1bH5RhEfRSH0VSXnc0b+z+RyBbmiwtVZqzxE
u3UQg/rAmtLDclLFEzjp8YDTIRYSLwstDbEXO/0ArdGrQm79HQ8i/3ZbP2357myW
i15qd6gMJIgGHS4b8Hc7R1K8LQ9Gm1aLKBEWVNGZlPK/cpXThpVmoEyslN2DHCrc
fbMbjNZpXlTMa+/b9z7Fa4X8dY8u/ELzZuJXJv5Rmqtg29eopFFYDCl0Nkh1XAjo
QejEoHHUvYV8TThHZr6Z6Ib8CECgTehU4QvepkgDXNoNrKRZBG0JhLjkwxh2whZq
nvWBfALC2VuNOM6C0rDY+HmhMlVt0XeqnybD9MuQALMit7Z00Cw2CIjNsBI9xBqD
xKK9CjUb7gzRUWSpB9jGHsvpEMHOzIFhufvH2Bz1XJw+Cl7khw==
-----END CERTIFICATE-----`

func TestAdditionFieldsInGeneralSubtree(t *testing.T) {
	// Very rarely, certificates can include additional fields in the
	// GeneralSubtree structure. This tests that such certificates can be
	// parsed.
	block, _ := pem.Decode([]byte(additionalGeneralSubtreePEM))
	if _, err := ParseCertificate(block.Bytes); err != nil {
		t.Fatalf("failed to parse certificate: %s", err)
	}
}

func TestEmptySubject(t *testing.T) {
	template := Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{"example.com"},
	}

	derBytes, err := CreateCertificate(rand.Reader, &template, &template, &testPrivateKey.PublicKey, testPrivateKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %s", err)
	}

	cert, err := ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %s", err)
	}

	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidExtensionSubjectAltName) {
			if !ext.Critical {
				t.Fatal("SAN extension is not critical")
			}
			return
		}
	}

	t.Fatal("SAN extension is missing")
}

// multipleURLsInCRLDPPEM contains two URLs in a single CRL DistributionPoint
// structure. It is taken from https://crt.sh/?id=12721534.
const multipleURLsInCRLDPPEM = `
-----BEGIN CERTIFICATE-----
MIIF4TCCBMmgAwIBAgIQc+6uFePfrahUGpXs8lhiTzANBgkqhkiG9w0BAQsFADCB
8zELMAkGA1UEBhMCRVMxOzA5BgNVBAoTMkFnZW5jaWEgQ2F0YWxhbmEgZGUgQ2Vy
dGlmaWNhY2lvIChOSUYgUS0wODAxMTc2LUkpMSgwJgYDVQQLEx9TZXJ2ZWlzIFB1
YmxpY3MgZGUgQ2VydGlmaWNhY2lvMTUwMwYDVQQLEyxWZWdldSBodHRwczovL3d3
dy5jYXRjZXJ0Lm5ldC92ZXJhcnJlbCAoYykwMzE1MDMGA1UECxMsSmVyYXJxdWlh
IEVudGl0YXRzIGRlIENlcnRpZmljYWNpbyBDYXRhbGFuZXMxDzANBgNVBAMTBkVD
LUFDQzAeFw0xNDA5MTgwODIxMDBaFw0zMDA5MTgwODIxMDBaMIGGMQswCQYDVQQG
EwJFUzEzMDEGA1UECgwqQ09OU09SQ0kgQURNSU5JU1RSQUNJTyBPQkVSVEEgREUg
Q0FUQUxVTllBMSowKAYDVQQLDCFTZXJ2ZWlzIFDDumJsaWNzIGRlIENlcnRpZmlj
YWNpw7MxFjAUBgNVBAMMDUVDLUNpdXRhZGFuaWEwggEiMA0GCSqGSIb3DQEBAQUA
A4IBDwAwggEKAoIBAQDFkHPRZPZlXTWZ5psJhbS/Gx+bxcTpGrlVQHHtIkgGz77y
TA7UZUFb2EQMncfbOhR0OkvQQn1aMvhObFJSR6nI+caf2D+h/m/InMl1MyH3S0Ak
YGZZsthnyC6KxqK2A/NApncrOreh70ULkQs45aOKsi1kR1W0zE+iFN+/P19P7AkL
Rl3bXBCVd8w+DLhcwRrkf1FCDw6cEqaFm3cGgf5cbBDMaVYAweWTxwBZAq2RbQAW
jE7mledcYghcZa4U6bUmCBPuLOnO8KMFAvH+aRzaf3ws5/ZoOVmryyLLJVZ54peZ
OwnP9EL4OuWzmXCjBifXR2IAblxs5JYj57tls45nAgMBAAGjggHaMIIB1jASBgNV
HRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUC2hZPofI
oxUa4ECCIl+fHbLFNxUwHwYDVR0jBBgwFoAUoMOLRKo3pUW/l4Ba0fF4opvpXY0w
gdYGA1UdIASBzjCByzCByAYEVR0gADCBvzAxBggrBgEFBQcCARYlaHR0cHM6Ly93
d3cuYW9jLmNhdC9DQVRDZXJ0L1JlZ3VsYWNpbzCBiQYIKwYBBQUHAgIwfQx7QXF1
ZXN0IGNlcnRpZmljYXQgw6lzIGVtw6hzIMO6bmljYSBpIGV4Y2x1c2l2YW1lbnQg
YSBFbnRpdGF0cyBkZSBDZXJ0aWZpY2FjacOzLiBWZWdldSBodHRwczovL3d3dy5h
b2MuY2F0L0NBVENlcnQvUmVndWxhY2lvMDMGCCsGAQUFBwEBBCcwJTAjBggrBgEF
BQcwAYYXaHR0cDovL29jc3AuY2F0Y2VydC5jYXQwYgYDVR0fBFswWTBXoFWgU4Yn
aHR0cDovL2Vwc2NkLmNhdGNlcnQubmV0L2NybC9lYy1hY2MuY3JshihodHRwOi8v
ZXBzY2QyLmNhdGNlcnQubmV0L2NybC9lYy1hY2MuY3JsMA0GCSqGSIb3DQEBCwUA
A4IBAQChqFTjlAH5PyIhLjLgEs68CyNNC1+vDuZXRhy22TI83JcvGmQrZosPvVIL
PsUXx+C06Pfqmh48Q9S89X9K8w1SdJxP/rZeGEoRiKpwvQzM4ArD9QxyC8jirxex
3Umg9Ai/sXQ+1lBf6xw4HfUUr1WIp7pNHj0ZWLo106urqktcdeAFWme+/klis5fu
labCSVPuT/QpwakPrtqOhRms8vgpKiXa/eLtL9ZiA28X/Mker0zlAeTA7Z7uAnp6
oPJTlZu1Gg1ZDJueTWWsLlO+P+Wzm3MRRIbcgdRzm4mdO7ubu26SzX/aQXDhuih+
eVxXDTCfs7GUlxnjOp5j559X/N0A
-----END CERTIFICATE-----
`

func TestMultipleURLsInCRLDP(t *testing.T) {
	block, _ := pem.Decode([]byte(multipleURLsInCRLDPPEM))
	cert, err := ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %s", err)
	}

	//goland:noinspection HttpUrlsUsage
	want := []string{
		"http://epscd.catcert.net/crl/ec-acc.crl",
		"http://epscd2.catcert.net/crl/ec-acc.crl",
	}
	if got := cert.CRLDistributionPoints; !reflect.DeepEqual(got, want) {
		t.Errorf("CRL distribution points = %#v, want #%v", got, want)
	}
}

const hexPKCS1TestPKCS8Key = "30820278020100300d06092a864886f70d0101010500048202623082025e02010002818100cfb1b5bf9685ffa97b4f99df4ff122b70e59ac9b992f3bc2b3dde17d53c1a34928719b02e8fd17839499bfbd515bd6ef99c7a1c47a239718fe36bfd824c0d96060084b5f67f0273443007a24dfaf5634f7772c9346e10eb294c2306671a5a5e719ae24b4de467291bc571014b0e02dec04534d66a9bb171d644b66b091780e8d020301000102818100b595778383c4afdbab95d2bfed12b3f93bb0a73a7ad952f44d7185fd9ec6c34de8f03a48770f2009c8580bcd275e9632714e9a5e3f32f29dc55474b2329ff0ebc08b3ffcb35bc96e6516b483df80a4a59cceb71918cbabf91564e64a39d7e35dce21cb3031824fdbc845dba6458852ec16af5dddf51a8397a8797ae0337b1439024100ea0eb1b914158c70db39031dd8904d6f18f408c85fbbc592d7d20dee7986969efbda081fdf8bc40e1b1336d6b638110c836bfdc3f314560d2e49cd4fbde1e20b024100e32a4e793b574c9c4a94c8803db5152141e72d03de64e54ef2c8ed104988ca780cd11397bc359630d01b97ebd87067c5451ba777cf045ca23f5912f1031308c702406dfcdbbd5a57c9f85abc4edf9e9e29153507b07ce0a7ef6f52e60dcfebe1b8341babd8b789a837485da6c8d55b29bbb142ace3c24a1f5b54b454d01b51e2ad03024100bd6a2b60dee01e1b3bfcef6a2f09ed027c273cdbbaf6ba55a80f6dcc64e4509ee560f84b4f3e076bd03b11e42fe71a3fdd2dffe7e0902c8584f8cad877cdc945024100aa512fa4ada69881f1d8bb8ad6614f192b83200aef5edf4811313d5ef30a86cbd0a90f7b025c71ea06ec6b34db6306c86b1040670fd8654ad7291d066d06d031"
const hexPKCS1TestECKey = "3081a40201010430bdb9839c08ee793d1157886a7a758a3c8b2a17a4df48f17ace57c72c56b4723cf21dcda21d4e1ad57ff034f19fcfd98ea00706052b81040022a16403620004feea808b5ee2429cfcce13c32160e1c960990bd050bb0fdf7222f3decd0a55008e32a6aa3c9062051c4cba92a7a3b178b24567412d43cdd2f882fa5addddd726fe3e208d2c26d733a773a597abb749714df7256ead5105fa6e7b3650de236b50"

var pkcs1MismatchKeyTests = []struct {
	hexKey        string
	errorContains string
}{
	{hexKey: hexPKCS1TestPKCS8Key, errorContains: "use ParsePKCS8PrivateKey instead"},
	{hexKey: hexPKCS1TestECKey, errorContains: "use ParseECPrivateKey instead"},
}

func TestPKCS1MismatchKeyFormat(t *testing.T) {
	for i, test := range pkcs1MismatchKeyTests {
		derBytes, _ := hex.DecodeString(test.hexKey)
		_, err := ParsePKCS1PrivateKey(derBytes)
		if !strings.Contains(err.Error(), test.errorContains) {
			t.Errorf("#%d: expected error containing %q, got %s", i, test.errorContains, err)
		}
	}
}

func TestCreateRevocationList(t *testing.T) {
	ec256Priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA P256 key: %s", err)
	}
	_, ed25519Priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %s", err)
	}
	tests := []struct {
		name          string
		key           crypto.Signer
		issuer        *Certificate
		template      *RevocationList
		expectedError string
	}{
		{
			name:          "nil template",
			key:           ec256Priv,
			issuer:        nil,
			template:      nil,
			expectedError: "x509: template can not be nil",
		},
		{
			name:          "nil issuer",
			key:           ec256Priv,
			issuer:        nil,
			template:      &RevocationList{},
			expectedError: "x509: issuer can not be nil",
		},
		{
			name: "issuer doesn't have crlSign key usage bit set",
			key:  ec256Priv,
			issuer: &Certificate{
				KeyUsage: KeyUsageCertSign,
			},
			template:      &RevocationList{},
			expectedError: "x509: issuer must have the crlSign key usage bit set",
		},
		{
			name: "issuer missing SubjectKeyId",
			key:  ec256Priv,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
			},
			template:      &RevocationList{},
			expectedError: "x509: issuer certificate doesn't contain a subject key identifier",
		},
		{
			name: "nextUpdate before thisUpdate",
			key:  ec256Priv,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				ThisUpdate: time.Time{}.Add(time.Hour),
				NextUpdate: time.Time{},
			},
			expectedError: "x509: template.ThisUpdate is after template.NextUpdate",
		},
		{
			name: "nil Number",
			key:  ec256Priv,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
			},
			expectedError: "x509: template contains nil Number field",
		},
		{
			name: "invalid signature algorithm",
			key:  ec256Priv,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				SignatureAlgorithm: SHA256WithRSA,
				RevokedCertificates: []pkix.RevokedCertificate{
					{
						SerialNumber:   big.NewInt(2),
						RevocationTime: time.Time{}.Add(time.Hour),
					},
				},
				Number:     big.NewInt(5),
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
			},
			expectedError: "x509: requested SignatureAlgorithm does not match private key type",
		},
		{
			name: "valid",
			key:  ec256Priv,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				RevokedCertificates: []pkix.RevokedCertificate{
					{
						SerialNumber:   big.NewInt(2),
						RevocationTime: time.Time{}.Add(time.Hour),
					},
				},
				Number:     big.NewInt(5),
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
			},
		},
		{
			name: "valid, Ed25519 key",
			key:  ed25519Priv,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				RevokedCertificates: []pkix.RevokedCertificate{
					{
						SerialNumber:   big.NewInt(2),
						RevocationTime: time.Time{}.Add(time.Hour),
					},
				},
				Number:     big.NewInt(5),
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
			},
		},
		{
			name: "valid, non-default signature algorithm",
			key:  ec256Priv,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				SignatureAlgorithm: ECDSAWithSHA512,
				RevokedCertificates: []pkix.RevokedCertificate{
					{
						SerialNumber:   big.NewInt(2),
						RevocationTime: time.Time{}.Add(time.Hour),
					},
				},
				Number:     big.NewInt(5),
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
			},
		},
		{
			name: "valid, extra extension",
			key:  ec256Priv,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				RevokedCertificates: []pkix.RevokedCertificate{
					{
						SerialNumber:   big.NewInt(2),
						RevocationTime: time.Time{}.Add(time.Hour),
					},
				},
				Number:     big.NewInt(5),
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
				ExtraExtensions: []pkix.Extension{
					{
						Id:    []int{2, 5, 29, 99},
						Value: []byte{5, 0},
					},
				},
			},
		},
		{
			name: "valid, empty list",
			key:  ec256Priv,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				Number:     big.NewInt(5),
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			crl, err := CreateRevocationList(rand.Reader, tc.template, tc.issuer, tc.key)
			if err != nil && tc.expectedError == "" {
				t.Fatalf("CreateRevocationList failed unexpectedly: %s", err)
			} else if err != nil && tc.expectedError != err.Error() {
				t.Fatalf("CreateRevocationList failed unexpectedly, wanted: %s, got: %s", tc.expectedError, err)
			} else if err == nil && tc.expectedError != "" {
				t.Fatalf("CreateRevocationList didn't fail, expected: %s", tc.expectedError)
			}
			if tc.expectedError != "" {
				return
			}

			parsedCRL, err := ParseDERCRL(crl)
			if err != nil {
				t.Fatalf("Failed to parse generated CRL: %s", err)
			}

			if tc.template.SignatureAlgorithm != UnknownSignatureAlgorithm &&
				parsedCRL.SignatureAlgorithm.Algorithm.Equal(signatureAlgorithmDetails[tc.template.SignatureAlgorithm].oid) {
				t.Fatalf("SignatureAlgorithm mismatch: got %v; want %v.", parsedCRL.SignatureAlgorithm,
					tc.template.SignatureAlgorithm)
			}

			if !reflect.DeepEqual(parsedCRL.TBSCertList.RevokedCertificates, tc.template.RevokedCertificates) {
				t.Fatalf("RevokedCertificates mismatch: got %v; want %v.",
					parsedCRL.TBSCertList.RevokedCertificates, tc.template.RevokedCertificates)
			}

			if len(parsedCRL.TBSCertList.Extensions) != 2+len(tc.template.ExtraExtensions) {
				t.Fatalf("Generated CRL has wrong number of extensions, wanted: %d, got: %d", 2+len(tc.template.ExtraExtensions), len(parsedCRL.TBSCertList.Extensions))
			}
			expectedAKI, err := asn1.Marshal(authKeyId{Id: tc.issuer.SubjectKeyId})
			if err != nil {
				t.Fatalf("asn1.Marshal failed: %s", err)
			}
			akiExt := pkix.Extension{
				Id:    oidExtensionAuthorityKeyId,
				Value: expectedAKI,
			}
			if !reflect.DeepEqual(parsedCRL.TBSCertList.Extensions[0], akiExt) {
				t.Fatalf("Unexpected first extension: got %v, want %v",
					parsedCRL.TBSCertList.Extensions[0], akiExt)
			}
			expectedNum, err := asn1.Marshal(tc.template.Number)
			if err != nil {
				t.Fatalf("asn1.Marshal failed: %s", err)
			}
			crlExt := pkix.Extension{
				Id:    oidExtensionCRLNumber,
				Value: expectedNum,
			}
			if !reflect.DeepEqual(parsedCRL.TBSCertList.Extensions[1], crlExt) {
				t.Fatalf("Unexpected second extension: got %v, want %v",
					parsedCRL.TBSCertList.Extensions[1], crlExt)
			}
			if len(parsedCRL.TBSCertList.Extensions[2:]) == 0 && len(tc.template.ExtraExtensions) == 0 {
				// If we don't have anything to check return early so we don't
				// hit a [] != nil false positive below.
				return
			}
			if !reflect.DeepEqual(parsedCRL.TBSCertList.Extensions[2:], tc.template.ExtraExtensions) {
				t.Fatalf("Extensions mismatch: got %v; want %v.",
					parsedCRL.TBSCertList.Extensions[2:], tc.template.ExtraExtensions)
			}
		})
	}
}

func TestRSAPSAParameters(t *testing.T) {
	generateParams := func(hashFunc Hash) []byte {
		var hashOID asn1.ObjectIdentifier

		switch hashFunc {
		case SHA256:
			hashOID = oidSHA256
		case SHA384:
			hashOID = oidSHA384
		case SHA512:
			hashOID = oidSHA512
		}

		params := pssParameters{
			Hash: pkix.AlgorithmIdentifier{
				Algorithm:  hashOID,
				Parameters: asn1.NullRawValue,
			},
			MGF: pkix.AlgorithmIdentifier{
				Algorithm: oidMGF1,
			},
			SaltLength:   hashFunc.Size(),
			TrailerField: 1,
		}

		mgf1Params := pkix.AlgorithmIdentifier{
			Algorithm:  hashOID,
			Parameters: asn1.NullRawValue,
		}

		var err error
		params.MGF.Parameters.FullBytes, err = asn1.Marshal(mgf1Params)
		if err != nil {
			t.Fatalf("failed to marshal MGF parameters: %s", err)
		}

		serialized, err := asn1.Marshal(params)
		if err != nil {
			t.Fatalf("failed to marshal parameters: %s", err)
		}

		return serialized
	}

	for h, params := range hashToPSSParameters {
		generated := generateParams(h)
		if !bytes.Equal(params.FullBytes, generated) {
			t.Errorf("hardcoded parameters for %s didn't match generated parameters: got (generated) %x, wanted (hardcoded) %x", h, generated, params.FullBytes)
		}
	}
}

func TestUnknownExtKey(t *testing.T) {
	const errorContains = "unknown extended key usage"

	template := &Certificate{
		SerialNumber: big.NewInt(10),
		DNSNames:     []string{"foo"},
		ExtKeyUsage:  []ExtKeyUsage{ExtKeyUsage(-1)},
	}
	signer, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Errorf("failed to generate key for TestUnknownExtKey")
	}

	_, err = CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	if !strings.Contains(err.Error(), errorContains) {
		t.Errorf("expected error containing %q, got %s", errorContains, err)
	}
}

func TestIA5SANEnforcement(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey failed: %s", err)
	}

	testURL, err := url.Parse("https://example.com/")
	if err != nil {
		t.Fatalf("url.Parse failed: %s", err)
	}
	testURL.RawQuery = "∞"

	marshalTests := []struct {
		name          string
		template      *Certificate
		expectedError string
	}{
		{
			name: "marshal: unicode dNSName",
			template: &Certificate{
				SerialNumber: big.NewInt(0),
				DNSNames:     []string{"∞"},
			},
			expectedError: "x509: \"∞\" cannot be encoded as an IA5String",
		},
		{
			name: "marshal: unicode rfc822Name",
			template: &Certificate{
				SerialNumber:   big.NewInt(0),
				EmailAddresses: []string{"∞"},
			},
			expectedError: "x509: \"∞\" cannot be encoded as an IA5String",
		},
		{
			name: "marshal: unicode uniformResourceIdentifier",
			template: &Certificate{
				SerialNumber: big.NewInt(0),
				URIs:         []*url.URL{testURL},
			},
			expectedError: "x509: \"https://example.com/?∞\" cannot be encoded as an IA5String",
		},
	}

	for _, tc := range marshalTests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CreateCertificate(rand.Reader, tc.template, tc.template, k.Public(), k)
			if err == nil {
				t.Errorf("expected CreateCertificate to fail with template: %v", tc.template)
			} else if err.Error() != tc.expectedError {
				t.Errorf("unexpected error: got %q, want %q", err.Error(), tc.expectedError)
			}
		})
	}

	unmarshalTests := []struct {
		name          string
		cert          string
		expectedError string
	}{
		{
			name:          "unmarshal: unicode dNSName",
			cert:          "308201083081aea003020102020100300a06082a8648ce3d04030230003022180f30303031303130313030303030305a180f30303031303130313030303030305a30003059301306072a8648ce3d020106082a8648ce3d0301070342000424bcc48180d8d9db794028f2575ebe3cac79f04d7b0d0151c5292e588aac3668c495f108c626168462e0668c9705e08a211dd103a659d2684e0adf8c2bfd47baa315301330110603551d110101ff040730058203e2889e300a06082a8648ce3d04030203490030460221008ac7827ac326a6ee0fa70b2afe99af575ec60b975f820f3c25f60fff43fbccd0022100bffeed93556722d43d13e461d5b3e33efc61f6349300327d3a0196cb6da501c2",
			expectedError: "x509: SAN dNSName is malformed",
		},
		{
			name:          "unmarshal: unicode rfc822Name",
			cert:          "308201083081aea003020102020100300a06082a8648ce3d04030230003022180f30303031303130313030303030305a180f30303031303130313030303030305a30003059301306072a8648ce3d020106082a8648ce3d0301070342000405cb4c4ba72aac980f7b11b0285191425e29e196ce7c5df1c83f56886566e517f196657cc1b73de89ab84ce503fd634e2f2af88fde24c63ca536dc3a5eed2665a315301330110603551d110101ff040730058103e2889e300a06082a8648ce3d0403020349003046022100ed1431cd4b9bb03d88d1511a0ec128a51204375764c716280dc36e2a60142c8902210088c96d25cfaf97eea851ff17d87bb6fe619d6546656e1739f35c3566051c3d0f",
			expectedError: "x509: SAN rfc822Name is malformed",
		},
		{
			name:          "unmarshal: unicode uniformResourceIdentifier",
			cert:          "3082011b3081c3a003020102020100300a06082a8648ce3d04030230003022180f30303031303130313030303030305a180f30303031303130313030303030305a30003059301306072a8648ce3d020106082a8648ce3d03010703420004ce0a79b511701d9188e1ea76bcc5907f1db51de6cc1a037b803f256e8588145ca409d120288bfeb4e38f3088104674d374b35bb91fc80d768d1d519dbe2b0b5aa32a302830260603551d110101ff041c301a861868747470733a2f2f6578616d706c652e636f6d2f3fe2889e300a06082a8648ce3d0403020347003044022044f4697779fd1dae1e382d2452413c5c5ca67851e267d6bc64a8d164977c172c0220505015e657637aa1945d46e7650b6f59b968fc1508ca8b152c99f782446dfc81",
			expectedError: "x509: SAN uniformResourceIdentifier is malformed",
		},
	}

	for _, tc := range unmarshalTests {
		der, err := hex.DecodeString(tc.cert)
		if err != nil {
			t.Fatalf("failed to decode test cert: %s", err)
		}
		_, err = ParseCertificate(der)
		if err == nil {
			t.Error("expected CreateCertificate to fail")
		} else if err.Error() != tc.expectedError {
			t.Errorf("unexpected error: got %q, want %q", err.Error(), tc.expectedError)
		}
	}
}

func BenchmarkCreateCertificate(b *testing.B) {
	template := &Certificate{
		SerialNumber: big.NewInt(10),
		DNSNames:     []string{"example.com"},
	}
	tests := []struct {
		name string
		gen  func() crypto.Signer
	}{
		{
			name: "RSA 2048",
			gen: func() crypto.Signer {
				k, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					b.Fatalf("failed to generate test key: %s", err)
				}
				return k
			},
		},
		{
			name: "ECDSA P256",
			gen: func() crypto.Signer {
				k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					b.Fatalf("failed to generate test key: %s", err)
				}
				return k
			},
		},
	}

	for _, tc := range tests {
		k := tc.gen()
		b.ResetTimer()
		b.Run(tc.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, err := CreateCertificate(rand.Reader, template, template, k.Public(), k)
				if err != nil {
					b.Fatalf("failed to create certificate: %s", err)
				}
			}
		})
	}
}

type brokenSigner struct {
	pub crypto.PublicKey
}

func (bs *brokenSigner) Public() crypto.PublicKey {
	return bs.pub
}

func (bs *brokenSigner) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return []byte{1, 2, 3}, nil
}

func TestCreateCertificateBrokenSigner(t *testing.T) {
	template := &Certificate{
		SerialNumber: big.NewInt(10),
		DNSNames:     []string{"example.com"},
	}
	k, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("failed to generate test key: %s", err)
	}
	expectedErr := "x509: signature over certificate returned by signer is invalid: crypto/rsa: verification error"
	_, err = CreateCertificate(rand.Reader, template, template, k.Public(), &brokenSigner{k.Public()})
	if err == nil {
		t.Fatal("expected CreateCertificate to fail with a broken signer")
	} else if err.Error() != expectedErr {
		t.Fatalf("CreateCertificate returned an unexpected error: got %q, want %q", err, expectedErr)
	}
}

func TestCreateCertificateMD5(t *testing.T) {
	template := &Certificate{
		SerialNumber:       big.NewInt(10),
		DNSNames:           []string{"example.com"},
		SignatureAlgorithm: MD5WithRSA,
	}
	k, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("failed to generate test key: %s", err)
	}
	_, err = CreateCertificate(rand.Reader, template, template, k.Public(), &brokenSigner{k.Public()})
	if err != nil {
		t.Fatalf("CreateCertificate failed when SignatureAlgorithm = MD5WithRSA: %s", err)
	}
}

func (s *CertPool) mustCert(t *testing.T, n int) *Certificate {
	c, err := s.lazyCerts[n].getCert()
	if err != nil {
		t.Fatalf("failed to load cert %d: %v", n, err)
	}
	return c
}

func allCerts(t *testing.T, p *CertPool) []*Certificate {
	all := make([]*Certificate, p.len())
	for i := range all {
		all[i] = p.mustCert(t, i)
	}
	return all
}

// certPoolEqual reports whether a and b are equal, except for the
// function pointers.
func certPoolEqual(a, b *CertPool) bool {
	if (a != nil) != (b != nil) {
		return false
	}
	if a == nil {
		return true
	}
	if !reflect.DeepEqual(a.byName, b.byName) ||
		len(a.lazyCerts) != len(b.lazyCerts) {
		return false
	}
	for i := range a.lazyCerts {
		la, lb := a.lazyCerts[i], b.lazyCerts[i]
		if !bytes.Equal(la.rawSubject, lb.rawSubject) {
			return false
		}
		ca, err := la.getCert()
		if err != nil {
			panic(err)
		}
		cb, err := la.getCert()
		if err != nil {
			panic(err)
		}
		if !ca.Equal(cb) {
			return false
		}
	}

	return true
}

func TestCertificateRequestRoundtripFields(t *testing.T) {
	urlA, err := url.Parse("https://example.com/_")
	if err != nil {
		t.Fatal(err)
	}
	urlB, err := url.Parse("https://example.org/_")
	if err != nil {
		t.Fatal(err)
	}
	in := &CertificateRequest{
		DNSNames:       []string{"example.com", "example.org"},
		EmailAddresses: []string{"a@example.com", "b@example.com"},
		IPAddresses:    []net.IP{net.IPv4(192, 0, 2, 0), net.IPv6loopback},
		URIs:           []*url.URL{urlA, urlB},
	}
	out := marshalAndParseCSR(t, in)

	if !reflect.DeepEqual(in.DNSNames, out.DNSNames) {
		t.Fatalf("Unexpected DNSNames: got %v, want %v", out.DNSNames, in.DNSNames)
	}
	if !reflect.DeepEqual(in.EmailAddresses, out.EmailAddresses) {
		t.Fatalf("Unexpected EmailAddresses: got %v, want %v", out.EmailAddresses, in.EmailAddresses)
	}
	if len(in.IPAddresses) != len(out.IPAddresses) ||
		!in.IPAddresses[0].Equal(out.IPAddresses[0]) ||
		!in.IPAddresses[1].Equal(out.IPAddresses[1]) {
		t.Fatalf("Unexpected IPAddresses: got %v, want %v", out.IPAddresses, in.IPAddresses)
	}
	if !reflect.DeepEqual(in.URIs, out.URIs) {
		t.Fatalf("Unexpected URIs: got %v, want %v", out.URIs, in.URIs)
	}
}

func BenchmarkParseCertificate(b *testing.B) {
	cases := []struct {
		name string
		pem  string
	}{
		{
			name: "ecdsa leaf",
			pem: `-----BEGIN CERTIFICATE-----
MIIINjCCBx6gAwIBAgIQHdQ6oBMoe/MJAAAAAEHzmTANBgkqhkiG9w0BAQsFADBG
MQswCQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2VzIExM
QzETMBEGA1UEAxMKR1RTIENBIDFDMzAeFw0yMDEyMDgwOTExMzZaFw0yMTAzMDIw
OTExMzVaMBcxFTATBgNVBAMMDCouZ29vZ2xlLmNvbTBZMBMGByqGSM49AgEGCCqG
SM49AwEHA0IABEFYegyHh1AHRS1nar5+zYJgMACcsIQMtg0YMyK/59ml8ERIt/JF
kXM3XIvQuCJhghUawZrrAcAs8djZF1U9M4mjggYYMIIGFDAOBgNVHQ8BAf8EBAMC
B4AwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQU
6SWWF36XBsmXJ6iV0EHPXUFoMbwwHwYDVR0jBBgwFoAUinR/r4XN7pXNPZzQ4kYU
83E1HScwagYIKwYBBQUHAQEEXjBcMCcGCCsGAQUFBzABhhtodHRwOi8vb2NzcC5w
a2kuZ29vZy9ndHMxYzMwMQYIKwYBBQUHMAKGJWh0dHA6Ly9wa2kuZ29vZy9yZXBv
L2NlcnRzL2d0czFjMy5kZXIwggTCBgNVHREEggS5MIIEtYIMKi5nb29nbGUuY29t
gg0qLmFuZHJvaWQuY29tghYqLmFwcGVuZ2luZS5nb29nbGUuY29tggkqLmJkbi5k
ZXaCEiouY2xvdWQuZ29vZ2xlLmNvbYIYKi5jcm93ZHNvdXJjZS5nb29nbGUuY29t
ghgqLmRhdGFjb21wdXRlLmdvb2dsZS5jb22CBiouZy5jb4IOKi5nY3AuZ3Z0Mi5j
b22CESouZ2NwY2RuLmd2dDEuY29tggoqLmdncGh0LmNugg4qLmdrZWNuYXBwcy5j
boIWKi5nb29nbGUtYW5hbHl0aWNzLmNvbYILKi5nb29nbGUuY2GCCyouZ29vZ2xl
LmNsgg4qLmdvb2dsZS5jby5pboIOKi5nb29nbGUuY28uanCCDiouZ29vZ2xlLmNv
LnVrgg8qLmdvb2dsZS5jb20uYXKCDyouZ29vZ2xlLmNvbS5hdYIPKi5nb29nbGUu
Y29tLmJygg8qLmdvb2dsZS5jb20uY2+CDyouZ29vZ2xlLmNvbS5teIIPKi5nb29n
bGUuY29tLnRygg8qLmdvb2dsZS5jb20udm6CCyouZ29vZ2xlLmRlggsqLmdvb2ds
ZS5lc4ILKi5nb29nbGUuZnKCCyouZ29vZ2xlLmh1ggsqLmdvb2dsZS5pdIILKi5n
b29nbGUubmyCCyouZ29vZ2xlLnBsggsqLmdvb2dsZS5wdIISKi5nb29nbGVhZGFw
aXMuY29tgg8qLmdvb2dsZWFwaXMuY26CESouZ29vZ2xlY25hcHBzLmNughQqLmdv
b2dsZWNvbW1lcmNlLmNvbYIRKi5nb29nbGV2aWRlby5jb22CDCouZ3N0YXRpYy5j
boINKi5nc3RhdGljLmNvbYISKi5nc3RhdGljY25hcHBzLmNuggoqLmd2dDEuY29t
ggoqLmd2dDIuY29tghQqLm1ldHJpYy5nc3RhdGljLmNvbYIMKi51cmNoaW4uY29t
ghAqLnVybC5nb29nbGUuY29tghMqLndlYXIuZ2tlY25hcHBzLmNughYqLnlvdXR1
YmUtbm9jb29raWUuY29tgg0qLnlvdXR1YmUuY29tghYqLnlvdXR1YmVlZHVjYXRp
b24uY29tghEqLnlvdXR1YmVraWRzLmNvbYIHKi55dC5iZYILKi55dGltZy5jb22C
GmFuZHJvaWQuY2xpZW50cy5nb29nbGUuY29tggthbmRyb2lkLmNvbYIbZGV2ZWxv
cGVyLmFuZHJvaWQuZ29vZ2xlLmNughxkZXZlbG9wZXJzLmFuZHJvaWQuZ29vZ2xl
LmNuggRnLmNvgghnZ3BodC5jboIMZ2tlY25hcHBzLmNuggZnb28uZ2yCFGdvb2ds
ZS1hbmFseXRpY3MuY29tggpnb29nbGUuY29tgg9nb29nbGVjbmFwcHMuY26CEmdv
b2dsZWNvbW1lcmNlLmNvbYIYc291cmNlLmFuZHJvaWQuZ29vZ2xlLmNuggp1cmNo
aW4uY29tggp3d3cuZ29vLmdsggh5b3V0dS5iZYILeW91dHViZS5jb22CFHlvdXR1
YmVlZHVjYXRpb24uY29tgg95b3V0dWJla2lkcy5jb22CBXl0LmJlMCEGA1UdIAQa
MBgwCAYGZ4EMAQIBMAwGCisGAQQB1nkCBQMwNQYDVR0fBC4wLDAqoCigJoYkaHR0
cDovL2NybC5wa2kuZ29vZy9ndHNyMS9ndHMxYzMuY3JsMBMGCisGAQQB1nkCBAMB
Af8EAgUAMA0GCSqGSIb3DQEBCwUAA4IBAQAlDQm5zY7JcPxcJ9ulfTGsWV/m6Pro
gLYmAlBUPGKy313aetT4Zjz44ZseVtUOKsXVHh4avPA9O+ta1FgkASlbkgJ05ivb
j/+MMqkrLemdMv9Svvx3CNaAq2jJ2E+8GdrA1RzMkiNthJCiRafaPnXnN6hOHGNr
GtqYfMHsvrRHW8J2IPHW0/MUHmJ/NDu/vNchxke2OEfCPLtseo3hJt8l8HbH+yE8
DFrt8YVRi1CLomEyuPJDF4og3O3ZsoXuxcPd9UPxULOCxycdolRw8Iv/Xgr082j3
svXC3HUd3apM2Yy3xJAlk/mUkzVXfdJZ+Zy1huNsUoJ+gM8rmpyGhYyx
-----END CERTIFICATE-----`,
		},
		{
			name: "rsa leaf",
			pem: `-----BEGIN CERTIFICATE-----
MIIJXjCCCEagAwIBAgIRAPYaTUsjP4iRBQAAAACHSSgwDQYJKoZIhvcNAQELBQAw
QjELMAkGA1UEBhMCVVMxHjAcBgNVBAoTFUdvb2dsZSBUcnVzdCBTZXJ2aWNlczET
MBEGA1UEAxMKR1RTIENBIDFPMTAeFw0yMTAxMjYwODQ2MzRaFw0yMTA0MjAwODQ2
MzNaMGYxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQH
Ew1Nb3VudGFpbiBWaWV3MRMwEQYDVQQKEwpHb29nbGUgTExDMRUwEwYDVQQDDAwq
Lmdvb2dsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC76xx0
UdZ36/41rZNPfQ/yQ05vsBLUO0d+3uMOhvDlpst+XvIsG6L+vLDgf3RiQRFlei0h
KqqLOtWLDc/y0+OmaaC+8ft1zljBYdvQlAYoZrT79Cc5pAIDq7G1OZ7cC4ahDno/
n46FHjT/UTUAMYa8cKWBaMPneMIsKvn8nMdZzHkfO2nUd6OEecn90XweMvNmx8De
6h5AlIgG3m66hkD/UCSdxn7yJHBQVdHgkfTqzv3sz2YyBQGNi288F1bn541f6khE
fYti1MvXRtkky7yLCQNUG6PtvuSU4cKaNvRklHigf5i1nVdGEuH61gAElZIklSia
OVK46UyU4DGtbdWNAgMBAAGjggYpMIIGJTAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0l
BAwwCgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQU8zCvllLd3jhB
k//+Wdjo40Q+T3gwHwYDVR0jBBgwFoAUmNH4bhDrz5vsYJ8YkBug630J/SswaAYI
KwYBBQUHAQEEXDBaMCsGCCsGAQUFBzABhh9odHRwOi8vb2NzcC5wa2kuZ29vZy9n
dHMxbzFjb3JlMCsGCCsGAQUFBzAChh9odHRwOi8vcGtpLmdvb2cvZ3NyMi9HVFMx
TzEuY3J0MIIE1wYDVR0RBIIEzjCCBMqCDCouZ29vZ2xlLmNvbYINKi5hbmRyb2lk
LmNvbYIWKi5hcHBlbmdpbmUuZ29vZ2xlLmNvbYIJKi5iZG4uZGV2ghIqLmNsb3Vk
Lmdvb2dsZS5jb22CGCouY3Jvd2Rzb3VyY2UuZ29vZ2xlLmNvbYIYKi5kYXRhY29t
cHV0ZS5nb29nbGUuY29tghMqLmZsYXNoLmFuZHJvaWQuY29tggYqLmcuY2+CDiou
Z2NwLmd2dDIuY29tghEqLmdjcGNkbi5ndnQxLmNvbYIKKi5nZ3BodC5jboIOKi5n
a2VjbmFwcHMuY26CFiouZ29vZ2xlLWFuYWx5dGljcy5jb22CCyouZ29vZ2xlLmNh
ggsqLmdvb2dsZS5jbIIOKi5nb29nbGUuY28uaW6CDiouZ29vZ2xlLmNvLmpwgg4q
Lmdvb2dsZS5jby51a4IPKi5nb29nbGUuY29tLmFygg8qLmdvb2dsZS5jb20uYXWC
DyouZ29vZ2xlLmNvbS5icoIPKi5nb29nbGUuY29tLmNvgg8qLmdvb2dsZS5jb20u
bXiCDyouZ29vZ2xlLmNvbS50coIPKi5nb29nbGUuY29tLnZuggsqLmdvb2dsZS5k
ZYILKi5nb29nbGUuZXOCCyouZ29vZ2xlLmZyggsqLmdvb2dsZS5odYILKi5nb29n
bGUuaXSCCyouZ29vZ2xlLm5sggsqLmdvb2dsZS5wbIILKi5nb29nbGUucHSCEiou
Z29vZ2xlYWRhcGlzLmNvbYIPKi5nb29nbGVhcGlzLmNughEqLmdvb2dsZWNuYXBw
cy5jboIUKi5nb29nbGVjb21tZXJjZS5jb22CESouZ29vZ2xldmlkZW8uY29tggwq
LmdzdGF0aWMuY26CDSouZ3N0YXRpYy5jb22CEiouZ3N0YXRpY2NuYXBwcy5jboIK
Ki5ndnQxLmNvbYIKKi5ndnQyLmNvbYIUKi5tZXRyaWMuZ3N0YXRpYy5jb22CDCou
dXJjaGluLmNvbYIQKi51cmwuZ29vZ2xlLmNvbYITKi53ZWFyLmdrZWNuYXBwcy5j
boIWKi55b3V0dWJlLW5vY29va2llLmNvbYINKi55b3V0dWJlLmNvbYIWKi55b3V0
dWJlZWR1Y2F0aW9uLmNvbYIRKi55b3V0dWJla2lkcy5jb22CByoueXQuYmWCCyou
eXRpbWcuY29tghphbmRyb2lkLmNsaWVudHMuZ29vZ2xlLmNvbYILYW5kcm9pZC5j
b22CG2RldmVsb3Blci5hbmRyb2lkLmdvb2dsZS5jboIcZGV2ZWxvcGVycy5hbmRy
b2lkLmdvb2dsZS5jboIEZy5jb4IIZ2dwaHQuY26CDGdrZWNuYXBwcy5jboIGZ29v
LmdsghRnb29nbGUtYW5hbHl0aWNzLmNvbYIKZ29vZ2xlLmNvbYIPZ29vZ2xlY25h
cHBzLmNughJnb29nbGVjb21tZXJjZS5jb22CGHNvdXJjZS5hbmRyb2lkLmdvb2ds
ZS5jboIKdXJjaGluLmNvbYIKd3d3Lmdvby5nbIIIeW91dHUuYmWCC3lvdXR1YmUu
Y29tghR5b3V0dWJlZWR1Y2F0aW9uLmNvbYIPeW91dHViZWtpZHMuY29tggV5dC5i
ZTAhBgNVHSAEGjAYMAgGBmeBDAECAjAMBgorBgEEAdZ5AgUDMDMGA1UdHwQsMCow
KKAmoCSGImh0dHA6Ly9jcmwucGtpLmdvb2cvR1RTMU8xY29yZS5jcmwwEwYKKwYB
BAHWeQIEAwEB/wQCBQAwDQYJKoZIhvcNAQELBQADggEBAHh9/ozYUGRd+W5akWlM
4WvX808TK2oUISnagbxCCFZ2trpg2oi03CJf4o4o3Je5Qzzz10s22oQY6gPHAR0B
QHzrpqAveQw9D5vd8xjgtQ/SAujPzPKNQee5511rS7/EKW9I83ccd5XhhoEyx8A1
/65RTS+2hKpJKTMkr0yHBPJV7kUW+n/KIef5YaSOA9VYK7hyH0niDpvm9EmoqvWS
U5xAFAe/Xrrq3sxTuDJPQA8alk6h/ql5Klkw6dL53csiPka/MevDqdifWkzuT/6n
YK/ePeJzPD17FA9V+N1rcuF3Wk29AZvCOSasdIkIuE82vGr3dfNrsrn9E9lWIbCr
Qc4=
-----END CERTIFICATE-----`,
		},
	}
	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			pemBlock, _ := pem.Decode([]byte(c.pem))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := ParseCertificate(pemBlock.Bytes)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestParseCertificateRawEquals(t *testing.T) {
	p, _ := pem.Decode([]byte(pemCertificate))
	cert, err := ParseCertificate(p.Bytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %s", err)
	}
	if !bytes.Equal(p.Bytes, cert.Raw) {
		t.Fatalf("unexpected Certificate.Raw\ngot: %x\nwant: %x\n", cert.Raw, p.Bytes)
	}
	fmt.Printf("in:  %x\nout: %x\n", p.Bytes, cert.Raw)
}

// mismatchingSigAlgIDPEM contains a certificate where the Certificate
// signatureAlgorithm and the TBSCertificate signature contain
// mismatching OIDs
const mismatchingSigAlgIDPEM = `-----BEGIN CERTIFICATE-----
MIIBBzCBrqADAgECAgEAMAoGCCqGSM49BAMCMAAwIhgPMDAwMTAxMDEwMDAwMDBa
GA8wMDAxMDEwMTAwMDAwMFowADBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABOqV
EDuVXxwZgIU3+dOwv1SsMu0xuV48hf7xmK8n7sAMYgllB+96DnPqBeboJj4snYnx
0AcE0PDVQ1l4Z3YXsQWjFTATMBEGA1UdEQEB/wQHMAWCA2FzZDAKBggqhkjOPQQD
AwNIADBFAiBi1jz/T2HT5nAfrD7zsgR+68qh7Erc6Q4qlxYBOgKG4QIhAOtjIn+Q
tA+bq+55P3ntxTOVRq0nv1mwnkjwt9cQR9Fn
-----END CERTIFICATE-----`

// mismatchingSigAlgParamPEM contains a certificate where the Certificate
// signatureAlgorithm and the TBSCertificate signature contain
// mismatching parameters
const mismatchingSigAlgParamPEM = `-----BEGIN CERTIFICATE-----
MIIBCTCBrqADAgECAgEAMAoGCCqGSM49BAMCMAAwIhgPMDAwMTAxMDEwMDAwMDBa
GA8wMDAxMDEwMTAwMDAwMFowADBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABOqV
EDuVXxwZgIU3+dOwv1SsMu0xuV48hf7xmK8n7sAMYgllB+96DnPqBeboJj4snYnx
0AcE0PDVQ1l4Z3YXsQWjFTATMBEGA1UdEQEB/wQHMAWCA2FzZDAMBggqhkjOPQQD
AgUAA0gAMEUCIGLWPP9PYdPmcB+sPvOyBH7ryqHsStzpDiqXFgE6AobhAiEA62Mi
f5C0D5ur7nk/ee3FM5VGrSe/WbCeSPC31xBH0Wc=
-----END CERTIFICATE-----`

func TestSigAlgMismatch(t *testing.T) {
	for _, certPEM := range []string{mismatchingSigAlgIDPEM, mismatchingSigAlgParamPEM} {
		b, _ := pem.Decode([]byte(certPEM))
		if b == nil {
			t.Fatalf("couldn't decode test certificate")
		}
		_, err := ParseCertificate(b.Bytes)
		if err == nil {
			t.Fatalf("expected ParseCertificate to fail")
		}
		expected := "x509: inner and outer signature algorithm identifiers don't match"
		if err.Error() != expected {
			t.Errorf("unexpected error from ParseCertificate: got %q, want %q", err.Error(), expected)
		}
	}
}

const optionalAuthKeyIDPEM = `-----BEGIN CERTIFICATE-----
MIIFEjCCBHugAwIBAgICAQwwDQYJKoZIhvcNAQEFBQAwgbsxJDAiBgNVBAcTG1Zh
bGlDZXJ0IFZhbGlkYXRpb24gTmV0d29yazEXMBUGA1UEChMOVmFsaUNlcnQsIElu
Yy4xNTAzBgNVBAsTLFZhbGlDZXJ0IENsYXNzIDIgUG9saWN5IFZhbGlkYXRpb24g
QXV0aG9yaXR5MSEwHwYDVQQDExhodHRwOi8vd3d3LnZhbGljZXJ0LmNvbS8xIDAe
BgkqhkiG9w0BCQEWEWluZm9AdmFsaWNlcnQuY29tMB4XDTA0MDYyOTE3MzkxNloX
DTI0MDYyOTE3MzkxNlowaDELMAkGA1UEBhMCVVMxJTAjBgNVBAoTHFN0YXJmaWVs
ZCBUZWNobm9sb2dpZXMsIEluYy4xMjAwBgNVBAsTKVN0YXJmaWVsZCBDbGFzcyAy
IENlcnRpZmljYXRpb24gQXV0aG9yaXR5MIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0A
MIIBCAKCAQEAtzLI/ulxpgSFrQwRZN/OTe/IAxiHP6Gr+zymn/DDodrU2G4rU5D7
JKQ+hPCe6F/s5SdE9SimP3ve4CrwyK9TL57KBQGTHo9mHDmnTfpatnMEJWbrd3/n
WcZKmSUUVOsmx/N/GdUwcI+vsEYq/63rKe3Xn6oEh6PU+YmlNF/bQ5GCNtlmPLG4
uYL9nDo+EMg77wZlZnqbGRg9/3FRPDAuX749d3OyXQZswyNWmiuFJpIcpwKz5D8N
rwh5grg2Peqc0zWzvGnK9cyd6P1kjReAM25eSl2ZyR6HtJ0awNVuEzUjXt+bXz3v
1vd2wuo+u3gNHEJnawTY+Nbab4vyRKABqwIBA6OCAfMwggHvMB0GA1UdDgQWBBS/
X7fRzt0fhvRbVazc1xDCDqmI5zCB0gYDVR0jBIHKMIHHoYHBpIG+MIG7MSQwIgYD
VQQHExtWYWxpQ2VydCBWYWxpZGF0aW9uIE5ldHdvcmsxFzAVBgNVBAoTDlZhbGlD
ZXJ0LCBJbmMuMTUwMwYDVQQLEyxWYWxpQ2VydCBDbGFzcyAyIFBvbGljeSBWYWxp
ZGF0aW9uIEF1dGhvcml0eTEhMB8GA1UEAxMYaHR0cDovL3d3dy52YWxpY2VydC5j
b20vMSAwHgYJKoZIhvcNAQkBFhFpbmZvQHZhbGljZXJ0LmNvbYIBATAPBgNVHRMB
Af8EBTADAQH/MDkGCCsGAQUFBwEBBC0wKzApBggrBgEFBQcwAYYdaHR0cDovL29j
c3Auc3RhcmZpZWxkdGVjaC5jb20wSgYDVR0fBEMwQTA/oD2gO4Y5aHR0cDovL2Nl
cnRpZmljYXRlcy5zdGFyZmllbGR0ZWNoLmNvbS9yZXBvc2l0b3J5L3Jvb3QuY3Js
MFEGA1UdIARKMEgwRgYEVR0gADA+MDwGCCsGAQUFBwIBFjBodHRwOi8vY2VydGlm
aWNhdGVzLnN0YXJmaWVsZHRlY2guY29tL3JlcG9zaXRvcnkwDgYDVR0PAQH/BAQD
AgEGMA0GCSqGSIb3DQEBBQUAA4GBAKVi8afCXSWlcD284ipxs33kDTcdVWptobCr
mADkhWBKIMuh8D1195TaQ39oXCUIuNJ9MxB73HZn8bjhU3zhxoNbKXuNSm8uf0So
GkVrMgfHeMpkksK0hAzc3S1fTbvdiuo43NlmouxBulVtWmQ9twPMHOKRUJ7jCUSV
FxdzPcwl
-----END CERTIFICATE-----`

func TestAuthKeyIdOptional(t *testing.T) {
	b, _ := pem.Decode([]byte(optionalAuthKeyIDPEM))
	if b == nil {
		t.Fatalf("couldn't decode test certificate")
	}
	_, err := ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate to failed to parse certificate with optional authority key identifier fields: %s", err)
	}
}

// 国密相关测试案例

func TestX509(t *testing.T) {
	// 生成sm2密钥对
	// priv, err := sm2.GenerateKey(nil)
	priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// 生成私钥文件字节流
	privPem, err := WritePrivateKeyToPem(priv, nil)
	if err != nil {
		t.Fatal(err)
	}
	pubKey, _ := priv.Public().(*sm2.PublicKey)
	// 生成公钥文件字节流
	pubkeyPem, _ := WritePublicKeyToPem(pubKey)
	// 读取私钥
	privKey, err := ReadPrivateKeyFromPem(privPem, nil)
	if err != nil {
		t.Fatal(err)
	}
	// 读取公钥
	pkTmp, err := ReadPublicKeyFromPem(pubkeyPem)
	if err != nil {
		t.Fatal(err)
	}
	pubKey = pkTmp.(*sm2.PublicKey)
	// 定义证书申请模板
	templateReq := CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "pangzi.com",
			Organization: []string{"PANGZIXIEHUI"},
		},
		//		SignatureAlgorithm: ECDSAWithSHA256,
		SignatureAlgorithm: SM2WithSM3,
	}
	// 创建证书申请pem字节流并签名
	reqPem, err := CreateCertificateRequestToPem(&templateReq, privKey)
	if err != nil {
		t.Fatal(err)
	}
	// 从pem读取证书申请
	req, err := ReadCertificateRequestFromPem(reqPem)
	if err != nil {
		t.Fatal(err)
	}
	// 检查证书申请的签名
	err = req.CheckSignature()
	if err != nil {
		t.Fatalf("Request CheckSignature error:%v", err)
	} else {
		fmt.Printf("CheckSignature ok\n")
	}
	testExtKeyUsage := []ExtKeyUsage{ExtKeyUsageClientAuth, ExtKeyUsageServerAuth}
	testUnknownExtKeyUsage := []asn1.ObjectIdentifier{[]int{1, 2, 3}, []int{2, 59, 1}}
	extraExtensionData := []byte("extra extension")
	commonName := "pangzi.com"
	// 定义证书模板
	//goland:noinspection HttpUrlsUsage
	template := Certificate{
		// SerialNumber is negative to ensure that negative
		// values are parsed. This is due to the prevalence of
		// buggy code that produces certificates with negative
		// serial numbers.
		SerialNumber: big.NewInt(-1),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"PANGZIXIEHUI"},
			Country:      []string{"China"},
			ExtraNames: []pkix.AttributeTypeAndValue{
				{
					Type:  []int{2, 5, 4, 42},
					Value: "Gopher",
				},
				// This should override the Country, above.
				{
					Type:  []int{2, 5, 4, 6},
					Value: "NL",
				},
			},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Date(2032, time.December, 31, 23, 59, 59, 1, time.UTC),

		//		SignatureAlgorithm: ECDSAWithSHA256,
		SignatureAlgorithm: SM2WithSM3,

		SubjectKeyId: []byte{1, 2, 3, 4},
		KeyUsage:     KeyUsageCertSign,

		ExtKeyUsage:        testExtKeyUsage,
		UnknownExtKeyUsage: testUnknownExtKeyUsage,

		BasicConstraintsValid: true,
		IsCA:                  true,

		OCSPServer:            []string{"http://ocsp.pangzi.com"},
		IssuingCertificateURL: []string{"http://crt.pangzi.com/ca1.crt"},

		DNSNames:       []string{"pangzi.com"},
		EmailAddresses: []string{"gopher@golang.org"},
		IPAddresses:    []net.IP{net.IPv4(127, 0, 0, 1).To4(), net.ParseIP("2001:4860:0:2001::68")},

		PolicyIdentifiers:   []asn1.ObjectIdentifier{[]int{1, 2, 3}},
		PermittedDNSDomains: []string{".pangzi.com", "pangzi.com"},

		CRLDistributionPoints: []string{"http://crl1.pangzi.com/ca1.crl", "http://crl2.pangzi.com/ca1.crl"},

		ExtraExtensions: []pkix.Extension{
			{
				Id:    []int{1, 2, 3, 4},
				Value: extraExtensionData,
			},
			// This extension should override the SubjectKeyId, above.
			{
				Id:       oidExtensionSubjectKeyId,
				Critical: false,
				Value:    []byte{0x04, 0x04, 4, 3, 2, 1},
			},
		},
	}
	// pubKey, _ = priv.Public().(*sm2.PublicKey)
	// 创建证书pem字节流
	certpem, err := CreateCertificateToPem(&template, &template, pubKey, privKey)
	if err != nil {
		t.Fatal("failed to create cert file")
	}
	// 读取证书pem
	cert, err := ReadCertificateFromPem(certpem)
	if err != nil {
		t.Fatal("failed to read cert file")
	}
	// 检查证书签名
	err = cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
	if err != nil {
		t.Fatal(err)
	} else {
		fmt.Printf("CheckSignature ok\n")
	}
}

func TestX509WithFile(t *testing.T) {
	// 生成sm2密钥对
	priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := &priv.PublicKey
	// 生成私钥pem文件
	_, err = WritePrivateKeytoPemFile("testdata/pri_key.pem", priv, nil)
	if err != nil {
		t.Fatal(err)
	}
	// 生成公钥pem文件
	_, err = WritePublicKeytoPemFile("testdata/pub_key.pem", pub)
	if err != nil {
		t.Fatal(err)
	}
	// 从pem文件读取私钥
	privKey, err := ReadPrivateKeyFromPemFile("testdata/pri_key.pem", nil)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("读取到sm2私钥 : %v\n", privKey)
	// 从pem文件读取公钥
	pubKey, err := ReadPublicKeyFromPemFile("testdata/pub_key.pem")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("读取到sm2公钥 : %v\n", pubKey)
	fmt.Println("测试sm2私钥与公钥文件读写成功")

	// 定义证书申请模板
	templateReq := CertificateRequest{
		Subject: pkix.Name{
			// Subject行的CN
			CommonName: "test.pangzi.com",
			// Subject行的O
			Organization: []string{"PANGZIXIEHUI", "dapangzixiehui"},
		},
		SignatureAlgorithm: SM2WithSM3,
	}
	// 创建证书申请pem字节流并签名
	_, err = CreateCertificateRequestToPemFile("testdata/csr.pem", &templateReq, privKey)
	if err != nil {
		t.Fatal(err)
	}
	// 创建证书申请csr文件后，可以用`openssl req -noout -text -in testdata/csr.pem`命令查看文件内容

	// 模拟ca检查证书申请
	// 从pem读取证书申请
	req, err := ReadCertificateRequestFromPemFile("testdata/csr.pem")
	if err != nil {
		t.Fatal(err)
	}
	// 检查证书申请的签名
	err = req.CheckSignature()
	if err != nil {
		t.Fatalf("证书申请验签失败 : %v", err)
	} else {
		fmt.Printf("证书申请验签成功\n")
	}
	fmt.Println("测试证书申请文件读写与验签成功")

	// 模拟ca发布证书
	testExtKeyUsage := []ExtKeyUsage{ExtKeyUsageClientAuth, ExtKeyUsageServerAuth}
	testUnknownExtKeyUsage := []asn1.ObjectIdentifier{[]int{1, 2, 3}, []int{2, 59, 1}}
	extraExtensionData := []byte("extra extension")
	commonName := "test.pangzi.com"
	// 定义证书模板
	//goland:noinspection HttpUrlsUsage
	template := Certificate{
		SerialNumber: big.NewInt(-1),
		Subject: pkix.Name{
			// Subject行的CN
			CommonName: commonName,
			// Subject行的O
			Organization: []string{"PANGZIXIEHUI", "dapangzixiehui"},
			Country:      []string{"China"},
			// CN之后的附加名称
			ExtraNames: []pkix.AttributeTypeAndValue{
				{
					// GN
					Type:  []int{2, 5, 4, 42},
					Value: "Gopher",
				},
				// This should override the Country, above.
				{
					// C
					Type:  []int{2, 5, 4, 6},
					Value: "NL",
				},
			},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Date(2032, time.December, 31, 23, 59, 59, 1, time.UTC),

		SignatureAlgorithm: SM2WithSM3,

		SubjectKeyId: []byte{1, 2, 3, 4},
		KeyUsage:     KeyUsageCertSign,

		ExtKeyUsage:        testExtKeyUsage,
		UnknownExtKeyUsage: testUnknownExtKeyUsage,

		BasicConstraintsValid: true,
		IsCA:                  true,

		OCSPServer:            []string{"http://ocsp.pangzi.com"},
		IssuingCertificateURL: []string{"http://crt.pangzi.com/ca1.crt"},

		DNSNames:       []string{"test.pangzi.com"},
		EmailAddresses: []string{"gopher@golang.org"},
		IPAddresses:    []net.IP{net.IPv4(127, 0, 0, 1).To4(), net.ParseIP("2001:4860:0:2001::68")},

		PolicyIdentifiers:   []asn1.ObjectIdentifier{[]int{1, 2, 3}},
		PermittedDNSDomains: []string{".pangzi.com", "pangzi.com"},

		CRLDistributionPoints: []string{"http://crl1.pangzi.com/ca1.crl", "http://crl2.pangzi.com/ca1.crl"},

		ExtraExtensions: []pkix.Extension{
			{
				Id:    []int{1, 2, 3, 4},
				Value: extraExtensionData,
			},
			// This extension should override the SubjectKeyId, above.
			{
				Id:       oidExtensionSubjectKeyId,
				Critical: false,
				Value:    []byte{0x04, 0x04, 4, 3, 2, 1},
			},
		},
	}
	// 创建证书pem文件
	_, err = CreateCertificateToPemFile("testdata/cert.cer", &template, &template, pubKey, privKey)
	if err != nil {
		t.Fatal("failed to create cert file")
	}
	// 可以使用命令`openssl x509 -noout -text -in testdata/cert.cer`查看生成的x509证书
	// 读取证书pem文件
	cert, err := ReadCertificateFromPemFile("testdata/cert.cer")
	if err != nil {
		t.Fatal("failed to read cert file")
	}
	// 检查证书签名
	err = cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
	if err != nil {
		t.Fatal(err)
	} else {
		fmt.Printf("CheckSignature ok\n")
	}
	fmt.Println("测试证书文件读写与验签成功")
}

func TestCreateCertFromCA_sm2(t *testing.T) {
	certTypePre := "sm2_"

	certType := certTypePre + "ca"
	caPriv, caCert, err := createCACert(certType)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("生成CA密钥对与CA证书成功 %s\n", certType)

	certType = certTypePre + "sign"
	err = createSignCert(caPriv, caCert, certType)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("生成 %s 密钥对并模拟CA为其颁发证书成功\n", certType)

	certType = certTypePre + "enc"
	err = createEncCert(caPriv, caCert, certType)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("生成 %s 密钥对并模拟CA为其颁发证书成功\n", certType)

	certType = certTypePre + "auth"
	err = createAuthCert(caPriv, caCert, certType)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("生成 %s 密钥对并模拟CA为其颁发证书成功\n", certType)
}

func TestCreateCertFromCA_ecdsa(t *testing.T) {
	certTypePre := "ecdsa_"
	certType := certTypePre + "ca"
	caPriv, caCert, err := createCACert(certType)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("生成CA密钥对与CA证书成功 %s\n", certType)

	certType = certTypePre + "sign"
	err = createSignCert(caPriv, caCert, certType)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("生成 %s 密钥对并模拟CA为其颁发证书成功\n", certType)

	certType = certTypePre + "enc"
	err = createEncCert(caPriv, caCert, certType)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("生成 %s 密钥对并模拟CA为其颁发证书成功\n", certType)

	certType = certTypePre + "auth"
	err = createAuthCert(caPriv, caCert, certType)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("生成 %s 密钥对并模拟CA为其颁发证书成功\n", certType)
}

func TestCreateCertFromCA_ecdsaext(t *testing.T) {
	zclog.Level = zclog.LOG_LEVEL_DEBUG
	certTypePre := "ecdsaext_"
	certType := certTypePre + "ca"

	caPriv, caCert, err := createCACert(certType)
	if err != nil {
		t.Fatal(err)
	}
	//caCertPem :=
	////caCert.Verify()
	fmt.Printf("生成CA密钥对与CA证书成功 %s\n", certType)

	certType = certTypePre + "sign"
	err = createSignCert(caPriv, caCert, certType)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("生成 %s 密钥对并模拟CA为其颁发证书成功\n", certType)

	certType = certTypePre + "enc"
	err = createEncCert(caPriv, caCert, certType)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("生成 %s 密钥对并模拟CA为其颁发证书成功\n", certType)

	certType = certTypePre + "auth"
	err = createAuthCert(caPriv, caCert, certType)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("生成 %s 密钥对并模拟CA为其颁发证书成功\n", certType)
}

func createCACert(certType string) (interface{}, *Certificate, error) {
	// 生成密钥对
	privKey, pubKey, err := createKeys(certType)
	if err != nil {
		return nil, nil, err
	}
	userKeyUsage := KeyUsageCertSign + KeyUsageCRLSign
	//goland:noinspection GoPreferNilSlice
	userExtKeyUsage := []ExtKeyUsage{
		// ExtKeyUsageAny,
		// ExtKeyUsageServerAuth,
		// ExtKeyUsageClientAuth,
		// ExtKeyUsageCodeSigning,
		// ExtKeyUsageEmailProtection,
		// ExtKeyUsageIPSECEndSystem,
		// ExtKeyUsageIPSECTunnel,
		// ExtKeyUsageIPSECUser,
		// ExtKeyUsageTimeStamping,
		// ExtKeyUsageOCSPSigning,
		// ExtKeyUsageMicrosoftServerGatedCrypto,
		// ExtKeyUsageNetscapeServerGatedCrypto,
	}
	// 创建证书，ca证书自签名
	cert, err := createCertSignSelf("ca.test.com", "catest", "CN", "Anhui Hefei", true, true, userKeyUsage, userExtKeyUsage, nil, certType, pubKey, privKey)
	if err != nil {
		return nil, nil, err
	}
	// 检查证书签名，因为是ca证书自签名，所以使用本证书自验
	err = cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
	if err != nil {
		return nil, nil, err
	} else {
		fmt.Printf("CheckSignature ok\n")
	}
	return privKey, cert, nil
}

func createSignCert(caPriv interface{}, caCert *Certificate, certType string) error {
	// 生成sm2密钥对
	_, pubKey, err := createKeys(certType)
	if err != nil {
		return err
	}
	userKeyUsage := KeyUsageDigitalSignature + KeyUsageContentCommitment
	userExtKeyUsage := []ExtKeyUsage{
		// ExtKeyUsageAny,
		ExtKeyUsageServerAuth,
		ExtKeyUsageClientAuth,
		// ExtKeyUsageCodeSigning,
		// ExtKeyUsageEmailProtection,
		// ExtKeyUsageIPSECEndSystem,
		// ExtKeyUsageIPSECTunnel,
		// ExtKeyUsageIPSECUser,
		// ExtKeyUsageTimeStamping,
		// ExtKeyUsageOCSPSigning,
		// ExtKeyUsageMicrosoftServerGatedCrypto,
		// ExtKeyUsageNetscapeServerGatedCrypto,
	}
	// 模拟CA颁发证书，注意此时ca证书是父证书
	cert, err := createCertSignParent("server.test.com", "server_test", "CN", "Anhui Hefei", false, false, userKeyUsage, userExtKeyUsage, nil, certType, pubKey, caPriv, caCert)
	if err != nil {
		return err
	}
	// 使用父证书caCert验签
	err = caCert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
	if err != nil {
		return err
	} else {
		fmt.Printf("CheckSignature ok\n")
	}
	return nil
}

func createEncCert(caPriv interface{}, caCert *Certificate, certType string) error {
	// 生成密钥对
	_, pubKey, err := createKeys(certType)
	if err != nil {
		return err
	}
	userKeyUsage := KeyUsageKeyEncipherment + KeyUsageDataEncipherment
	//goland:noinspection GoPreferNilSlice
	userExtKeyUsage := []ExtKeyUsage{
		// ExtKeyUsageAny,
		// ExtKeyUsageServerAuth,
		// ExtKeyUsageClientAuth,
		// ExtKeyUsageCodeSigning,
		// ExtKeyUsageEmailProtection,
		// ExtKeyUsageIPSECEndSystem,
		// ExtKeyUsageIPSECTunnel,
		// ExtKeyUsageIPSECUser,
		// ExtKeyUsageTimeStamping,
		// ExtKeyUsageOCSPSigning,
		// ExtKeyUsageMicrosoftServerGatedCrypto,
		// ExtKeyUsageNetscapeServerGatedCrypto,
	}
	// 模拟CA颁发证书，注意此时ca证书是父证书
	cert, err := createCertSignParent("server.test.com", "server_test", "CN", "Anhui Hefei", false, false, userKeyUsage, userExtKeyUsage, nil, certType, pubKey, caPriv, caCert)
	if err != nil {
		return err
	}
	// 使用父证书caCert验签
	err = caCert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
	if err != nil {
		return err
	} else {
		fmt.Printf("CheckSignature ok\n")
	}
	return nil
}

func createAuthCert(caPriv interface{}, caCert *Certificate, certType string) error {
	// 生成密钥对
	_, pubKey, err := createKeys(certType)
	if err != nil {
		return err
	}
	userKeyUsage := KeyUsageDigitalSignature + KeyUsageContentCommitment
	userExtKeyUsage := []ExtKeyUsage{
		// ExtKeyUsageAny,
		ExtKeyUsageServerAuth,
		ExtKeyUsageClientAuth,
		// ExtKeyUsageCodeSigning,
		// ExtKeyUsageEmailProtection,
		// ExtKeyUsageIPSECEndSystem,
		// ExtKeyUsageIPSECTunnel,
		// ExtKeyUsageIPSECUser,
		// ExtKeyUsageTimeStamping,
		// ExtKeyUsageOCSPSigning,
		// ExtKeyUsageMicrosoftServerGatedCrypto,
		// ExtKeyUsageNetscapeServerGatedCrypto,
	}
	// 模拟CA颁发证书，注意此时ca证书是父证书
	cert, err := createCertSignParent("client.test.com", "client_test", "CN", "Anhui Hefei", false, false, userKeyUsage, userExtKeyUsage, nil, certType, pubKey, caPriv, caCert)
	if err != nil {
		return err
	}
	// 使用父证书caCert验签
	err = caCert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
	if err != nil {
		return err
	} else {
		fmt.Printf("CheckSignature ok\n")
	}
	return nil
}

func createKeys(certType string) (interface{}, interface{}, error) {
	var priv, pub interface{}
	var err error

	if strings.HasPrefix(certType, "sm2_") {
		// 生成sm2密钥对
		priv, err = sm2.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		pub = &priv.(*sm2.PrivateKey).PublicKey
	} else if strings.HasPrefix(certType, "ecdsa_") {
		// 生成ecdsa密钥对
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		pub = &priv.(*ecdsa.PrivateKey).PublicKey
	} else if strings.HasPrefix(certType, "ecdsaext_") {
		// 生成ecdsa_ext密钥对
		priv, err = ecdsa_ext.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		pub = priv.(*ecdsa_ext.PrivateKey).Public().(*ecdsa_ext.PublicKey)
	}
	// 生成私钥pem文件
	_, err = WritePrivateKeytoPemFile("testdata/"+certType+"_key.pem", priv, nil)
	if err != nil {
		return nil, nil, err
	}
	// 生成公钥pem文件
	_, err = WritePublicKeytoPemFile("testdata/"+certType+"_pubkey.pem", pub)
	if err != nil {
		return nil, nil, err
	}
	// 从pem文件读取私钥
	privKey, err := ReadPrivateKeyFromPemFile("testdata/"+certType+"_key.pem", nil)
	if err != nil {
		return nil, nil, err
	}
	// 从pem文件读取公钥
	pubKey, err := ReadPublicKeyFromPemFile("testdata/" + certType + "_pubkey.pem")
	if err != nil {
		return nil, nil, err
	}
	return privKey, pubKey, nil
}

func createCertSignSelf(cn string, o string, c string, st string, bcs bool, isca bool,
	ku KeyUsage, ekus []ExtKeyUsage, uekus []asn1.ObjectIdentifier,
	certType string, pubKey interface{}, privKey interface{}) (*Certificate, error) {
	// 获取ski
	var ski []byte
	switch pk := pubKey.(type) {
	case *sm2.PublicKey:
		ski = CreateEllipticSKI(pk.Curve, pk.X, pk.Y)
	case *ecdsa.PublicKey:
		ski = CreateEllipticSKI(pk.Curve, pk.X, pk.Y)
	case *ecdsa_ext.PublicKey:
		ski = CreateEllipticSKI(pk.Curve, pk.X, pk.Y)
	default:
		panic("不支持的公钥类型")
	}
	// 定义证书模板
	template := createTemplate(cn, o, c, st, bcs, isca, ski, ku, ekus, uekus, privKey)
	// 创建自签名证书pem文件
	_, err := CreateCertificateToPemFile("testdata/"+certType+"_cert.cer", template, template, pubKey, privKey)
	if err != nil {
		return nil, err
	}
	// 可以使用命令`openssl x509 -noout -text -in testdata/user_cert.cer`查看生成的x509证书
	// 读取证书pem文件
	cert, err := ReadCertificateFromPemFile("testdata/" + certType + "_cert.cer")
	if err != nil {
		return nil, err
	}
	text, err := CertificateText(cert)
	if err != nil {
		return nil, err
	}
	fmt.Println("打印证书信息：")
	fmt.Println(text)
	return cert, nil
}

func createCertSignParent(cn string, o string, c string, st string, bcs bool, isca bool,
	ku KeyUsage, ekus []ExtKeyUsage, uekus []asn1.ObjectIdentifier,
	certType string, pubKey interface{}, privKey interface{}, parent *Certificate) (*Certificate, error) {

	// 获取ski
	var ski []byte
	switch pk := pubKey.(type) {
	case *sm2.PublicKey:
		ski = CreateEllipticSKI(pk.Curve, pk.X, pk.Y)
	case *ecdsa.PublicKey:
		ski = CreateEllipticSKI(pk.Curve, pk.X, pk.Y)
	case *ecdsa_ext.PublicKey:
		ski = CreateEllipticSKI(pk.Curve, pk.X, pk.Y)
	default:
		panic("不支持的公钥类型")
	}
	// 定义证书模板
	template := createTemplate(cn, o, c, st, bcs, isca, ski, ku, ekus, uekus, privKey)
	// 创建自签名证书pem文件
	_, err := CreateCertificateToPemFile("testdata/"+certType+"_cert.cer", template, parent, pubKey, privKey)
	if err != nil {
		return nil, err
	}
	// 可以使用命令`openssl x509 -noout -text -in testdata/user_cert.cer`查看生成的x509证书
	// 读取证书pem文件
	cert, err := ReadCertificateFromPemFile("testdata/" + certType + "_cert.cer")
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func createTemplate(cn string, o string, c string, st string, bcs bool, isca bool, sId []byte, ku KeyUsage, ekus []ExtKeyUsage, uekus []asn1.ObjectIdentifier, privKey interface{}) *Certificate {
	var signAlg SignatureAlgorithm
	switch privKey.(type) {
	case *sm2.PrivateKey:
		signAlg = SM2WithSM3
	case *ecdsa.PrivateKey:
		signAlg = ECDSAWithSHA256
	case *ecdsa_ext.PrivateKey:
		signAlg = ECDSAEXTWithSHA256
	default:
		panic("不支持的私钥类型")
	}

	// 定义证书模板
	template := &Certificate{
		// 证书序列号
		SerialNumber: utils.GetRandBigInt(),
		// 证书拥有者
		Subject: pkix.Name{
			// CN 证书拥有者通用名, 一般是域名
			CommonName: cn,
			// O 证书拥有者组织机构
			Organization: []string{o},
			// C 证书拥有者所在国家
			Country: []string{"China"},
			// 附加名称
			ExtraNames: []pkix.AttributeTypeAndValue{
				// This should override the Country, above.
				{
					// C 会覆盖Country
					Type:  []int{2, 5, 4, 6},
					Value: c,
				},
				{
					// ST 省市
					Type:  []int{2, 5, 4, 8},
					Value: st,
				},
			},
		},
		// 证书有效期 十年
		// NotBefore:             time.Now(),
		// NotAfter:              time.Date(2032, time.December, 31, 23, 59, 59, 1, time.UTC),
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(87600 * time.Hour),
		// 证书签名算法
		SignatureAlgorithm:    signAlg,
		BasicConstraintsValid: bcs,
		IsCA:                  isca,
		SubjectKeyId:          sId,
		// AuthorityKeyId:        aId,
		KeyUsage:           ku,
		ExtKeyUsage:        ekus,
		UnknownExtKeyUsage: uekus,
		// x509 v3 版本不再使用 CommonName 而是使用这里的SAN扩展信息
		DNSNames:       []string{cn, "test.example.com"},
		EmailAddresses: []string{"gopher@golang.org"},
		IPAddresses:    []net.IP{net.IPv4(127, 0, 0, 1).To4(), net.ParseIP("2001:4860:0:2001::68")},
		URIs:           []*url.URL{parseURI("https://foo.com/wibble#foo")},
	}
	return template
}
