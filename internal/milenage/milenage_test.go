package milenage

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

// conformanceSet is one test set of TS 35.208 §4.3: inputs and the expected
// output of every function, as hex.
type conformanceSet struct {
	set                    int
	k, rand, sqn, amf      string
	op, opc                string
	f1, f1Star, f2, f3, f4 string
	f5, f5Star             string
}

// conformanceSets holds all twenty test sets of TS 35.208 §4.3 (§4.3.1 to
// §4.3.20). The first six carry the same data as the implementers' test sets of TS 35.207.
var conformanceSets = []conformanceSet{
	{set: 1, k: "465b5ce8b199b49faa5f0a2ee238a6bc", rand: "23553cbe9637a89d218ae64dae47bf35", sqn: "ff9bb4d0b607", amf: "b9b9",
		op: "cdc202d5123e20f62b6d676ac72cb318", opc: "cd63cb71954a9f4e48a5994e37a02baf",
		f1: "4a9ffac354dfafb3", f1Star: "01cfaf9ec4e871e9", f2: "a54211d5e3ba50bf",
		f3: "b40ba9a3c58b2a05bbf0d987b21bf8cb", f4: "f769bcd751044604127672711c6d3441",
		f5: "aa689c648370", f5Star: "451e8beca43b"},
	{set: 2, k: "0396eb317b6d1c36f19c1c84cd6ffd16", rand: "c00d603103dcee52c4478119494202e8", sqn: "fd8eef40df7d", amf: "af17",
		op: "ff53bade17df5d4e793073ce9d7579fa", opc: "53c15671c60a4b731c55b4a441c0bde2",
		f1: "5df5b31807e258b0", f1Star: "a8c016e51ef4a343", f2: "d3a628ed988620f0",
		f3: "58c433ff7a7082acd424220f2b67c556", f4: "21a8c1f929702adb3e738488b9f5c5da",
		f5: "c47783995f72", f5Star: "30f1197061c1"},
	{set: 3, k: "fec86ba6eb707ed08905757b1bb44b8f", rand: "9f7c8d021accf4db213ccff0c7f71a6a", sqn: "9d0277595ffc", amf: "725c",
		op: "dbc59adcb6f9a0ef735477b7fadf8374", opc: "1006020f0a478bf6b699f15c062e42b3",
		f1: "9cabc3e99baf7281", f1Star: "95814ba2b3044324", f2: "8011c48c0c214ed2",
		f3: "5dbdbb2954e8f3cde665b046179a5098", f4: "59a92d3b476a0443487055cf88b2307b",
		f5: "33484dc2136b", f5Star: "deacdd848cc6"},
	{set: 4, k: "9e5944aea94b81165c82fbf9f32db751", rand: "ce83dbc54ac0274a157c17f80d017bd6", sqn: "0b604a81eca8", amf: "9e09",
		op: "223014c5806694c007ca1eeef57f004f", opc: "a64a507ae1a2a98bb88eb4210135dc87",
		f1: "74a58220cba84c49", f1Star: "ac2cc74a96871837", f2: "f365cd683cd92e96",
		f3: "e203edb3971574f5a94b0d61b816345d", f4: "0c4524adeac041c4dd830d20854fc46b",
		f5: "f0b9c08ad02e", f5Star: "6085a86c6f63"},
	{set: 5, k: "4ab1deb05ca6ceb051fc98e77d026a84", rand: "74b0cd6031a1c8339b2b6ce2b8c4a186", sqn: "e880a1b580b6", amf: "9f07",
		op: "2d16c5cd1fdf6b22383584e3bef2a8d8", opc: "dcf07cbd51855290b92a07a9891e523e",
		f1: "49e785dd12626ef2", f1Star: "9e85790336bb3fa2", f2: "5860fc1bce351e7e",
		f3: "7657766b373d1c2138f307e3de9242f9", f4: "1c42e960d89b8fa99f2744e0708ccb53",
		f5: "31e11a609118", f5Star: "fe2555e54aa9"},
	{set: 6, k: "6c38a116ac280c454f59332ee35c8c4f", rand: "ee6466bc96202c5a557abbeff8babf63", sqn: "414b98222181", amf: "4464",
		op: "1ba00a1a7c6700ac8c3ff3e96ad08725", opc: "3803ef5363b947c6aaa225e58fae3934",
		f1: "078adfb488241a57", f1Star: "80246b8d0186bcf1", f2: "16c8233f05a0ac28",
		f3: "3f8c7587fe8e4b233af676aede30ba3b", f4: "a7466cc1e6b2a1337d49d3b66e95d7b4",
		f5: "45b0f69ab06c", f5Star: "1f53cd2b1113"},
	{set: 7, k: "2d609d4db0ac5bf0d2c0de267014de0d", rand: "194aa756013896b74b4a2a3b0af4539e", sqn: "6bf69438c2e4", amf: "5f67",
		op: "460a48385427aa39264aac8efc9e73e8", opc: "c35a0ab0bcbfc9252caff15f24efbde0",
		f1: "bd07d3003b9e5cc3", f1Star: "bcb6c2fcad152250", f2: "8c25a16cd918a1df",
		f3: "4cd0846020f8fa0731dd47cbdc6be411", f4: "88ab80a415f15c73711254a1d388f696",
		f5: "7e6455f34cf3", f5Star: "dc6dd01e8f15"},
	{set: 8, k: "a530a7fe428fad1082c45eddfce13884", rand: "3a4c2b3245c50eb5c71d08639395764d", sqn: "f63f5d768784", amf: "b90e",
		op: "511c6c4e83e38c89b1c5d8dde62426fa", opc: "27953e49bc8af6dcc6e730eb80286be3",
		f1: "53761fbd679b0bad", f1Star: "21adfd334a10e7ce", f2: "a63241e1ffc3e5ab",
		f3: "10f05bab75a99a5fbb98a9c287679c3b", f4: "f9ec0865eb32f22369cade40c59c3a44",
		f5: "88196c47986f", f5Star: "c987a3d23115"},
	{set: 9, k: "d9151cf04896e25830bf2e08267b8360", rand: "f761e5e93d603feb730e27556cb8a2ca", sqn: "47ee0199820a", amf: "9113",
		op: "75fc2233a44294ee8e6de25c4353d26b", opc: "c4c93effe8a08138c203d4c27ce4e3d9",
		f1: "66cc4be44862af1f", f1Star: "7a4b8d7a8753f246", f2: "4a90b2171ac83a76",
		f3: "71236b7129f9b22ab77ea7a54c96da22", f4: "90527ebaa5588968db41727325a04d9e",
		f5: "82a0f5287a71", f5Star: "527dbf41f35f"},
	{set: 10, k: "a0e2971b6822e8d354a18cc235624ecb", rand: "08eff828b13fdb562722c65c7f30a9b2", sqn: "db5c066481e0", amf: "716b",
		op: "323792faca21fb4d5d6f13c145a9d2c1", opc: "82a26f22bba9e9488f949a10d98e9cc4",
		f1: "9485fe24621cb9f6", f1Star: "bce325ce03e2e9b9", f2: "4bc2212d8624910a",
		f3: "08cef6d004ec61471a3c3cda048137fa", f4: "ed0318ca5deb9206272f6e8fa64ba411",
		f5: "a2f858aa9e5d", f5Star: "74e76fbbec38"},
	{set: 11, k: "0da6f7ba86d5eac8a19cf563ac58642d", rand: "679ac4dbacd7d233ff9d6806f4149ce3", sqn: "6e2331d692ad", amf: "224a",
		op: "4b9a26fa459e3acbff36f4015de3bdc1", opc: "0db1071f8767562ca43a0a64c41e8d08",
		f1: "2831d7ae9088e492", f1Star: "9b2e16951135d523", f2: "6fc30fee6d123523",
		f3: "69b1cae7c7429d975e245cacb05a517c", f4: "74f24e8c26df58e1b38d7dcd4f1b7fbd",
		f5: "4c539a26e1fa", f5Star: "07861e126928"},
	{set: 12, k: "77b45843c88e58c10d202684515ed430", rand: "4c47eb3076dc55fe5106cb2034b8cd78", sqn: "fe1a8731005d", amf: "ad25",
		op: "bf3286c7a51409ce95724d503bfe6e70", opc: "d483afae562409a326b5bb0b20c4d762",
		f1: "08332d7e9f484570", f1Star: "ed41b734489d5207", f2: "aefa357beac2a87a",
		f3: "908c43f0569cb8f74bc971e706c36c5f", f4: "c251df0d888dd9329bcf46655b226e40",
		f5: "30ff25cdadf6", f5Star: "e84ed0d4677e"},
	{set: 13, k: "729b17729270dd87ccdf1bfe29b4e9bb", rand: "311c4c929744d675b720f3b7e9b1cbd0", sqn: "c85c4cf65916", amf: "5bb2",
		op: "d04c9c35bd2262fa810d2924d036fd13", opc: "228c2f2f06ac3268a9e616ee16db4ba1",
		f1: "ff794fe2f827ebf8", f1Star: "24fe4dc61e874b52", f2: "98dbbd099b3b408d",
		f3: "44c0f23c5493cfd241e48f197e1d1012", f4: "0c9fb81613884c2535dd0eabf3b440d8",
		f5: "5380d158cfe3", f5Star: "87ac3b559fb6"},
	{set: 14, k: "d32dd23e89dc662354ca12eb79dd32fa", rand: "cf7d0ab1d94306950bf12018fbd46887", sqn: "484107e56a43", amf: "b5e6",
		op: "fe75905b9da47d356236d0314e09c32e", opc: "d22a4b4180a5325708a5ff70d9f67ec7",
		f1: "cf19d62b6a809866", f1Star: "5d269537e45e2ce6", f2: "af4a411e1139f2c2",
		f3: "5af86b80edb70df5292cc1121cbad50c", f4: "7f4d6ae7440e18789a8b75ad3f42f03a",
		f5: "217af49272ad", f5Star: "900e101c677e"},
	{set: 15, k: "af7c65e1927221de591187a2c5987a53", rand: "1f0f8578464fd59b64bed2d09436b57a", sqn: "3d627b01418d", amf: "84f6",
		op: "0c7acb8d95b7d4a31c5aca6d26345a88", opc: "a4cf5c8155c08a7eff418e5443b98e55",
		f1: "c37cae7805642032", f1Star: "68cd09a452d8db7c", f2: "7bffa5c2f41fbc05",
		f3: "3f8c3f3ccf7625bf77fc94bcfd22fd26", f4: "abcbae8fd46115e9961a55d0da5f2078",
		f5: "837fd7b74419", f5Star: "56e97a6090b1"},
	{set: 16, k: "5bd7ecd3d3127a41d12539bed4e7cf71", rand: "59b75f14251c75031d0bcbac1c2c04c7", sqn: "a298ae8929dc", amf: "d056",
		op: "f967f76038b920a9cd25e10c08b49924", opc: "76089d3c0ff3efdc6e36721d4fceb747",
		f1: "c3f25cd94309107e", f1Star: "b0c8ba343665afcc", f2: "7e3f44c7591f6f45",
		f3: "d42b2d615e49a03ac275a5aef97af892", f4: "0b3f8d024fe6bfafaa982b8f82e319c2",
		f5: "5be11495525d", f5Star: "4d6a34a1e4eb"},
	{set: 17, k: "6cd1c6ceb1e01e14f1b82316a90b7f3d", rand: "f69b78f300a0568bce9f0cb93c4be4c9", sqn: "b4fce5feb059", amf: "e4bb",
		op: "078bfca9564659ecd8851e84e6c59b48", opc: "a219dc37f1dc7d66738b5843c799f206",
		f1: "69a90869c268cb7b", f1Star: "2e0fdcf9fd1cfa6a", f2: "70f6bdb9ad21525f",
		f3: "6edaf99e5bd9f85d5f36d91c1272fb4b", f4: "d61c853c280dd9c46f297baec386de17",
		f5: "1c408a858b3e", f5Star: "aa4ae52daa30"},
	{set: 18, k: "b73a90cbcf3afb622dba83c58a8415df", rand: "b120f1c1a0102a2f507dd543de68281f", sqn: "f1e8a523a36d", amf: "471b",
		op: "b672047e003bb952dca6cb8af0e5b779", opc: "df0c67868fa25f748b7044c6e7c245b8",
		f1: "ebd70341bcd415b0", f1Star: "12359f5d82220c14", f2: "479dd25c20792d63",
		f3: "66195dbed0313274c5ca7766615fa25e", f4: "66bec707eb2afc476d7408a8f2927b36",
		f5: "aefdaa5ddd99", f5Star: "12ec2b87fbb1"},
	{set: 19, k: "5122250214c33e723a5dd523fc145fc0", rand: "81e92b6c0ee0e12ebceba8d92a99dfa5", sqn: "16f3b3f70fc2", amf: "c3ab",
		op: "c9e8763286b5b9ffbdf56e1297d0887b", opc: "981d464c7c52eb6e5036234984ad0bcf",
		f1: "2a5c23d15ee351d5", f1Star: "62dae3853f3af9d2", f2: "28d7b0f2a2ec3de5",
		f3: "5349fbe098649f948f5d2e973a81c00f", f4: "9744871ad32bf9bbd1dd5ce54e3e2e5a",
		f5: "ada15aeb7bb8", f5Star: "d461bc15475d"},
	{set: 20, k: "90dca4eda45b53cf0f12d7c9c3bc6a89", rand: "9fddc72092c6ad036b6e464789315b78", sqn: "20f813bd4141", amf: "61df",
		op: "3ffcfe5b7b1111589920d3528e84e655", opc: "cb9cccc4b9258e6dca4760379fb82581",
		f1: "09db94eab4f8149e", f1Star: "a29468aa9775b527", f2: "a95100e2760952cd",
		f3: "b5f2da03883b69f96bf52e029ed9ac45", f4: "b4721368bc16ea67875c5598688bb0ef",
		f5: "83cfd54db913", f5Star: "4f2039392ddc"},
}

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func key(t testing.TB, s string) [KeySize]byte   { return [KeySize]byte(unhex(t, s)) }
func rnd(t testing.TB, s string) [RANDSize]byte  { return [RANDSize]byte(unhex(t, s)) }
func sqnOf(t testing.TB, s string) [SQNSize]byte { return [SQNSize]byte(unhex(t, s)) }
func amfOf(t testing.TB, s string) [AMFSize]byte { return [AMFSize]byte(unhex(t, s)) }

func check(t *testing.T, name string, got []byte, want string) {
	t.Helper()
	if h := hex.EncodeToString(got); h != want {
		t.Errorf("%s = %s, want %s", name, h, want)
	}
}

func TestEveryConformanceSetProducesTheSpecifiedOutputs(t *testing.T) {
	if len(conformanceSets) != 20 {
		t.Fatalf("have %d test sets, TS 35.208 §4.3 has 20", len(conformanceSets))
	}
	for _, ts := range conformanceSets {
		t.Run(fmt.Sprintf("set%d", ts.set), func(t *testing.T) {
			k, op, rand := key(t, ts.k), key(t, ts.op), rnd(t, ts.rand)
			sqn, amf := sqnOf(t, ts.sqn), amfOf(t, ts.amf)

			opc := DeriveOPc(k, op)
			check(t, "OPc", opc[:], ts.opc)

			m := New(k, key(t, ts.opc))
			f1 := m.F1(rand, sqn, amf)
			check(t, "f1", f1[:], ts.f1)
			f1s := m.F1Star(rand, sqn, amf)
			check(t, "f1*", f1s[:], ts.f1Star)
			f2 := m.F2(rand)
			check(t, "f2", f2[:], ts.f2)
			f3 := m.F3(rand)
			check(t, "f3", f3[:], ts.f3)
			f4 := m.F4(rand)
			check(t, "f4", f4[:], ts.f4)
			f5 := m.F5(rand)
			check(t, "f5", f5[:], ts.f5)
			f5s := m.F5Star(rand)
			check(t, "f5*", f5s[:], ts.f5Star)
		})
	}
}

func TestNewWithOPMatchesNewWithDerivedOPc(t *testing.T) {
	for _, ts := range conformanceSets {
		k, rand := key(t, ts.k), rnd(t, ts.rand)
		got := NewWithOP(k, key(t, ts.op)).F2(rand)
		check(t, fmt.Sprintf("set%d f2", ts.set), got[:], ts.f2)
	}
}

func TestVectorCombinesTheFunctionsAsTS33102Specifies(t *testing.T) {
	for _, ts := range conformanceSets {
		t.Run(fmt.Sprintf("set%d", ts.set), func(t *testing.T) {
			m := New(key(t, ts.k), key(t, ts.opc))
			rand := rnd(t, ts.rand)
			sqn := SQNFromBytes(sqnOf(t, ts.sqn))
			v := m.Vector(rand, sqn, amfOf(t, ts.amf))

			check(t, "RAND", v.RAND[:], ts.rand)
			check(t, "XRES", v.XRES[:], ts.f2)
			check(t, "CK", v.CK[:], ts.f3)
			check(t, "IK", v.IK[:], ts.f4)

			// AUTN = SQN ⊕ AK ‖ AMF ‖ MAC-A, built here from the test set
			// independently of Vector.
			concealed := unhex(t, ts.sqn)
			for i, b := range unhex(t, ts.f5) {
				concealed[i] ^= b
			}
			check(t, "AUTN", v.AUTN[:], hex.EncodeToString(concealed)+ts.amf+ts.f1)
		})
	}
}

func TestVectorAUTNForTestSet1IsTheKnownValue(t *testing.T) {
	// SQN ⊕ AK for set 1 worked out by hand: ff9bb4d0b607 ⊕ aa689c648370.
	ts := conformanceSets[0]
	m := New(key(t, ts.k), key(t, ts.opc))
	v := m.Vector(rnd(t, ts.rand), SQNFromBytes(sqnOf(t, ts.sqn)), amfOf(t, ts.amf))
	check(t, "AUTN", v.AUTN[:], "55f328b43577b9b94a9ffac354dfafb3")
}

func TestCardRecoversSQNFromAUTNItsNetworkBuilt(t *testing.T) {
	for _, ts := range conformanceSets {
		m := New(key(t, ts.k), key(t, ts.opc))
		rand := rnd(t, ts.rand)
		sqn := SQNFromBytes(sqnOf(t, ts.sqn))
		v := m.Vector(rand, sqn, amfOf(t, ts.amf))
		got, err := m.CheckAUTN(rand, v.AUTN)
		if err != nil {
			t.Fatalf("set%d: CheckAUTN: %v", ts.set, err)
		}
		if got != sqn {
			t.Errorf("set%d: SQN = %012x, want %012x", ts.set, uint64(got), uint64(sqn))
		}
	}
}

func TestCardRejectsAUTNThatWasTamperedWithOrMadeWithAnotherKey(t *testing.T) {
	ts := conformanceSets[0]
	m := New(key(t, ts.k), key(t, ts.opc))
	rand := rnd(t, ts.rand)
	v := m.Vector(rand, SQNFromBytes(sqnOf(t, ts.sqn)), amfOf(t, ts.amf))

	for i := range AUTNSize {
		autn := v.AUTN
		autn[i] ^= 0x01
		if _, err := m.CheckAUTN(rand, autn); !errors.Is(err, ErrMACFailure) {
			t.Errorf("AUTN with byte %d flipped: err = %v, want ErrMACFailure", i, err)
		}
	}
	otherRAND := rand
	otherRAND[0] ^= 0x80
	if _, err := m.CheckAUTN(otherRAND, v.AUTN); !errors.Is(err, ErrMACFailure) {
		t.Errorf("AUTN with another RAND: err = %v, want ErrMACFailure", err)
	}
	other := conformanceSets[2]
	stranger := New(key(t, other.k), key(t, other.opc))
	if _, err := stranger.CheckAUTN(rand, v.AUTN); !errors.Is(err, ErrMACFailure) {
		t.Errorf("AUTN checked with another subscriber's keys: err = %v, want ErrMACFailure", err)
	}
}

func TestNetworkRecoversSQNMSFromAUTSTheCardBuilt(t *testing.T) {
	for _, ts := range conformanceSets {
		m := New(key(t, ts.k), key(t, ts.opc))
		rand := rnd(t, ts.rand)
		sqnMS := SQNFromBytes(sqnOf(t, ts.sqn))
		auts := m.AUTS(rand, sqnMS)

		// The concealed half is SQN_MS ⊕ AK*, checked against the test
		// set's f5* so that AUTS is not only consistent with itself.
		concealed := unhex(t, ts.sqn)
		for i, b := range unhex(t, ts.f5Star) {
			concealed[i] ^= b
		}
		check(t, fmt.Sprintf("set%d AUTS[:6]", ts.set), auts[:SQNSize], hex.EncodeToString(concealed))

		got, err := m.VerifyAUTS(rand, auts)
		if err != nil {
			t.Fatalf("set%d: VerifyAUTS: %v", ts.set, err)
		}
		if got != sqnMS {
			t.Errorf("set%d: SQN_MS = %012x, want %012x", ts.set, uint64(got), uint64(sqnMS))
		}
	}
}

func TestMACSIsComputedOverTheZeroResynchronisationAMF(t *testing.T) {
	ts := conformanceSets[0]
	m := New(key(t, ts.k), key(t, ts.opc))
	rand := rnd(t, ts.rand)
	sqn := sqnOf(t, ts.sqn)
	auts := m.AUTS(rand, SQNFromBytes(sqn))
	macS := m.F1Star(rand, sqn, [AMFSize]byte{})
	if !bytes.Equal(auts[SQNSize:], macS[:]) {
		t.Fatalf("MAC-S in AUTS = %x, want f1* over AMF 0000 = %x", auts[SQNSize:], macS)
	}
}

func TestNetworkRejectsAUTSThatWasTamperedWithOrIsForAnotherRAND(t *testing.T) {
	ts := conformanceSets[0]
	m := New(key(t, ts.k), key(t, ts.opc))
	rand := rnd(t, ts.rand)
	auts := m.AUTS(rand, SQNFromBytes(sqnOf(t, ts.sqn)))
	for i := range AUTSSize {
		bad := auts
		bad[i] ^= 0x01
		if _, err := m.VerifyAUTS(rand, bad); !errors.Is(err, ErrMACFailure) {
			t.Errorf("AUTS with byte %d flipped: err = %v, want ErrMACFailure", i, err)
		}
	}
	otherRAND := rand
	otherRAND[15] ^= 0x01
	if _, err := m.VerifyAUTS(otherRAND, auts); !errors.Is(err, ErrMACFailure) {
		t.Errorf("AUTS for another RAND: err = %v, want ErrMACFailure", err)
	}
}

// secretsOf returns every secret the test set holds, in the forms a leak
// could take: lower and upper hex, and the raw bytes.
func secretsOf(t *testing.T, ts conformanceSet) []string {
	var out []string
	for _, h := range []string{ts.k, ts.op, ts.opc, ts.f2, ts.f3, ts.f4} {
		out = append(out, h, strings.ToUpper(h), string(unhex(t, h)))
	}
	return out
}

func formatted(v any) []string {
	var outs []string
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%T %v"} {
		outs = append(outs, fmt.Sprintf(verb, v))
	}
	outs = append(outs, fmt.Sprint(v), fmt.Sprintln(v))
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("x", "value", v)
	slog.New(slog.NewTextHandler(&buf, nil)).Info("x", "value", v)
	return append(outs, buf.String())
}

func TestNoSecretAppearsInFormattedOrLoggedValues(t *testing.T) {
	ts := conformanceSets[0]
	m := New(key(t, ts.k), key(t, ts.opc))
	v := m.Vector(rnd(t, ts.rand), SQNFromBytes(sqnOf(t, ts.sqn)), amfOf(t, ts.amf))
	values := map[string]any{
		"Milenage": m, "*Milenage": &m, "Vector": v, "*Vector": &v,
		"struct holding both": struct {
			M Milenage
			V Vector
		}{m, v},
	}
	for name, val := range values {
		for _, out := range formatted(val) {
			for _, secret := range secretsOf(t, ts) {
				if strings.Contains(out, secret) {
					t.Errorf("%s formatted as %q leaks a secret", name, out)
				}
			}
		}
	}
	for _, s := range []string{m.String(), m.GoString(), v.String(), v.GoString()} {
		if !strings.Contains(s, "redacted") {
			t.Errorf("String/GoString = %q, want the redacted placeholder", s)
		}
	}
}

func TestErrorsCarryNoSecret(t *testing.T) {
	ts := conformanceSets[0]
	m := New(key(t, ts.k), key(t, ts.opc))
	rand := rnd(t, ts.rand)
	_, errAUTN := m.CheckAUTN(rand, [AUTNSize]byte{})
	_, errAUTS := m.VerifyAUTS(rand, [AUTSSize]byte{})
	_, errSQN := NewSQN(MaxSEQ+1, 0)
	for _, err := range []error{errAUTN, errAUTS, errSQN, ErrSQNExhausted} {
		if err == nil {
			t.Fatal("expected an error")
		}
		for _, secret := range secretsOf(t, ts) {
			if strings.Contains(err.Error(), secret) {
				t.Errorf("error %q leaks a secret", err)
			}
		}
	}
}
