//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"runar-integration/helpers"

	runar "github.com/icellan/runar/packages/runar-go"
)

// ---------------------------------------------------------------------------
// JSON vector types
// ---------------------------------------------------------------------------

type friVectorFile struct {
	Field   string      `json:"field"`
	Prime   uint64      `json:"prime"`
	Vectors []friVector `json:"vectors"`
}

type friVector struct {
	X           uint64     `json:"x"`
	FX          [4]uint64  `json:"f_x"`
	FNegX       [4]uint64  `json:"f_neg_x"`
	Alpha       [4]uint64  `json:"alpha"`
	ExpectedGX2 [4]uint64  `json:"expected_g_x2"`
	Expected    string     `json:"expected"`
	Description string     `json:"description"`
}

func friVectorsDir() string {
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "tests", "vectors")
}

func loadFRIVectors(t *testing.T, filename string) friVectorFile {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(friVectorsDir(), filename))
	if err != nil {
		t.Fatalf("load vectors %s: %v", filename, err)
	}
	var vf friVectorFile
	if err := json.Unmarshal(data, &vf); err != nil {
		t.Fatalf("parse vectors %s: %v", filename, err)
	}
	return vf
}

// ---------------------------------------------------------------------------
// Contract source — implements the full FRI colinearity formula
// ---------------------------------------------------------------------------

const friColinearitySource = `
import {
  SmartContract, assert,
  bbFieldAdd, bbFieldSub, bbFieldMul, bbFieldInv,
  bbExt4Mul0, bbExt4Mul1, bbExt4Mul2, bbExt4Mul3
} from 'runar-lang';

class FRIColinearityCheck extends SmartContract {
  constructor() { super(); }

  public verify(
    x: bigint,
    fx0: bigint, fx1: bigint, fx2: bigint, fx3: bigint,
    fnx0: bigint, fnx1: bigint, fnx2: bigint, fnx3: bigint,
    a0: bigint, a1: bigint, a2: bigint, a3: bigint,
    eg0: bigint, eg1: bigint, eg2: bigint, eg3: bigint
  ) {
    const s0 = bbFieldAdd(fx0, fnx0);
    const s1 = bbFieldAdd(fx1, fnx1);
    const s2 = bbFieldAdd(fx2, fnx2);
    const s3 = bbFieldAdd(fx3, fnx3);
    const inv2 = bbFieldInv(2n);
    const hs0 = bbFieldMul(s0, inv2);
    const hs1 = bbFieldMul(s1, inv2);
    const hs2 = bbFieldMul(s2, inv2);
    const hs3 = bbFieldMul(s3, inv2);
    const d0 = bbFieldSub(fx0, fnx0);
    const d1 = bbFieldSub(fx1, fnx1);
    const d2 = bbFieldSub(fx2, fnx2);
    const d3 = bbFieldSub(fx3, fnx3);
    const ad0 = bbExt4Mul0(a0, a1, a2, a3, d0, d1, d2, d3);
    const ad1 = bbExt4Mul1(a0, a1, a2, a3, d0, d1, d2, d3);
    const ad2 = bbExt4Mul2(a0, a1, a2, a3, d0, d1, d2, d3);
    const ad3 = bbExt4Mul3(a0, a1, a2, a3, d0, d1, d2, d3);
    const inv2x = bbFieldInv(bbFieldMul(2n, x));
    const at0 = bbFieldMul(ad0, inv2x);
    const at1 = bbFieldMul(ad1, inv2x);
    const at2 = bbFieldMul(ad2, inv2x);
    const at3 = bbFieldMul(ad3, inv2x);
    const g0 = bbFieldAdd(hs0, at0);
    const g1 = bbFieldAdd(hs1, at1);
    const g2 = bbFieldAdd(hs2, at2);
    const g3 = bbFieldAdd(hs3, at3);
    assert(g0 === eg0);
    assert(g1 === eg1);
    assert(g2 === eg2);
    assert(g3 === eg3);
  }
}
`

// ---------------------------------------------------------------------------
// Test entry points
// ---------------------------------------------------------------------------

func TestFRI_Vectors_Accept(t *testing.T) {
	vf := loadFRIVectors(t, "fri_colinearity.json")

	artifact, err := helpers.CompileSourceStringToSDKArtifact(friColinearitySource, "FRIColinearityCheck.runar.ts", map[string]interface{}{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	t.Logf("compiled FRI colinearity check: %d bytes script", len(artifact.Script)/2)

	for i, vec := range vf.Vectors {
		if vec.Expected != "accept" {
			continue
		}
		vec := vec
		t.Run(fmt.Sprintf("%d_%s", i, vec.Description), func(t *testing.T) {
			contract := runar.NewRunarContract(artifact, []interface{}{})

			wallet := helpers.NewWallet()
			helpers.RPCCall("importaddress", wallet.Address, "", false)
			_, err := helpers.FundWallet(wallet, 0.5)
			if err != nil {
				t.Fatalf("fund: %v", err)
			}

			provider := helpers.NewRPCProvider()
			signer, errS := helpers.SDKSignerFromWallet(wallet)
			if errS != nil {
				t.Fatalf("signer: %v", errS)
			}

			_, _, err = contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 200000})
			if err != nil {
				t.Fatalf("deploy: %v", err)
			}

			args := []interface{}{
				big.NewInt(int64(vec.X)),
				big.NewInt(int64(vec.FX[0])), big.NewInt(int64(vec.FX[1])),
				big.NewInt(int64(vec.FX[2])), big.NewInt(int64(vec.FX[3])),
				big.NewInt(int64(vec.FNegX[0])), big.NewInt(int64(vec.FNegX[1])),
				big.NewInt(int64(vec.FNegX[2])), big.NewInt(int64(vec.FNegX[3])),
				big.NewInt(int64(vec.Alpha[0])), big.NewInt(int64(vec.Alpha[1])),
				big.NewInt(int64(vec.Alpha[2])), big.NewInt(int64(vec.Alpha[3])),
				big.NewInt(int64(vec.ExpectedGX2[0])), big.NewInt(int64(vec.ExpectedGX2[1])),
				big.NewInt(int64(vec.ExpectedGX2[2])), big.NewInt(int64(vec.ExpectedGX2[3])),
			}

			txid, _, err := contract.Call("verify", args, provider, signer, nil)
			if err != nil {
				t.Fatalf("FAIL: %v", err)
			}
			t.Logf("PASS: %s → tx %s", vec.Description, txid)
		})
	}
}
