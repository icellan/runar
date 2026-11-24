package helpers

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bsv-blockchain/go-sdk/transaction"
)

// oldShape is the assertion integration/go/bug100_covenant_bypass_test.go used
// to make: any error at all from FinalizeCall counted as proof that the node
// enforced the covenant.
func oldShape(err error) bool { return err != nil }

const stubTxid = "abababababababababababababababababababababababababababababababab"

// stubNode starts a JSON-RPC stub on 127.0.0.1 and points RPCCall at it.
// answer maps a method name to the reply body; an unknown method gets a
// method-not-found error. SV Node answers a JSON-RPC error with HTTP 500 and
// the error in the body, so the stub does too.
func stubNode(t *testing.T, answer map[string]string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Method string `json:"method"`
		}
		_ = json.Unmarshal(body, &req)
		reply, ok := answer[req.Method]
		if !ok {
			reply = rpcErrorBody(-32601, "Method not found")
		}
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(reply, `"error":{`) {
			w.WriteHeader(http.StatusInternalServerError)
		}
		_, _ = io.WriteString(w, reply)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("RPC_URL", srv.URL)
	t.Setenv("NODE_TYPE", "svnode")
}

func okBody(resultJSON string) string {
	return `{"result":` + resultJSON + `,"error":null,"id":1}`
}

func rpcErrorBody(code int, msg string) string {
	m, _ := json.Marshal(msg)
	return fmt.Sprintf(`{"result":null,"error":{"code":%d,"message":%s},"id":1}`, code, m)
}

// broadcastThroughStub drives the real RPCProvider.Broadcast against the stub,
// exactly as RunarContract.Call does, and returns what the call returned.
func broadcastThroughStub(t *testing.T, p *RPCProvider) error {
	t.Helper()
	_, err := p.Broadcast(transaction.NewTransaction())
	if err != nil {
		return fmt.Errorf("RunarContract.Call: broadcasting: %w", err)
	}
	return nil
}

// TestBroadcast_FailedConfirmingMineIsAnError — R3-GO-BROADCAST-MINE. The node
// accepted the transaction but the confirming block never came. Broadcast
// used to discard that (`_ = Mine(1)`) and report a confirmation that did not
// happen; round-1 GK-BUG-004 made it an error in every other tier.
func TestBroadcast_FailedConfirmingMineIsAnError(t *testing.T) {
	stubNode(t, map[string]string{
		"sendrawtransaction": okBody(`"` + stubTxid + `"`),
		"generate":           rpcErrorBody(-32601, "Method not found"),
		"getnewaddress":      rpcErrorBody(-18, "No wallet is loaded"),
	})
	p := NewRPCProvider()
	_, err := p.Broadcast(transaction.NewTransaction())
	if err == nil {
		t.Fatal("Broadcast returned no error although the confirming mine failed")
	}
	if !strings.Contains(err.Error(), "broadcast succeeded (txid "+stubTxid+") but auto-mine failed") {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := p.BroadcastLog; len(got) != 1 || got[0].Kind != BroadcastAcceptedMineFailed {
		t.Fatalf("broadcast log = %+v, want one accepted-mine-failed outcome", got)
	}
}

// TestCheckNodeRejected_AcceptedThenMineFailedIsNotARejection is the vacuity
// proof for the mine fix: an ACCEPTED spend whose confirming mine fails now
// errors after a broadcast attempt, and the old helper (error + moved counter
// + "RPC error " in the text) passed it, because the mine failure is itself
// the node's own "RPC error ..." reply.
func TestCheckNodeRejected_AcceptedThenMineFailedIsNotARejection(t *testing.T) {
	stubNode(t, map[string]string{
		"sendrawtransaction": okBody(`"` + stubTxid + `"`),
		"generate":           rpcErrorBody(-32601, "Method not found"),
		"getnewaddress":      rpcErrorBody(-18, "No wallet is loaded"),
	})
	p := NewRPCProvider()
	before := p.BroadcastAttempts
	err := broadcastThroughStub(t, p)
	if !oldShape(err) || p.BroadcastAttempts <= before || !strings.Contains(err.Error(), "RPC error ") {
		t.Fatalf("setup is wrong: the old helper must accept this (err=%v, attempts %d -> %d)", err, before, p.BroadcastAttempts)
	}
	if got := CheckNodeRejected(p, before, err, ScriptVerifyFailed); got == nil {
		t.Fatal("CheckNodeRejected accepted an ACCEPTED spend whose confirming mine failed")
	}
}

// TestCheckNodeRejected_AssemblyFailureIsNotANodeRejection: FinalizeCall
// returns "parsing tx: ..." before it ever reaches provider.Broadcast, so a
// guard that hand-mutates a PreparedCall can fail assembly and look identical
// to a consensus rejection from the outside.
func TestCheckNodeRejected_AssemblyFailureIsNotANodeRejection(t *testing.T) {
	p := NewRPCProvider()
	before := p.BroadcastAttempts
	err := fmt.Errorf("RunarContract.FinalizeCall: parsing tx: %w", errors.New("bad hex"))
	if !oldShape(err) {
		t.Fatal("setup is wrong: the old assertion must accept this error")
	}
	if got := CheckNodeRejected(p, before, err, ScriptVerifyFailed); got == nil {
		t.Fatal("CheckNodeRejected accepted an assembly failure as a node rejection")
	}
}

// TestCheckNodeRejected_TransportFailureIsNotANodeRejection: the tx was handed
// to the provider, but the node never answered.
func TestCheckNodeRejected_TransportFailureIsNotANodeRejection(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	t.Setenv("RPC_URL", "http://"+addr)
	t.Setenv("NODE_TYPE", "svnode")

	p := NewRPCProvider()
	before := p.BroadcastAttempts
	callErr := broadcastThroughStub(t, p)
	if !oldShape(callErr) || p.BroadcastAttempts <= before {
		t.Fatalf("setup is wrong: a broadcast must have been attempted and failed (err=%v)", callErr)
	}
	if got := CheckNodeRejected(p, before, callErr, ScriptVerifyFailed); got == nil {
		t.Fatal("CheckNodeRejected accepted an unreachable node as a node rejection")
	}
}

// TestCheckNodeRejected_SuccessIsNotARejection: no error at all.
func TestCheckNodeRejected_SuccessIsNotARejection(t *testing.T) {
	stubNode(t, map[string]string{
		"sendrawtransaction": okBody(`"` + stubTxid + `"`),
		"generate":           okBody(`["00"]`),
	})
	p := NewRPCProvider()
	before := p.BroadcastAttempts
	err := broadcastThroughStub(t, p)
	if err != nil {
		t.Fatalf("setup is wrong: %v", err)
	}
	if got := CheckNodeRejected(p, before, err, ScriptVerifyFailed); got == nil {
		t.Fatal("CheckNodeRejected accepted a SUCCESSFUL spend as a rejection")
	}
}

// TestCheckNodeRejected_WrongReasonIsNotTheRejectionUnderTest: the node did
// refuse the spend, but not for the reason the test claims. A spend refused as
// a double-spend never reached the script, so it proves nothing about the
// covenant the test exercises.
func TestCheckNodeRejected_WrongReasonIsNotTheRejectionUnderTest(t *testing.T) {
	stubNode(t, map[string]string{
		"sendrawtransaction": rpcErrorBody(-26, "16: bad-txns-inputs-missingorspent"),
	})
	p := NewRPCProvider()
	before := p.BroadcastAttempts
	err := broadcastThroughStub(t, p)
	got := CheckNodeRejected(p, before, err, ScriptVerifyFailed)
	if got == nil || !strings.Contains(got.Error(), "wrong reason") {
		t.Fatalf("CheckNodeRejected did not refuse a rejection for the wrong reason: %v", got)
	}
}

// TestCheckNodeRejected_UtxoFetchFailureIsNotANodeRejection: the SDK gave up
// before building the spend, and the error it surfaced is the NODE's own
// "RPC error ..." text -- from a UTXO lookup, not from broadcasting the attack.
func TestCheckNodeRejected_UtxoFetchFailureIsNotANodeRejection(t *testing.T) {
	stubNode(t, map[string]string{
		"listunspent": rpcErrorBody(-5, "No information available about address"),
	})
	p := NewRPCProvider()
	before := p.BroadcastAttempts
	_, utxoErr := p.GetUtxos("mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r")
	err := fmt.Errorf("RunarContract.FinalizeCall: fetching utxos: %w", utxoErr)
	if !oldShape(utxoErr) {
		t.Fatal("setup is wrong: the UTXO fetch must fail")
	}
	if got := CheckNodeRejected(p, before, err, ScriptVerifyFailed); got == nil {
		t.Fatal("CheckNodeRejected accepted a pre-broadcast UTXO-fetch failure as a node rejection")
	}
}

// TestCheckNodeRejected_GenuineConsensusRejectionPasses is the control with
// teeth: an over-strict guard that reddens a real node rejection reddens here.
// The texts are what SV Node actually returns for a script failure.
func TestCheckNodeRejected_GenuineConsensusRejectionPasses(t *testing.T) {
	for _, nodeMsg := range []string{
		"mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation)",
		"mandatory-script-verify-flag-failed (Signature must be zero for failed CHECK(MULTI)SIG operation)",
		"mandatory-script-verify-flag-failed (Script evaluated without error but finished with a false/empty top stack element)",
	} {
		stubNode(t, map[string]string{
			"sendrawtransaction": rpcErrorBody(-26, nodeMsg),
		})
		p := NewRPCProvider()
		p.BroadcastAttempts = 0
		before := p.BroadcastAttempts
		err := broadcastThroughStub(t, p)
		if got := CheckNodeRejected(p, before, err, ScriptVerifyFailed); got != nil {
			t.Fatalf("CheckNodeRejected refused a genuine consensus rejection %q: %v", nodeMsg, got)
		}
	}
}

// TestAssertTxRejected_RequiresTheNodesScriptRefusal — AssertTxRejected (raw
// sendrawtransaction negatives) passed on ANY error: an unreachable node, or
// a refusal for a reason that never ran the script. Control: a genuine
// script-verify refusal passes.
func TestAssertTxRejected_RequiresTheNodesScriptRefusal(t *testing.T) {
	stubNode(t, map[string]string{"sendrawtransaction": okBody(`"` + stubTxid + `"`)})
	if checkTxRejected("00", ScriptVerifyFailed) == nil {
		t.Fatal("an accepted TX passed as rejected")
	}
	stubNode(t, map[string]string{"sendrawtransaction": rpcErrorBody(-26, "16: bad-txns-inputs-missingorspent")})
	if why := checkTxRejected("00", ScriptVerifyFailed); why == nil || !strings.Contains(why.Error(), "wrong reason") {
		t.Fatalf("a double-spend refusal passed as a script refusal: %v", why)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	t.Setenv("RPC_URL", "http://"+addr)
	if checkTxRejected("00", ScriptVerifyFailed) == nil {
		t.Fatal("an unreachable node passed as a rejection")
	}
	stubNode(t, map[string]string{"sendrawtransaction": rpcErrorBody(-26,
		"mandatory-script-verify-flag-failed (Script failed an OP_VERIFY operation)")})
	if why := checkTxRejected("00", ScriptVerifyFailed); why != nil {
		t.Fatalf("a genuine script refusal was refused: %v", why)
	}
}

// TestCheckNodeRejected_BatchProviderLogsToo: BatchRPCProvider broadcasts
// without mining, through its own Broadcast; its outcomes must land in the
// same log so a negative driven through it is checked the same way.
func TestCheckNodeRejected_BatchProviderLogsToo(t *testing.T) {
	stubNode(t, map[string]string{
		"sendrawtransaction": rpcErrorBody(-26, "mandatory-script-verify-flag-failed (Script failed an OP_VERIFY operation)"),
	})
	p := NewBatchRPCProvider()
	before := p.BroadcastAttempts
	_, err := p.Broadcast(transaction.NewTransaction())
	if got := CheckNodeRejected(&p.RPCProvider, before, err, ScriptVerifyFailed); got != nil {
		t.Fatalf("batch provider rejection not recognised: %v", got)
	}
}

// TestScriptRefusal_TeranodeWording: Teranode reports a failed script as
// "error validating transaction scripts -> TX_INVALID (31): ScriptVerifierGoBDK
// fail to VerifyScript -> ...", never SV Node's
// "mandatory-script-verify-flag-failed". Every negative in the nightly
// Teranode job failed on that wording while the node was rejecting the spend.
// Texts below are copied from that job's log. Control: a Teranode refusal for
// a reason that never ran the script must still not count.
func TestScriptRefusal_TeranodeWording(t *testing.T) {
	const prefix = "TX rejected: PROCESSING (4): [Validate][7e80d17696c00342f73b4947993654cd3c55a727d39cd9a4ad49646b19126bdb] error validating transaction scripts -> TX_INVALID (31): ScriptVerifierGoBDK fail to VerifyScript -> UNKNOWN (0): "
	for _, nodeMsg := range []string{
		prefix + "Script evaluated without error but finished with a false/empty top stack element",
		prefix + "Signature must be zero for failed CHECK(MULTI)SIG operation",
	} {
		stubNode(t, map[string]string{"sendrawtransaction": rpcErrorBody(-26, nodeMsg)})
		p := NewRPCProvider()
		p.BroadcastAttempts = 0
		err := broadcastThroughStub(t, p)
		if got := CheckNodeRejected(p, 0, err, ScriptVerifyFailed); got != nil {
			t.Fatalf("CheckNodeRejected refused Teranode's script refusal %q: %v", nodeMsg, got)
		}
		if why := checkTxRejected("00", ScriptVerifyFailed); why != nil {
			t.Fatalf("checkTxRejected refused Teranode's script refusal %q: %v", nodeMsg, why)
		}
	}
	for _, nodeMsg := range []string{
		"TX rejected: UTXO_NON_FINAL (71): [Validate][497f25350c5e8439892e131dada370bc67941e2eed69bad589c664b845ab899b] transaction is not final -> TX_LOCK_TIME (35): lock time (25101) as block height is greater than block height (15102)",
		"TX rejected: TX_INVALID (31): [Validate] error validating transaction scripts",
	} {
		stubNode(t, map[string]string{"sendrawtransaction": rpcErrorBody(-26, nodeMsg)})
		if why := checkTxRejected("00", ScriptVerifyFailed); why == nil || !strings.Contains(why.Error(), "wrong reason") {
			t.Fatalf("a Teranode refusal that never ran the script passed as a script refusal %q: %v", nodeMsg, why)
		}
	}
}
