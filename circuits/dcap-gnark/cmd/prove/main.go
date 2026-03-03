package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/schema"

	"github.com/reliqlabs/oauth3/circuits/dcap-gnark/circuit"
	"github.com/reliqlabs/oauth3/circuits/dcap-gnark/witness"
)

// Prover holds cached circuit, proving key, and options for reuse across requests.
type Prover struct {
	ccs       constraint.ConstraintSystem
	pk        groth16.ProvingKey
	proveOpts []backend.ProverOption
	schema    *schema.Schema
}

func initProver(pkPath string, gpu bool) *Prover {
	t0 := time.Now()

	fmt.Println("Compiling circuit...")
	tStep := time.Now()
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit.DcapCircuit{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "compile: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Circuit compiled in %v (%d constraints)\n", time.Since(tStep), ccs.GetNbConstraints())

	fmt.Println("Loading proving key...")
	tStep = time.Now()
	fpk, err := os.Open(pkPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open pk: %v\n", err)
		os.Exit(1)
	}
	pk := groth16.NewProvingKey(ecc.BN254)
	if _, err := pk.ReadFrom(fpk); err != nil {
		fpk.Close()
		fmt.Fprintf(os.Stderr, "read pk: %v\n", err)
		os.Exit(1)
	}
	fpk.Close()
	fmt.Printf("Proving key loaded in %v\n", time.Since(tStep))

	schema, err := frontend.NewSchema(ecc.BN254.ScalarField(), &circuit.DcapCircuit{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "create schema: %v\n", err)
		os.Exit(1)
	}

	var proveOpts []backend.ProverOption
	if gpu {
		fmt.Println("GPU acceleration enabled (icicle)")
		proveOpts = append(proveOpts, backend.WithIcicleAcceleration())
	}

	fmt.Printf("Prover initialized in %v\n", time.Since(t0))
	return &Prover{ccs: ccs, pk: pk, proveOpts: proveOpts, schema: schema}
}

// proveRequest is the JSON body for POST /prove.
type proveRequest struct {
	QuoteHex        string                   `json:"quote_hex"`
	PreVerifiedJSON witness.PreVerifiedJSON  `json:"pre_verified_json"`
	Timestamp       uint64                   `json:"timestamp"`
}

func (p *Prover) handleProve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("read body: %v", err), http.StatusBadRequest)
		return
	}

	var req proveRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, fmt.Sprintf("parse request: %v", err), http.StatusBadRequest)
		return
	}

	quoteBytes, err := hex.DecodeString(req.QuoteHex)
	if err != nil {
		http.Error(w, fmt.Sprintf("decode quote_hex: %v", err), http.StatusBadRequest)
		return
	}

	preVerified, err := req.PreVerifiedJSON.ToPreVerifiedInputs()
	if err != nil {
		http.Error(w, fmt.Sprintf("convert pre_verified: %v", err), http.StatusBadRequest)
		return
	}

	t0 := time.Now()

	assignment, err := witness.BuildWitness(quoteBytes, preVerified, req.Timestamp)
	if err != nil {
		http.Error(w, fmt.Sprintf("build witness: %v", err), http.StatusInternalServerError)
		return
	}

	wit, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		http.Error(w, fmt.Sprintf("create witness: %v", err), http.StatusInternalServerError)
		return
	}

	proof, err := groth16.Prove(p.ccs, p.pk, wit, p.proveOpts...)
	if err != nil {
		http.Error(w, fmt.Sprintf("prove: %v", err), http.StatusInternalServerError)
		return
	}

	elapsed := time.Since(t0)

	pubWitness, err := wit.Public()
	if err != nil {
		http.Error(w, fmt.Sprintf("extract public witness: %v", err), http.StatusInternalServerError)
		return
	}
	pubJSON, err := pubWitness.ToJSON(p.schema)
	if err != nil {
		http.Error(w, fmt.Sprintf("marshal public witness: %v", err), http.StatusInternalServerError)
		return
	}
	var publicInputs map[string]interface{}
	if err := json.Unmarshal(pubJSON, &publicInputs); err != nil {
		http.Error(w, fmt.Sprintf("parse public witness JSON: %v", err), http.StatusInternalServerError)
		return
	}

	snarkProof, err := proofToSnarkJS(proof)
	if err != nil {
		http.Error(w, fmt.Sprintf("convert proof: %v", err), http.StatusInternalServerError)
		return
	}
	snarkProof["public_inputs"] = publicInputs

	fmt.Printf("Proved in %v\n", elapsed)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(snarkProof)
}

func runServer(prover *Prover, socketPath string) {
	// Remove stale socket
	os.Remove(socketPath)

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen %s: %v\n", socketPath, err)
		os.Exit(1)
	}
	// Make socket world-accessible
	os.Chmod(socketPath, 0666)

	mux := http.NewServeMux()
	mux.HandleFunc("/prove", prover.handleProve)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	// Graceful shutdown on SIGTERM/SIGINT
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sig
		fmt.Println("Shutting down gnark server...")
		listener.Close()
		os.Remove(socketPath)
		os.Exit(0)
	}()

	fmt.Printf("gnark server listening on %s\n", socketPath)
	if err := http.Serve(listener, mux); err != nil {
		fmt.Fprintf(os.Stderr, "serve: %v\n", err)
	}
}

func runCLI(prover *Prover, quotePath, prePath string, ts uint64, outPath string) {
	quoteBytes, err := os.ReadFile(quotePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read quote: %v\n", err)
		os.Exit(1)
	}

	preBytes, err := os.ReadFile(prePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read pre_verified: %v\n", err)
		os.Exit(1)
	}

	var preJSON witness.PreVerifiedJSON
	if err := json.Unmarshal(preBytes, &preJSON); err != nil {
		fmt.Fprintf(os.Stderr, "parse pre_verified: %v\n", err)
		os.Exit(1)
	}
	preVerified, err := preJSON.ToPreVerifiedInputs()
	if err != nil {
		fmt.Fprintf(os.Stderr, "convert pre_verified: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Building witness...")
	tStep := time.Now()
	assignment, err := witness.BuildWitness(quoteBytes, preVerified, ts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "build witness: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Witness built in %v\n", time.Since(tStep))

	tStep = time.Now()
	w, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		fmt.Fprintf(os.Stderr, "create witness: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Witness created in %v\n", time.Since(tStep))

	fmt.Println("Proving...")
	t0 := time.Now()
	proof, err := groth16.Prove(prover.ccs, prover.pk, w, prover.proveOpts...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "prove: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Proved in %v\n", time.Since(t0))

	pubWitness, err := w.Public()
	if err != nil {
		fmt.Fprintf(os.Stderr, "extract public witness: %v\n", err)
		os.Exit(1)
	}
	pubJSON, err := pubWitness.ToJSON(prover.schema)
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal public witness: %v\n", err)
		os.Exit(1)
	}
	var publicInputs map[string]interface{}
	if err := json.Unmarshal(pubJSON, &publicInputs); err != nil {
		fmt.Fprintf(os.Stderr, "parse public witness JSON: %v\n", err)
		os.Exit(1)
	}

	snarkProof, err := proofToSnarkJS(proof)
	if err != nil {
		fmt.Fprintf(os.Stderr, "convert proof: %v\n", err)
		os.Exit(1)
	}
	snarkProof["public_inputs"] = publicInputs

	outJSON, err := json.MarshalIndent(snarkProof, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal proof: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(outPath, outJSON, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "write proof: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Proof written to %s\n", outPath)
}

func main() {
	quotePath := flag.String("quote", "", "path to quote.bin")
	prePath := flag.String("pre", "", "path to pre_verified.json")
	tsStr := flag.String("timestamp", "", "verification timestamp (unix seconds)")
	pkPath := flag.String("pk", "pk.bin", "proving key path")
	outPath := flag.String("out", "proof.json", "output proof path")
	gpuFlag := flag.Bool("gpu", false, "enable icicle GPU acceleration")
	serverFlag := flag.Bool("server", false, "run as HTTP server on unix socket")
	socketPath := flag.String("socket", "/tmp/gnark-prove.sock", "unix socket path (server mode)")
	flag.Parse()

	if *serverFlag {
		prover := initProver(*pkPath, *gpuFlag)
		runServer(prover, *socketPath)
		return
	}

	// CLI mode
	if *quotePath == "" || *prePath == "" || *tsStr == "" {
		fmt.Fprintln(os.Stderr, "usage: prove -quote <file> -pre <file> -timestamp <unix> [-pk pk.bin] [-out proof.json]")
		fmt.Fprintln(os.Stderr, "       prove -server [-pk pk.bin] [-socket /tmp/gnark-prove.sock] [-gpu]")
		os.Exit(1)
	}

	ts, err := strconv.ParseUint(*tsStr, 10, 64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid timestamp: %v\n", err)
		os.Exit(1)
	}

	prover := initProver(*pkPath, *gpuFlag)
	runCLI(prover, *quotePath, *prePath, ts, *outPath)
}

// proofToSnarkJS converts a gnark Groth16 proof to SnarkJS-compatible JSON.
// Uses WriteRawTo (uncompressed points: Ar(64B) + Bs(128B) + Krs(64B) = 256B).
func proofToSnarkJS(proof groth16.Proof) (map[string]interface{}, error) {
	var buf bytes.Buffer
	if _, err := proof.WriteRawTo(&buf); err != nil {
		return nil, fmt.Errorf("write raw proof: %w", err)
	}

	raw := buf.Bytes()
	// gnark WriteRawTo for BN254 groth16:
	// Ar: G1 uncompressed (64 bytes: X 32B + Y 32B)
	// Bs: G2 uncompressed (128 bytes: X.A0 32B + X.A1 32B + Y.A0 32B + Y.A1 32B)
	// Krs: G1 uncompressed (64 bytes)
	// Total: 256 bytes
	if len(raw) < 256 {
		return nil, fmt.Errorf("proof too short: %d bytes", len(raw))
	}

	toDecimal := func(b []byte) string {
		return new(big.Int).SetBytes(b).String()
	}

	return map[string]interface{}{
		"pi_a": []string{toDecimal(raw[0:32]), toDecimal(raw[32:64]), "1"},
		"pi_b": [][]string{
			{toDecimal(raw[64:96]), toDecimal(raw[96:128])},    // [A0(real), A1(imag)]
			{toDecimal(raw[128:160]), toDecimal(raw[160:192])},
			{"1", "0"},
		},
		"pi_c":     []string{toDecimal(raw[192:224]), toDecimal(raw[224:256]), "1"},
		"protocol": "groth16",
		"curve":    "bn128",
	}, nil
}
