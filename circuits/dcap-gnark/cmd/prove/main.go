package main

import (
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
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/hash_to_field"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/schema"

	"github.com/reliqlabs/oauth3/circuits/dcap-gnark/circuit"
	"github.com/reliqlabs/oauth3/circuits/dcap-gnark/witness"
)

// Prover holds cached circuit, proving key, verifying key, and options for reuse across requests.
type Prover struct {
	ccs       constraint.ConstraintSystem
	pk        groth16.ProvingKey
	vk        *groth16_bn254.VerifyingKey // for commitment hash computation
	proveOpts []backend.ProverOption
	schema    *schema.Schema
}

func initProver(pkPath, vkPath string, gpu bool) *Prover {
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

	// Load verifying key (needed for commitment hash computation)
	var vkBn254 *groth16_bn254.VerifyingKey
	if vkPath != "" {
		fmt.Println("Loading verifying key...")
		tStep = time.Now()
		fvk, err := os.Open(vkPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "open vk: %v\n", err)
			os.Exit(1)
		}
		vk := groth16.NewVerifyingKey(ecc.BN254)
		if _, err := vk.ReadFrom(fvk); err != nil {
			fvk.Close()
			fmt.Fprintf(os.Stderr, "read vk: %v\n", err)
			os.Exit(1)
		}
		fvk.Close()
		vkBn254 = vk.(*groth16_bn254.VerifyingKey)
		fmt.Printf("Verifying key loaded in %v (commitments: %d, IC: %d)\n",
			time.Since(tStep), len(vkBn254.PublicAndCommitmentCommitted), len(vkBn254.G1.K))
	}

	s, err := frontend.NewSchema(ecc.BN254.ScalarField(), &circuit.DcapCircuit{})
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
	return &Prover{ccs: ccs, pk: pk, vk: vkBn254, proveOpts: proveOpts, schema: s}
}

// proveRequest is the JSON body for POST /prove.
type proveRequest struct {
	QuoteHex        string                  `json:"quote_hex"`
	PreVerifiedJSON witness.PreVerifiedJSON `json:"pre_verified_json"`
	Timestamp       uint64                  `json:"timestamp"`
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

	snarkProof := proofToSnarkJS(proof)
	snarkProof["public_inputs"] = publicInputs

	// Compute flat public_signals array (including commitment hashes)
	if p.vk != nil {
		pubVec := pubWitness.Vector().(fr.Vector)
		signals, err := computePublicSignals(proof, p.vk, pubVec)
		if err != nil {
			http.Error(w, fmt.Sprintf("compute public signals: %v", err), http.StatusInternalServerError)
			return
		}
		snarkProof["public_signals"] = signals
	}

	fmt.Printf("Proved in %v\n", elapsed)

	respBytes, err := json.Marshal(snarkProof)
	if err != nil {
		http.Error(w, fmt.Sprintf("marshal proof: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(respBytes)))
	w.Write(respBytes)
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

	snarkProof := proofToSnarkJS(proof)
	snarkProof["public_inputs"] = publicInputs

	// Compute flat public_signals array (including commitment hashes)
	if prover.vk != nil {
		pubVec := pubWitness.Vector().(fr.Vector)
		signals, err := computePublicSignals(proof, prover.vk, pubVec)
		if err != nil {
			fmt.Fprintf(os.Stderr, "compute public signals: %v\n", err)
			os.Exit(1)
		}
		snarkProof["public_signals"] = signals
	}

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
	vkPath := flag.String("vk", "", "verifying key path (enables public_signals output)")
	outPath := flag.String("out", "proof.json", "output proof path")
	gpuFlag := flag.Bool("gpu", false, "enable icicle GPU acceleration")
	serverFlag := flag.Bool("server", false, "run as HTTP server on unix socket")
	socketPath := flag.String("socket", "/tmp/gnark-prove.sock", "unix socket path (server mode)")
	flag.Parse()

	if *serverFlag {
		prover := initProver(*pkPath, *vkPath, *gpuFlag)
		runServer(prover, *socketPath)
		return
	}

	// CLI mode
	if *quotePath == "" || *prePath == "" || *tsStr == "" {
		fmt.Fprintln(os.Stderr, "usage: prove -quote <file> -pre <file> -timestamp <unix> [-pk pk.bin] [-vk vk.bin] [-out proof.json]")
		fmt.Fprintln(os.Stderr, "       prove -server [-pk pk.bin] [-vk vk.bin] [-socket /tmp/gnark-prove.sock] [-gpu]")
		os.Exit(1)
	}

	ts, err := strconv.ParseUint(*tsStr, 10, 64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid timestamp: %v\n", err)
		os.Exit(1)
	}

	prover := initProver(*pkPath, *vkPath, *gpuFlag)
	runCLI(prover, *quotePath, *prePath, ts, *outPath)
}

// g1ToDecimal converts a BN254 G1 affine point to [x, y, "1"] decimal strings.
func g1ToDecimal(p *bn254.G1Affine) []string {
	x := new(big.Int)
	y := new(big.Int)
	p.X.BigInt(x)
	p.Y.BigInt(y)
	return []string{x.String(), y.String(), "1"}
}

// proofToSnarkJS converts a gnark Groth16 proof to SnarkJS-compatible JSON.
// Uses concrete BN254 types for reliable field extraction.
func proofToSnarkJS(proof groth16.Proof) map[string]interface{} {
	p := proof.(*groth16_bn254.Proof)

	// G2 point extraction
	g2ToDecimal := func(pt *bn254.G2Affine) [][]string {
		x0 := new(big.Int)
		x1 := new(big.Int)
		y0 := new(big.Int)
		y1 := new(big.Int)
		pt.X.A0.BigInt(x0)
		pt.X.A1.BigInt(x1)
		pt.Y.A0.BigInt(y0)
		pt.Y.A1.BigInt(y1)
		return [][]string{
			{x0.String(), x1.String()},
			{y0.String(), y1.String()},
			{"1", "0"},
		}
	}

	result := map[string]interface{}{
		"pi_a":     g1ToDecimal(&p.Ar),
		"pi_b":     g2ToDecimal(&p.Bs),
		"pi_c":     g1ToDecimal(&p.Krs),
		"protocol": "groth16",
		"curve":    "bn128",
	}

	// Include Pedersen commitment data if present
	if len(p.Commitments) > 0 {
		comms := make([][]string, len(p.Commitments))
		for i := range p.Commitments {
			comms[i] = g1ToDecimal(&p.Commitments[i])
		}
		result["commitments"] = comms
		result["commitment_pok"] = g1ToDecimal(&p.CommitmentPok)
	}

	return result
}

// computePublicSignals produces the flat decimal-string public signals array,
// replicating gnark's verify.go commitment hash computation (lines 77-94).
// Output order: [circuit_public_inputs..., commitment_hashes...]
func computePublicSignals(proof groth16.Proof, vk *groth16_bn254.VerifyingKey, pubWitVec fr.Vector) ([]string, error) {
	nCommitments := len(vk.PublicAndCommitmentCommitted)
	signals := make([]string, 0, len(pubWitVec)+nCommitments)

	// Circuit public inputs as decimal strings
	for _, elem := range pubWitVec {
		var bi big.Int
		elem.BigInt(&bi)
		signals = append(signals, bi.String())
	}

	if nCommitments == 0 {
		return signals, nil
	}

	// Compute commitment hashes (replicates verify.go solveCommitmentWire)
	proofBn254 := proof.(*groth16_bn254.Proof)

	for i := range vk.PublicAndCommitmentCommitted {
		if i >= len(proofBn254.Commitments) {
			return nil, fmt.Errorf("proof has %d commitments, VK expects %d", len(proofBn254.Commitments), nCommitments)
		}

		// Serialize: commitment_G1_uncompressed || committed_public_values
		commitBytes := proofBn254.Commitments[i].Marshal() // 64 bytes (uncompressed G1)
		prehash := make([]byte, len(commitBytes)+len(vk.PublicAndCommitmentCommitted[i])*fr.Bytes)
		copy(prehash, commitBytes)
		offset := len(commitBytes)
		for _, idx := range vk.PublicAndCommitmentCommitted[i] {
			copy(prehash[offset:], pubWitVec[idx-1].Marshal()) // idx is 1-based (0=ONE wire)
			offset += fr.Bytes
		}

		// Hash to field with domain "bsb22-commitment"
		hFunc := hash_to_field.New([]byte("bsb22-commitment"))
		hFunc.Write(prehash[:offset])
		hashBts := hFunc.Sum(nil)

		var res fr.Element
		res.SetBytes(hashBts[:fr.Bytes])

		var bi big.Int
		res.BigInt(&bi)
		signals = append(signals, bi.String())
	}

	return signals, nil
}
