package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"github.com/reliqlabs/oauth3/circuits/dcap-gnark/circuit"
	"github.com/reliqlabs/oauth3/circuits/dcap-gnark/witness"
)

func main() {
	quotePath := flag.String("quote", "", "path to quote.bin")
	prePath := flag.String("pre", "", "path to pre_verified.json")
	tsStr := flag.String("timestamp", "", "verification timestamp (unix seconds)")
	pkPath := flag.String("pk", "pk.bin", "proving key path")
	outPath := flag.String("out", "proof.json", "output proof path")
	gpuFlag := flag.Bool("gpu", false, "enable icicle GPU acceleration")
	flag.Parse()

	if *quotePath == "" || *prePath == "" || *tsStr == "" {
		fmt.Fprintln(os.Stderr, "usage: prove -quote <file> -pre <file> -timestamp <unix> [-pk pk.bin] [-out proof.json]")
		os.Exit(1)
	}

	ts, err := strconv.ParseUint(*tsStr, 10, 64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid timestamp: %v\n", err)
		os.Exit(1)
	}

	// Read inputs
	quoteBytes, err := os.ReadFile(*quotePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read quote: %v\n", err)
		os.Exit(1)
	}

	preBytes, err := os.ReadFile(*prePath)
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

	// Build witness
	fmt.Println("Building witness...")
	tStep := time.Now()
	assignment, err := witness.BuildWitness(quoteBytes, preVerified, ts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "build witness: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Witness built in %v\n", time.Since(tStep))

	// Compile circuit (needed for witness creation)
	fmt.Println("Compiling circuit...")
	tStep = time.Now()
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit.DcapCircuit{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "compile: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Circuit compiled in %v (%d constraints)\n", time.Since(tStep), ccs.GetNbConstraints())

	// Create witness
	tStep = time.Now()
	w, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		fmt.Fprintf(os.Stderr, "create witness: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Witness created in %v\n", time.Since(tStep))

	// Load proving key
	fmt.Println("Loading proving key...")
	tStep = time.Now()
	fpk, err := os.Open(*pkPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open pk: %v\n", err)
		os.Exit(1)
	}
	defer fpk.Close()

	pk := groth16.NewProvingKey(ecc.BN254)
	if _, err := pk.ReadFrom(fpk); err != nil {
		fmt.Fprintf(os.Stderr, "read pk: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Proving key loaded in %v\n", time.Since(tStep))

	// Prove
	var proveOpts []backend.ProverOption
	if *gpuFlag {
		fmt.Println("GPU acceleration enabled (icicle)")
		proveOpts = append(proveOpts, backend.WithIcicleAcceleration())
	}
	fmt.Println("Proving...")
	t0 := time.Now()
	proof, err := groth16.Prove(ccs, pk, w, proveOpts...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "prove: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Proved in %v\n", time.Since(t0))

	// Extract public witness
	pubWitness, err := w.Public()
	if err != nil {
		fmt.Fprintf(os.Stderr, "extract public witness: %v\n", err)
		os.Exit(1)
	}
	schema, err := frontend.NewSchema(ecc.BN254.ScalarField(), &circuit.DcapCircuit{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "create schema: %v\n", err)
		os.Exit(1)
	}
	pubJSON, err := pubWitness.ToJSON(schema)
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal public witness: %v\n", err)
		os.Exit(1)
	}
	var publicInputs map[string]interface{}
	if err := json.Unmarshal(pubJSON, &publicInputs); err != nil {
		fmt.Fprintf(os.Stderr, "parse public witness JSON: %v\n", err)
		os.Exit(1)
	}

	// Convert to SnarkJS-compatible format
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

	if err := os.WriteFile(*outPath, outJSON, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "write proof: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Proof written to %s\n", *outPath)
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
