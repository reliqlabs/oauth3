package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/groth16"
)

func main() {
	vkPath := flag.String("vk", "vk.bin", "path to gnark vk.bin")
	output := flag.String("output", "", "output file (default: stdout)")
	flag.Parse()

	f, err := os.Open(*vkPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open vk: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	vk := groth16.NewVerifyingKey(ecc.BN254)
	if _, err := vk.ReadFrom(f); err != nil {
		fmt.Fprintf(os.Stderr, "read vk: %v\n", err)
		os.Exit(1)
	}

	// Cast to bn254 concrete type to access fields
	vkBn254 := vk.(*groth16_bn254.VerifyingKey)
	snarkjs := toSnarkJS(vkBn254)

	out, err := json.MarshalIndent(snarkjs, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal: %v\n", err)
		os.Exit(1)
	}

	if *output != "" {
		if err := os.WriteFile(*output, out, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "write: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "wrote %s\n", *output)
	} else {
		fmt.Println(string(out))
	}
}

func toSnarkJS(vk *groth16_bn254.VerifyingKey) map[string]interface{} {
	nPublic := len(vk.G1.K) - 1

	ic := make([][]string, len(vk.G1.K))
	for i, p := range vk.G1.K {
		ic[i] = g1ToJSON(&p)
	}

	result := map[string]interface{}{
		"protocol":         "groth16",
		"curve":            "bn128",
		"nPublic":          nPublic,
		"vk_alpha_1":       g1ToJSON(&vk.G1.Alpha),
		"vk_beta_2":        g2ToJSON(&vk.G2.Beta),
		"vk_gamma_2":       g2ToJSON(&vk.G2.Gamma),
		"vk_delta_2":       g2ToJSON(&vk.G2.Delta),
		"vk_alphabeta_12":  alphabetaPlaceholder(),
		"IC":               ic,
	}

	// Include Pedersen commitment metadata (gnark v0.14+ auto-commits private inputs)
	if len(vk.PublicAndCommitmentCommitted) > 0 {
		result["nCommitments"] = len(vk.PublicAndCommitmentCommitted)
		result["publicAndCommitmentCommitted"] = vk.PublicAndCommitmentCommitted

		// Export commitment verifying keys (G, GRootSigmaNeg points)
		commitmentKeys := make([]map[string]interface{}, len(vk.CommitmentKeys))
		for i, ck := range vk.CommitmentKeys {
			commitmentKeys[i] = map[string]interface{}{
				"g":                g2ToJSON(&ck.G),
				"gSigmaNeg":       g2ToJSON(&ck.GSigmaNeg),
			}
		}
		result["commitmentKeys"] = commitmentKeys
	}

	return result
}

func g1ToJSON(p *bn254.G1Affine) []string {
	x := new(big.Int)
	y := new(big.Int)
	p.X.BigInt(x)
	p.Y.BigInt(y)
	return []string{x.String(), y.String(), "1"}
}

func g2ToJSON(p *bn254.G2Affine) [][]string {
	x0 := new(big.Int)
	x1 := new(big.Int)
	y0 := new(big.Int)
	y1 := new(big.Int)
	p.X.A0.BigInt(x0)
	p.X.A1.BigInt(x1)
	p.Y.A0.BigInt(y0)
	p.Y.A1.BigInt(y1)
	return [][]string{
		{x0.String(), x1.String()},
		{y0.String(), y1.String()},
		{"1", "0"},
	}
}

func alphabetaPlaceholder() [2][3][2]string {
	var out [2][3][2]string
	for i := range out {
		for j := range out[i] {
			out[i][j] = [2]string{"0", "0"}
		}
	}
	return out
}
