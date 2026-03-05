package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"github.com/reliqlabs/oauth3/circuits/dcap-gnark/circuit"
)

func main() {
	pkOut := flag.String("pk", "pk.bin", "proving key output path")
	vkOut := flag.String("vk", "vk.bin", "verifying key output path")
	flag.Parse()

	fmt.Println("Compiling DCAP circuit...")
	t0 := time.Now()
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit.DcapCircuit{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "compile error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Compiled: %d constraints in %v\n", ccs.GetNbConstraints(), time.Since(t0))

	fmt.Println("Running Groth16 setup...")
	t1 := time.Now()
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "setup error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Setup complete in %v\n", time.Since(t1))

	// Write proving key
	fpk, err := os.Create(*pkOut)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create pk: %v\n", err)
		os.Exit(1)
	}
	defer fpk.Close()
	if _, err := pk.WriteTo(fpk); err != nil {
		fmt.Fprintf(os.Stderr, "write pk: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Proving key written to %s\n", *pkOut)

	// Write verifying key
	fvk, err := os.Create(*vkOut)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create vk: %v\n", err)
		os.Exit(1)
	}
	defer fvk.Close()
	if _, err := vk.WriteTo(fvk); err != nil {
		fmt.Fprintf(os.Stderr, "write vk: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Verifying key written to %s\n", *vkOut)
}
