package main

/*
#include "./koalabear.h"
#include <stdlib.h>

typedef struct {
	char *PublicInputs[5];
	char *EncodedProof;
	char *RawProof;
} C_PlonkBn254Proof;

typedef struct {
	char *PublicInputs[5];
	char *EncodedProof;
	char *RawProof;
} C_Groth16Bn254Proof;
*/
import "C"
import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"unsafe"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"
	"github.com/succinctlabs/sp1-recursion-gnark/sp1"
	"github.com/succinctlabs/sp1-recursion-gnark/sp1/koalabear"
	"github.com/succinctlabs/sp1-recursion-gnark/sp1/poseidon2"
)

func main() {}

//export ProvePlonkBn254
func ProvePlonkBn254(dataDir *C.char, witnessPath *C.char) *C.C_PlonkBn254Proof {
	dataDirString := C.GoString(dataDir)
	witnessPathString := C.GoString(witnessPath)

	sp1PlonkBn254Proof := sp1.ProvePlonk(dataDirString, witnessPathString)

	ms := C.malloc(C.sizeof_C_PlonkBn254Proof)
	if ms == nil {
		return nil
	}

	structPtr := (*C.C_PlonkBn254Proof)(ms)
	structPtr.PublicInputs[0] = C.CString(sp1PlonkBn254Proof.PublicInputs[0])
	structPtr.PublicInputs[1] = C.CString(sp1PlonkBn254Proof.PublicInputs[1])
	structPtr.PublicInputs[2] = C.CString(sp1PlonkBn254Proof.PublicInputs[2])
	structPtr.PublicInputs[3] = C.CString(sp1PlonkBn254Proof.PublicInputs[3])
	structPtr.PublicInputs[4] = C.CString(sp1PlonkBn254Proof.PublicInputs[4])
	structPtr.EncodedProof = C.CString(sp1PlonkBn254Proof.EncodedProof)
	structPtr.RawProof = C.CString(sp1PlonkBn254Proof.RawProof)
	return structPtr
}

//export FreePlonkBn254Proof
func FreePlonkBn254Proof(proof *C.C_PlonkBn254Proof) {
	C.free(unsafe.Pointer(proof.EncodedProof))
	C.free(unsafe.Pointer(proof.RawProof))
	C.free(unsafe.Pointer(proof.PublicInputs[0]))
	C.free(unsafe.Pointer(proof.PublicInputs[1]))
	C.free(unsafe.Pointer(proof.PublicInputs[2]))
	C.free(unsafe.Pointer(proof.PublicInputs[3]))
	C.free(unsafe.Pointer(proof.PublicInputs[4]))
	C.free(unsafe.Pointer(proof))
}

//export BuildPlonkBn254
func BuildPlonkBn254(dataDir *C.char) {
	// Sanity check the required arguments have been provided.
	dataDirString := C.GoString(dataDir)

	sp1.BuildPlonk(dataDirString)
}

//export VerifyPlonkBn254
func VerifyPlonkBn254(dataDir *C.char, proof *C.char, vkeyHash *C.char, committedValuesDigest *C.char, exitCode *C.char, vkRoot *C.char, proofNonce *C.char) *C.char {
	dataDirString := C.GoString(dataDir)
	proofString := C.GoString(proof)
	vkeyHashString := C.GoString(vkeyHash)
	committedValuesDigestString := C.GoString(committedValuesDigest)
	exitCodeString := C.GoString(exitCode)
	vkRootString := C.GoString(vkRoot)
	proofNonceString := C.GoString(proofNonce)
	err := sp1.VerifyPlonk(dataDirString, proofString, vkeyHashString, committedValuesDigestString, exitCodeString, vkRootString, proofNonceString)
	if err != nil {
		return C.CString(err.Error())
	}
	return nil
}

var testMutex = &sync.Mutex{}

//export TestPlonkBn254
func TestPlonkBn254(witnessPath *C.char, constraintsJson *C.char) *C.char {
	// Because of the global env variables used here, we need to lock this function
	testMutex.Lock()
	witnessPathString := C.GoString(witnessPath)
	constraintsJsonString := C.GoString(constraintsJson)
	os.Setenv("WITNESS_JSON", witnessPathString)
	os.Setenv("CONSTRAINTS_JSON", constraintsJsonString)
	err := TestMain()
	testMutex.Unlock()
	if err != nil {
		return C.CString(err.Error())
	}
	return nil
}

//export ProveGroth16Bn254
func ProveGroth16Bn254(dataDir *C.char, witnessPath *C.char) *C.C_Groth16Bn254Proof {
	dataDirString := C.GoString(dataDir)
	witnessPathString := C.GoString(witnessPath)

	sp1Groth16Bn254Proof := sp1.ProveGroth16(dataDirString, witnessPathString)

	ms := C.malloc(C.sizeof_C_Groth16Bn254Proof)
	if ms == nil {
		return nil
	}

	structPtr := (*C.C_Groth16Bn254Proof)(ms)
	structPtr.PublicInputs[0] = C.CString(sp1Groth16Bn254Proof.PublicInputs[0])
	structPtr.PublicInputs[1] = C.CString(sp1Groth16Bn254Proof.PublicInputs[1])
	structPtr.PublicInputs[2] = C.CString(sp1Groth16Bn254Proof.PublicInputs[2])
	structPtr.PublicInputs[3] = C.CString(sp1Groth16Bn254Proof.PublicInputs[3])
	structPtr.PublicInputs[4] = C.CString(sp1Groth16Bn254Proof.PublicInputs[4])
	structPtr.EncodedProof = C.CString(sp1Groth16Bn254Proof.EncodedProof)
	structPtr.RawProof = C.CString(sp1Groth16Bn254Proof.RawProof)
	return structPtr
}

//export FreeGroth16Bn254Proof
func FreeGroth16Bn254Proof(proof *C.C_Groth16Bn254Proof) {
	C.free(unsafe.Pointer(proof.EncodedProof))
	C.free(unsafe.Pointer(proof.RawProof))
	C.free(unsafe.Pointer(proof.PublicInputs[0]))
	C.free(unsafe.Pointer(proof.PublicInputs[1]))
	C.free(unsafe.Pointer(proof.PublicInputs[2]))
	C.free(unsafe.Pointer(proof.PublicInputs[3]))
	C.free(unsafe.Pointer(proof.PublicInputs[4]))
	C.free(unsafe.Pointer(proof))
}

//export BuildGroth16Bn254
func BuildGroth16Bn254(dataDir *C.char) {
	// Sanity check the required arguments have been provided.
	dataDirString := C.GoString(dataDir)

	sp1.BuildGroth16(dataDirString)
}

//export VerifyGroth16Bn254
func VerifyGroth16Bn254(dataDir *C.char, proof *C.char, vkeyHash *C.char, committedValuesDigest *C.char, exitCode *C.char, vkRoot *C.char, proofNonce *C.char) *C.char {
	dataDirString := C.GoString(dataDir)
	proofString := C.GoString(proof)
	vkeyHashString := C.GoString(vkeyHash)
	committedValuesDigestString := C.GoString(committedValuesDigest)
	exitCodeString := C.GoString(exitCode)
	vkRootString := C.GoString(vkRoot)
	proofNonceString := C.GoString(proofNonce)
	err := sp1.VerifyGroth16(dataDirString, proofString, vkeyHashString, committedValuesDigestString, exitCodeString, vkRootString, proofNonceString)
	if err != nil {
		return C.CString(err.Error())
	}
	return nil
}

//export TestGroth16Bn254
func TestGroth16Bn254(witnessJson *C.char, constraintsJson *C.char) *C.char {
	// Because of the global env variables used here, we need to lock this function
	testMutex.Lock()
	witnessPathString := C.GoString(witnessJson)
	constraintsJsonString := C.GoString(constraintsJson)
	os.Setenv("WITNESS_JSON", witnessPathString)
	os.Setenv("CONSTRAINTS_JSON", constraintsJsonString)
	os.Setenv("GROTH16", "1")
	err := TestMain()
	testMutex.Unlock()
	if err != nil {
		return C.CString(err.Error())
	}
	return nil
}

func TestMain() error {
	// Get the file name from an environment variable.
	fileName := os.Getenv("WITNESS_JSON")
	if fileName == "" {
		fileName = "plonk_witness.json"
	}

	// Read the file.
	data, err := os.ReadFile(fileName)
	if err != nil {
		return err
	}

	// Deserialize the JSON data into a slice of Instruction structs
	var inputs sp1.WitnessInput
	err = json.Unmarshal(data, &inputs)
	if err != nil {
		return err
	}

	// Compile the circuit.
	circuit := sp1.NewCircuit(inputs)
	builder := scs.NewBuilder
	scs, err := frontend.Compile(ecc.BN254.ScalarField(), builder, &circuit)
	if err != nil {
		return err
	}
	fmt.Println("[sp1] gnark verifier constraints:", scs.GetNbConstraints())

	// Run the dummy setup.
	srs, srsLagrange, err := unsafekzg.NewSRS(scs)
	if err != nil {
		return err
	}
	var pk plonk.ProvingKey
	pk, _, err = plonk.Setup(scs, srs, srsLagrange)
	if err != nil {
		return err
	}

	// Generate witness.
	assignment := sp1.NewCircuit(inputs)
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		return err
	}

	// Generate the proof.
	_, err = plonk.Prove(scs, pk, witness)
	if err != nil {
		return err
	}

	return nil
}

//export TestPoseidonKoalaBear2
func TestPoseidonKoalaBear2() *C.char {
	input := [poseidon2.KOALABEAR_WIDTH]koalabear.Variable{
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
	}

	expectedOutput := [poseidon2.KOALABEAR_WIDTH]koalabear.Variable{
		koalabear.NewFConst("145589356"),
		koalabear.NewFConst("1876041682"),
		koalabear.NewFConst("1734203622"),
		koalabear.NewFConst("499355069"),
		koalabear.NewFConst("673349476"),
		koalabear.NewFConst("595701365"),
		koalabear.NewFConst("270340205"),
		koalabear.NewFConst("131707822"),
		koalabear.NewFConst("1236787881"),
		koalabear.NewFConst("1085405948"),
		koalabear.NewFConst("2065733208"),
		koalabear.NewFConst("1999012278"),
		koalabear.NewFConst("2062318124"),
		koalabear.NewFConst("1616707536"),
		koalabear.NewFConst("324813015"),
		koalabear.NewFConst("749520722"),
	}

	circuit := sp1.TestPoseidon2KoalaBearCircuit{Input: input, ExpectedOutput: expectedOutput}
	assignment := sp1.TestPoseidon2KoalaBearCircuit{Input: input, ExpectedOutput: expectedOutput}

	builder := r1cs.NewBuilder
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), builder, &circuit)
	if err != nil {
		return C.CString(err.Error())
	}

	var pk groth16.ProvingKey
	pk, err = groth16.DummySetup(r1cs)
	if err != nil {
		return C.CString(err.Error())
	}

	// Generate witness.
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		return C.CString(err.Error())
	}

	// Generate the proof.
	_, err = groth16.Prove(r1cs, pk, witness)
	if err != nil {
		return C.CString(err.Error())
	}

	return nil
}

//export FreeString
func FreeString(s *C.char) {
	C.free(unsafe.Pointer(s))
}
