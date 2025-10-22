package sp1

import (
	"bytes"
	"encoding/hex"
	"math/big"

	groth16 "github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	plonk "github.com/consensys/gnark/backend/plonk"
	plonk_bn254 "github.com/consensys/gnark/backend/plonk/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/succinctlabs/sp1-recursion-gnark/sp1/koalabear"
)

func parseBig(s string) *big.Int {
	value := new(big.Int)
	if _, ok := value.SetString(s, 0); !ok {
		panic("invalid integer string: " + s)
	}
	return value
}

func writeUint256(buf *bytes.Buffer, v *big.Int) {
	b := v.Bytes()
	if len(b) > 32 {
		panic("value too large for uint256")
	}
	buf.Write(make([]byte, 32-len(b)))
	buf.Write(b)
}

func NewSP1PlonkBn254Proof(proof *plonk.Proof, witnessInput WitnessInput) Proof {
	var buf bytes.Buffer
	(*proof).WriteRawTo(&buf)
	proofBytes := buf.Bytes()

	var publicInputs [5]string
	publicInputs[0] = witnessInput.VkeyHash
	publicInputs[1] = witnessInput.CommittedValuesDigest
	publicInputs[2] = witnessInput.ExitCode
	publicInputs[3] = witnessInput.VkRoot
	publicInputs[4] = witnessInput.ProofNonce

	// Cast plonk proof into plonk_bn254 proof so we can call MarshalSolidity.
	p := (*proof).(*plonk_bn254.Proof)

	encodedProof := p.MarshalSolidity()

	var encodedProofBuf bytes.Buffer
	writeUint256(&encodedProofBuf, parseBig(witnessInput.ExitCode))
	writeUint256(&encodedProofBuf, parseBig(witnessInput.VkRoot))
	encodedProofBuf.Write(encodedProof)

	return Proof{
		PublicInputs: publicInputs,
		EncodedProof: hex.EncodeToString(encodedProofBuf.Bytes()),
		RawProof:     hex.EncodeToString(proofBytes),
	}
}

func NewSP1Groth16Proof(proof *groth16.Proof, witnessInput WitnessInput) Proof {
	var buf bytes.Buffer
	(*proof).WriteRawTo(&buf)
	proofBytes := buf.Bytes()

	var publicInputs [5]string
	publicInputs[0] = witnessInput.VkeyHash
	publicInputs[1] = witnessInput.CommittedValuesDigest
	publicInputs[2] = witnessInput.ExitCode
	publicInputs[3] = witnessInput.VkRoot
	publicInputs[4] = witnessInput.ProofNonce

	// Cast groth16 proof into groth16_bn254 proof so we can call MarshalSolidity.
	p := (*proof).(*groth16_bn254.Proof)

	encodedProof := p.MarshalSolidity()

	var encodedProofBuf bytes.Buffer
	writeUint256(&encodedProofBuf, parseBig(witnessInput.ExitCode))
	writeUint256(&encodedProofBuf, parseBig(witnessInput.VkRoot))
	encodedProofBuf.Write(encodedProof)

	return Proof{
		PublicInputs: publicInputs,
		EncodedProof: hex.EncodeToString(encodedProofBuf.Bytes()),
		RawProof:     hex.EncodeToString(proofBytes),
	}
}

func NewCircuit(witnessInput WitnessInput) Circuit {
	vars := make([]frontend.Variable, len(witnessInput.Vars))
	felts := make([]koalabear.Variable, len(witnessInput.Felts))
	exts := make([]koalabear.ExtensionVariable, len(witnessInput.Exts))
	for i := 0; i < len(witnessInput.Vars); i++ {
		vars[i] = frontend.Variable(witnessInput.Vars[i])
	}
	for i := 0; i < len(witnessInput.Felts); i++ {
		felts[i] = koalabear.NewF(witnessInput.Felts[i])
	}
	for i := 0; i < len(witnessInput.Exts); i++ {
		exts[i] = koalabear.NewE(witnessInput.Exts[i])
	}
	return Circuit{
		VkeyHash:              witnessInput.VkeyHash,
		CommittedValuesDigest: witnessInput.CommittedValuesDigest,
		ExitCode:              witnessInput.ExitCode,
		VkRoot:                witnessInput.VkRoot,
		ProofNonce:            witnessInput.ProofNonce,
		Vars:                  vars,
		Felts:                 felts,
		Exts:                  exts,
	}
}
