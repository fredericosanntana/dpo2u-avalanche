package midnightverifier

// The verifier itself is Midnight's own (midnight-zk, pinned in ../midnight-verifier-ffi), built as
// a static library and called over its C ABI. Build it before the Go package:
//
//	../build-ffi.sh

/*
#cgo LDFLAGS: -L${SRCDIR}/lib -ldpo2u_midnight_verifier -lgcc_s -lutil -lrt -lpthread -lm -ldl
#include <stddef.h>
#include <stdint.h>

int32_t dpo2u_midnight_verify(const uint8_t *params, size_t params_len,
                              const uint8_t *vk, size_t vk_len,
                              const uint8_t *public_inputs, size_t public_inputs_len,
                              const uint8_t *proof, size_t proof_len);
int64_t dpo2u_midnight_check_vk(const uint8_t *vk, size_t vk_len);
int32_t dpo2u_midnight_check_params(const uint8_t *params, size_t params_len);
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// Codes returned by the Rust verifier for malformed inputs.
const (
	codeParams              = -1
	codeVerifyingKey        = -2
	codePublicInputLength   = -3
	codePublicInputNotCanon = -4
	codePublicInputCount    = -5
	codePanic               = -100
)

func ptr(b []byte) *C.uint8_t {
	if len(b) == 0 {
		return nil
	}
	return (*C.uint8_t)(unsafe.Pointer(&b[0]))
}

func codeError(code int64) error {
	switch code {
	case codeParams:
		return fmt.Errorf("midnight verifier: invalid verifier params")
	case codeVerifyingKey:
		return fmt.Errorf("midnight verifier: invalid verifying key")
	case codePublicInputLength:
		return fmt.Errorf("midnight verifier: public inputs are not 32-byte words")
	case codePublicInputNotCanon:
		return fmt.Errorf("midnight verifier: public input is not a canonical BLS12-381 scalar")
	case codePublicInputCount:
		return fmt.Errorf("midnight verifier: wrong number of public inputs for this key")
	case codePanic:
		return fmt.Errorf("midnight verifier: input rejected (verifier panicked)")
	default:
		return fmt.Errorf("midnight verifier: unexpected code %d", code)
	}
}

// nativeVerify checks one proof. (true, nil) valid, (false, nil) invalid proof, error for
// malformed params, key or public inputs. publicInputs are 32-byte big-endian words.
func nativeVerify(params, vk, publicInputs, proof []byte) (bool, error) {
	// cgo pointer rules: the Go slices are only read during the call and not retained.
	r := C.dpo2u_midnight_verify(
		ptr(params), C.size_t(len(params)),
		ptr(vk), C.size_t(len(vk)),
		ptr(publicInputs), C.size_t(len(publicInputs)),
		ptr(proof), C.size_t(len(proof)),
	)
	switch r {
	case 1:
		return true, nil
	case 0:
		return false, nil
	default:
		return false, codeError(int64(r))
	}
}

// nativeCheckVK returns the number of public inputs the key expects, or an error if it does not
// parse.
func nativeCheckVK(vk []byte) (int, error) {
	r := int64(C.dpo2u_midnight_check_vk(ptr(vk), C.size_t(len(vk))))
	if r < 0 {
		return 0, codeError(r)
	}
	return int(r), nil
}

// nativeCheckParams returns an error unless params parse as KZG verifier parameters.
func nativeCheckParams(params []byte) error {
	if r := C.dpo2u_midnight_check_params(ptr(params), C.size_t(len(params))); r != 1 {
		return codeError(int64(r))
	}
	return nil
}
