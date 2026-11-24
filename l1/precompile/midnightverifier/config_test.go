package midnightverifier

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ava-labs/subnet-evm/precompile/precompileconfig"
	"github.com/ava-labs/subnet-evm/precompile/precompiletest"
	"github.com/ava-labs/subnet-evm/utils"
	"go.uber.org/mock/gomock"
)

func testParams(t testing.TB) []byte {
	b, err := os.ReadFile(filepath.Join("..", "testdata", "membership-k12", "params.bin"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestVerify(t *testing.T) {
	params := testParams(t)
	chainConfig := func() precompileconfig.ChainConfig {
		config := precompileconfig.NewMockChainConfig(gomock.NewController(t))
		config.EXPECT().IsDurango(gomock.Any()).Return(true).AnyTimes()
		return config
	}
	tests := map[string]precompiletest.ConfigVerifyTest{
		"valid config": {
			Config:      NewConfig(utils.NewUint64(3), params),
			ChainConfig: chainConfig(),
		},
		"missing params": {
			Config:        NewConfig(utils.NewUint64(3), nil),
			ChainConfig:   chainConfig(),
			ExpectedError: "verifierParams is required",
		},
		"params that do not parse": {
			Config:        NewConfig(utils.NewUint64(3), params[:95]),
			ChainConfig:   chainConfig(),
			ExpectedError: "invalid verifier params",
		},
		"disable needs no params": {
			Config:      NewDisableConfig(utils.NewUint64(3)),
			ChainConfig: chainConfig(),
		},
	}
	precompiletest.RunVerifyTests(t, tests)
}

func TestEqual(t *testing.T) {
	params := testParams(t)
	other := append([]byte{}, params...)
	other[0] ^= 1
	tests := map[string]precompiletest.ConfigEqualTest{
		"non-nil config and nil other": {
			Config:   NewConfig(utils.NewUint64(3), params),
			Other:    nil,
			Expected: false,
		},
		"different type": {
			Config:   NewConfig(utils.NewUint64(3), params),
			Other:    precompileconfig.NewMockConfig(gomock.NewController(t)),
			Expected: false,
		},
		"different timestamp": {
			Config:   NewConfig(utils.NewUint64(3), params),
			Other:    NewConfig(utils.NewUint64(4), params),
			Expected: false,
		},
		"different params": {
			Config:   NewConfig(utils.NewUint64(3), params),
			Other:    NewConfig(utils.NewUint64(3), other),
			Expected: false,
		},
		"same config": {
			Config:   NewConfig(utils.NewUint64(3), params),
			Other:    NewConfig(utils.NewUint64(3), params),
			Expected: true,
		},
	}
	precompiletest.RunEqualTests(t, tests)
}
