package config

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	core "github.com/iden3/go-iden3-core"
	"github.com/kelseyhightower/envconfig"
	"gopkg.in/yaml.v3"
)

type resolverSettings map[string]struct {
	NetworkURL    string `yaml:"networkURL" default:"https://polygon-mumbai.g.alchemy.com/v2/U8dKILdlLLRhfB_CzYjZ9gNB2eyBOWrb"`
	ContractState string `yaml:"contractState" default:"0x134B1BE34911E39A8397ec6289782989729807a4"`
}

func (r resolverSettings) Verify() error {
	for _, settings := range r {
		if settings.NetworkURL == "" {
			return errors.New("network url is not set")
		}
		if settings.ContractState == "" {
			return errors.New("contract state is not set")
		}
	}
	return nil
}

type Config struct {
	OnchainIssuerContractAddress    string `envconfig:"ONCHAIN_ISSUER_CONTRACT_ADDRESS" default:"0x134B1BE34911E39A8397ec6289782989729807a4"`
	KeyDir                          string `envconfig:"KEY_DIR" default:"./keys"`
	HostUrl                         string `envconfig:"HOST_URL" default:"https://d527-212-104-236-94.ngrok-free.app"`
	OnchainIssuerContractBlockchain string `envconfig:"ONCHAIN_ISSUER_CONTRACT_BLOCKCHAIN" default:"polygon" required:"true"`
	OnchainIssuerContractNetwork    string `envconfig:"ONCHAIN_ISSUER_CONTRACT_NETWORK" default:"mumbai" required:"true"`

	OnchainIssuerIdentity string
	Resolvers             resolverSettings
}

func (c *Config) GetIssuerIdentityDIDFromAddress() error {
	genesis := genFromHex("00000000000000" + strings.Trim(c.OnchainIssuerContractAddress, "0x"))
	tp, err := core.BuildDIDType(
		core.DIDMethodPolygonID,
		core.Blockchain(c.OnchainIssuerContractBlockchain),
		core.NetworkID(c.OnchainIssuerContractNetwork),
	)
	if err != nil {
		return err
	}
	id := core.NewID(tp, genesis)
	c.OnchainIssuerIdentity = fmt.Sprintf(
		"did:polygonid:%s:%s:%v",
		c.OnchainIssuerContractBlockchain,
		c.OnchainIssuerContractNetwork,
		id.String(),
	)

	return nil
}

func readResolverConfig(cfg *Config) error {
	content, err := os.ReadFile("resolvers.settings.yaml")
	if err != nil {
		return err
	}
	var settings resolverSettings
	if err = yaml.Unmarshal(content, &settings); err != nil {
		return err
	}
	if err = settings.Verify(); err != nil {
		return err
	}
	cfg.Resolvers = settings
	return nil
}

func ParseConfig() (Config, error) {
	var cfg Config
	if err := envconfig.Process("", &cfg); err != nil {
		log.Fatal("failed read config", err)
	}
	if err := readResolverConfig(&cfg); err != nil {
		return cfg, err
	}
	if err := cfg.Resolvers.Verify(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func genFromHex(gh string) [27]byte {
	genBytes, err := hex.DecodeString(gh)
	if err != nil {
		panic(err)
	}
	var gen [27]byte
	copy(gen[:], genBytes)
	return gen
}
