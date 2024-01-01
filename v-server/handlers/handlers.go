package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"strconv"
	"time"

	"github.com/0xPolygonID/onchain-issuer-integration-demo/server/config"
	"github.com/ethereum/go-ethereum/common"
	"github.com/google/uuid"
	circuits "github.com/iden3/go-circuits/v2"
	auth "github.com/iden3/go-iden3-auth/v2"

	"github.com/iden3/go-iden3-auth/v2/loaders"
	"github.com/iden3/go-iden3-auth/v2/pubsignals"
	"github.com/iden3/go-iden3-auth/v2/state"
	"github.com/iden3/iden3comm/v2/protocol"
	"github.com/patrickmn/go-cache"
	"github.com/ugorji/go/codec"
)

var (
	NgrokCallbackURL   string
	userSessionTracker = cache.New(60*time.Minute, 60*time.Minute)
	jsonHandle         codec.JsonHandle
)

const (
	URL = "https://1b05-112-134-208-202.ngrok-free.app"
)

type Handler struct {
	cfg config.Config
}

func NewHandler(cfg config.Config) *Handler {
	return &Handler{cfg: cfg}
}

func (h *Handler) GetAuthVerificationRequest(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Verification Request Stage 1")
	resB, sessionId, err := h.getAuthVerificationRequest()
	if err != nil {
		log.Printf("Server -> issuer.CommHandler.GetAuthVerificationRequest() return err, err: %v", err)
		EncodeResponse(w, http.StatusInternalServerError, fmt.Sprintf("can't get auth verification request. err: %v", err))
		return
	}
	w.Header().Set("Access-Control-Expose-Headers", "x-id")
	w.Header().Set("x-id", sessionId)
	w.Header().Set("Access-Control-Allow-Origin", "*")
	EncodeByteResponse(w, http.StatusOK, resB)
}

func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Callback Request Stage 1")
	sessionID := r.URL.Query().Get("sessionId")
	tokenBytes, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Server.callback() error reading request body, err: %v", err)
		EncodeResponse(w, http.StatusBadRequest, fmt.Errorf("can't read request body"))
		return
	}

	resB, err := h.callback(sessionID, tokenBytes)
	if err != nil {
		log.Printf("Server.callback() return err, err: %v", err)
		EncodeResponse(w, http.StatusInternalServerError, fmt.Errorf("can't handle callback request"))
		return
	}

	EncodeByteResponse(w, http.StatusOK, resB)
}

func (h *Handler) GetRequestStatus(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		log.Println("Server.getRequestStatus() url parameter has invalid values")
		EncodeResponse(w, http.StatusBadRequest, fmt.Errorf("url parameter has invalid values"))
		return
	}

	resB, err := h.getRequestStatus(id)
	if err != nil {
		log.Printf("Server -> issuer.CommHandler.GetRequestStatus() return err, err: %v", err)
		EncodeResponse(w, http.StatusInternalServerError, fmt.Sprintf("can't get request status. err: %v", err))
		return
	}

	if resB == nil {
		EncodeResponse(w, http.StatusNotFound, fmt.Errorf("can't get request status with id: %s", id))
		return
	}

	EncodeByteResponse(w, http.StatusOK, resB)
}

func (h *Handler) getAuthVerificationRequest() ([]byte, string, error) {
	fmt.Println("Verification Request Stage 2")
	log.Println("Communication.GetAuthVerificationRequest() invoked")

	sId := strconv.Itoa(rand.Intn(1000000))
	uri := fmt.Sprintf("%s/api/v1/callback?sessionId=%s", URL, sId)

	Audience := "did:polygonid:polygon:mumbai:2qG7bhdJKsk4tSbShiXiF2Eti2cVjUH3iTDXyyn6i7"

	// request := auth.CreateAuthorizationRequestWithMessage("test flow", "message to sign", h.cfg.OnchainIssuerIdentity, uri)
	var request protocol.AuthorizationRequestMessage = auth.CreateAuthorizationRequest("test flow", Audience, uri)

	request.ID = uuid.New().String()
	request.ThreadID = uuid.New().String()

	// Add request for a specific proof
	var mtpProofRequest protocol.ZeroKnowledgeProofRequest
	mtpProofRequest.ID = 1
	mtpProofRequest.CircuitID = string(circuits.AtomicQuerySigV2CircuitID)
	mtpProofRequest.Query = map[string]interface{}{
		"allowedIssuers": []string{"*"},
		"credentialSubject": map[string]interface{}{
			"filehash": map[string]interface{}{
				"$eq": "12345678",
			},
		},
		// "context": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
		"context": "ipfs://QmfN3SaKgvTFGVN4cXFH8oWtvvwEdVQ9aeBQcS4ACPW6Z5",
		"type":    "Identification",
	}
	request.Body.Scope = append(request.Body.Scope, mtpProofRequest)

	userSessionTracker.Set(sId, request, cache.DefaultExpiration)

	msgBytes, err := json.Marshal(request)
	if err != nil {
		return nil, "", fmt.Errorf("error marshalizing response: %v", err)
	}

	return msgBytes, sId, nil
}

func (h *Handler) callback(sId string, tokenBytes []byte) ([]byte, error) {
	fmt.Println("Callback Request Stage 2")
	log.Println("Communication.Callback() invoked")

	authRequest, wasFound := userSessionTracker.Get(sId)
	if !wasFound {
		return nil, fmt.Errorf("auth request was not found for session ID: %s", sId)
	}

	// Add Polygon Mumbai RPC node endpoint - needed to read on-chain state
	ethURL := "https://polygon-mumbai.g.alchemy.com/v2/vxZ13gzWqTPzjEAvZEQdHjmcV1620Gy8"

	// Add identity state contract address
	contractAddress := "0x134B1BE34911E39A8397ec6289782989729807a4"

	resolverPrefix := "polygon:mumbai"

	// var resolvers = make(map[string]pubsignals.StateResolver)
	resolver := state.ETHResolver{
		RPCUrl:          ethURL,
		ContractAddress: common.HexToAddress(contractAddress),
	}

	resolvers := map[string]pubsignals.StateResolver{
		resolverPrefix: resolver,
	}
	// for network, settings := range h.cfg.Resolvers {
	// 	resolvers[network] = state.ETHResolver{
	// 		RPCUrl:          settings.NetworkURL,
	// 		ContractAddress: common.HexToAddress(settings.ContractState),
	// 	}
	// }
	// var verificationKeyLoader = &loaders.FSKeyLoader{Dir: h.cfg.KeyDir}
	keyDIR := "./keys"
	var verificationKeyloader = &loaders.FSKeyLoader{Dir: keyDIR}
	// verifier, _ := auth.NewVerifier(verificationKeyLoader, loaders.DefaultSchemaLoader{}, resolvers)
	verifier, err := auth.NewVerifier(verificationKeyloader, resolvers, auth.WithIPFSGateway("https://ipfs.io"))
	if err != nil {
		return nil, fmt.Errorf("error creating verifier 1 %v", err)
	}

	if verifier == nil {
		return nil, fmt.Errorf("error creating verifier 2")
	}

	arm, err := verifier.FullVerify(
		context.Background(),
		string(tokenBytes),
		authRequest.(protocol.AuthorizationRequestMessage),
		pubsignals.WithAcceptedStateTransitionDelay(time.Minute*5))
	if err != nil {
		log.Println(err.Error())
		return nil, fmt.Errorf("error Full Verify: %v", err)
	}

	m := make(map[string]interface{})
	m["id"] = arm.From

	fmt.Printf("Arm.From >>> %v\n", arm.From)

	mBytes, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("error marshalizing response: %v", err)
	}

	userSessionTracker.Set(sId, m, cache.DefaultExpiration)

	return mBytes, nil
}

func (h *Handler) getRequestStatus(id string) ([]byte, error) {
	log.Println("Communication.Callback() Status invoked")

	item, ok := userSessionTracker.Get(id)
	if !ok {
		log.Printf("item not found %v", id)
		return nil, nil
	}

	switch item.(type) {
	case protocol.AuthorizationRequestMessage:
		log.Println("no authorization response yet - no data available for this request")
		return nil, nil
	case map[string]interface{}:
		b, err := json.Marshal(item)
		if err != nil {
			return nil, fmt.Errorf("error marshalizing response: %v", err)
		}
		return b, nil
	}

	return nil, fmt.Errorf("unknown item return from tracker (type %T)", item)
}

func EncodeByteResponse(w http.ResponseWriter, statusCode int, res []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_, err := w.Write(res)
	if err != nil {
		log.Panicln(err)
	}
}

func EncodeResponse(w http.ResponseWriter, statusCode int, res interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if err := codec.NewEncoder(w, &jsonHandle).Encode(res); err != nil {
		log.Println(err)
	}
}
