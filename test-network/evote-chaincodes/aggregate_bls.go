package main

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/mod"
	"go.dedis.ch/kyber/v3/sign/bls"
)

// SmartContract for e-voting
type SmartContract struct {
	contractapi.Contract
}

// BLSKeyAggregate stores the aggregated public key
type BLSKeyAggregate struct {
	AggregatedKey string `json:"aggregated_key"`
}

// Aggregate and store BLS public keys
func (s *SmartContract) AggregateAndStoreBLSKeys(ctx contractapi.TransactionContextInterface, pubKeys []string) error {
	suite := bls.NewBLS12381Suite() // Use a valid BLS suite
	var points []kyber.Point

	// Convert received hex keys to Kyber points
	for _, keyHex := range pubKeys {
		point := suite.G1().Point()
		err := point.UnmarshalBinary([]byte(keyHex))
		if err != nil {
			return fmt.Errorf("invalid public key format: %v", err)
		}
		points = append(points, point)
	}

	// Aggregate public keys using BLS (sum of all points)
	aggregatedKey := suite.G1().Point().Null()
	for _, point := range points {
		aggregatedKey = aggregatedKey.Add(aggregatedKey, point)
	}

	// Store aggregated key on ledger
	aggKeyBytes, _ := aggregatedKey.MarshalBinary()
	aggKey := BLSKeyAggregate{AggregatedKey: string(aggKeyBytes)}

	aggKeyJSON, _ := json.Marshal(aggKey)
	err := ctx.GetStub().PutState("BLS_Aggregated_Key", aggKeyJSON)
	if err != nil {
		return fmt.Errorf("failed to store aggregated key: %v", err)
	}

	return nil
}

// Retrieve the aggregated BLS key
func (s *SmartContract) GetAggregatedBLSKey(ctx contractapi.TransactionContextInterface) (string, error) {
	keyJSON, err := ctx.GetStub().GetState("BLS_Aggregated_Key")
	if err != nil || keyJSON == nil {
		return "", fmt.Errorf("aggregated key not found")
	}

	var aggKey BLSKeyAggregate
	json.Unmarshal(keyJSON, &aggKey)
	return aggKey.AggregatedKey, nil
}

func main() {
	chaincode, err := contractapi.NewChaincode(new(SmartContract))
	if err != nil {
		log.Fatalf("Error creating chaincode: %v", err)
	}

	if err := chaincode.Start(); err != nil {
		log.Fatalf("Error starting chaincode: %v", err)
	}
}
