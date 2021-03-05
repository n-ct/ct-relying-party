package relyingparty

import (
	"fmt"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"math/rand"
	"time"
	"io/ioutil"
	mtr "github.com/n-ct/ct-monitor"
	"github.com/n-ct/ct-monitor/utils"
	"github.com/n-ct/ct-monitor/entitylist"
	"github.com/n-ct/ct-monitor/signature"
	"github.com/google/trillian/merkle/logverifier"
	"github.com/google/trillian/merkle/rfc6962/hasher"
	"github.com/google/certificate-transparency-go/tls"
	ct "github.com/google/certificate-transparency-go"
)

//type to hold data and functionality of a Relying Party
type RelyingParty struct {
	LogList			*entitylist.LogList //list to hold all loggers this RP can query
	LogIDs			[]string //list of all the IDs to the loggers this RP can query
	MonitorList		*entitylist.MonitorList //list to hold all monitors this RP can query
	MonitorIDs		[]string //list of all the IDs to the monitors this RP can query
	//CTObjectMap 	map[string]map[string]map[uint64]map[string] *mtr.CTObject //map to store AuditOKs and possibly PoM (to be implemented later (possibly))
}

//type to hold config information about a Relying Party
type RelyingPartyConfig struct {
	LogIDs			[]string	`json:"logIDs"`
	MonitorIDs		[]string	`json:"monitorIDs"`
}

//parses a given file as json, constructs a RelyingPartyConfig type and retursn it
func parseRelyingPartyConfig(fileName string) (*RelyingPartyConfig, error){
	byteData, err := utils.FiletoBytes(fileName)
	if err != nil {
		return nil, fmt.Errorf("error parsing relying party config: %w", err)
	}
	var config RelyingPartyConfig
	err = json.Unmarshal(byteData, &config)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal relying party config: %w", err)
	}
	return &config, nil
}

//creates and returns a new Relying party type
func NewRelyingParty(logListName string, monitorListName string, configFileName string) (*RelyingParty, error){
	logList, err := entitylist.NewLogList(logListName)
	if err != nil {
		return nil, fmt.Errorf("failed to create loglist for relying party: %w", err)
	}
	monitorList, err := entitylist.NewMonitorList(monitorListName)
	if err != nil {
		return nil, fmt.Errorf("failed to create monitorlist for relying party: %w", err)
	}

	config, err := parseRelyingPartyConfig(configFileName)
	if err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}
	//ctObjectMap := make(map[string]map[string]map[uint64]map[string] *mtr.CTObject)

	rp := &RelyingParty{logList, config.LogIDs, monitorList, config.MonitorIDs}
	return rp, nil
}

//function that takes in a montorID and a loggerID, then
//	1. Querrys the logger with that ID for an STH, a cert and the PoI for that cert
//	2. Veryfiers both that the signature on the STH is valid, and that the PoI is valid
//	3. Sends the sth to the monitor with that ID, to audit it
func (rp *RelyingParty) QueryVerifyAndAudit(logID string, monID string) (error){
	//Query
	log := rp.LogList.FindLogByLogID(logID) //get logger from list of all loggers
	if log == nil { // if logger is not found return an error
		return fmt.Errorf("logger with id '%v' not found", logID)
	}
	logClient, err := mtr.NewLogClient(log) // create a logClient from the logger
	if err != nil { //report error if there is one
		return fmt.Errorf("failed to create logClient: %v", err)
	}
	ctx := context.Background()
	sth, err := logClient.GetSTH(ctx) //get the STH from the logger
	if err != nil { //report error if there is one
		return fmt.Errorf("failed to get STH from logger: %v", err)
	}

	//Verify STH
	blob, err := sth.DeconstructSTH() //convert STH as a CTObject struct to a SignedTreeHeadData struct
	if err != nil { //report error if there is one
		return fmt.Errorf("Error deconstructing STH\n")
	}

	err = signature.VerifySignature(log.Key, blob.TreeHeadData, blob.Signature) //verify the signature over the STH, using the loggers public key
	if err != nil { //report error if there is one
		return fmt.Errorf("Signature Invalid\n")
	}

	//Verify PoI

	rand.Seed(time.Now().Unix())
	randIndex := rand.Intn(len(rp.LogIDs)-1)+1 //choose a random index, to get a random cert from the logger
	poi, leafInput, err := logClient.GetEntryAndProof(ctx, uint64(randIndex), blob.TreeHeadData.TreeSize) //get the cert and the PoI from the logger
	if err != nil { //report error if there is one
		return fmt.Errorf("Error getting PoI and Cert %v\n", err)
	}

	verifier := logverifier.New(hasher.DefaultHasher) //struct for verifying proofs

	ret := ct.RawLogEntry{Index: 3}
	tls.Unmarshal(leafInput, &ret.Leaf)
	leafHash, err := ct.LeafHashForLeaf(&ret.Leaf) //setup the cert for the logverifier
	if err != nil { //report error if there is one
		return fmt.Errorf("Error calculating leaf hash %v\n", err)
	}

	//verify that the PoI proves the cert is in the STH
	//VerifyInclusionProof returns nil, if PoI is valid
	err = verifier.VerifyInclusionProof(int64(randIndex), int64(blob.TreeHeadData.TreeSize), poi.InclusionPath, blob.TreeHeadData.SHA256RootHash[:], leafHash[:])
	if err != nil { //report error if there is one
		return fmt.Errorf("Error verifying PoI for Cert %v\n", err)
	}

	//print info for debug
	fmt.Printf("poi: %v\nleafInput: %v\n", poi, leafInput)

	//Audit
	monitor := rp.MonitorList.FindMonitorByMonitorID(monID) //get the monitor from the monitorID

	//print info for debug
	fmt.Printf("http://%v%v\n", monitor.MonitorURL, mtr.AuditPath)

	//send the STH to the monitor
	//only for debugging
	newinfo(fmt.Sprintf("http://%v%v", monitor.MonitorURL, mtr.NewInfoPath), sth)

	//uncomment the next line to test gettign a PoM from the monitor if the digest is wrong
	//sth.Digest = []byte{0,1,2,3};

	auditOK, err := audit(fmt.Sprintf("http://%v%v", monitor.MonitorURL, mtr.AuditPath), sth) //send STH to monitor to be audited and capture the response

	if err != nil { //report error if there is one
		return fmt.Errorf("error auditing monitor %v", err)
	}

	//print info for debug
	fmt.Printf("auditOK: %v\n",auditOK)

	return nil //if no error have been thrown, everythin went well, return no errors
}

// function to send an STH to a monitor to be audited, and returs the output as an AuditOK struct
func audit(address string, toSend *mtr.CTObject) (*mtr.AuditOK, error){
	var jsonStr, _ = json.Marshal(toSend); //create JSON string for the CTObject

	req, err := http.NewRequest("POST", address, bytes.NewBuffer(jsonStr)); //create a post request
	req.Header.Set("Content-Type", "application/json"); //set message type to JSON

	client := &http.Client{};
	resp, err := client.Do(req); //make the request
	if err != nil {
		return nil, fmt.Errorf("error making post request %v", err);
	}

	defer resp.Body.Close();

	//print info for debug
	fmt.Println("response Status:", resp.Status);
	fmt.Println("response Headers:", resp.Header);
	body, _ := ioutil.ReadAll(resp.Body);
	sbody := string(body);
	fmt.Println("response Body:", sbody);

	var auditOK mtr.AuditOK
	err = json.Unmarshal(body, &auditOK)
	if err != nil { //report error if there is one
		return nil, fmt.Errorf("error reading response from post request %v", err);
	}
	return &auditOK, nil
}

// only for debbuging
// sends STH to monitor to make sure monitor has seen the STH from the logger
func newinfo(address string, toSend *mtr.CTObject){
	var jsonStr, _ = json.Marshal(toSend);

	req, err := http.NewRequest("POST", address, bytes.NewBuffer(jsonStr)); //create a post request
	req.Header.Set("Content-Type", "application/json"); //set message type to JSON

	client := &http.Client{};
	resp, err := client.Do(req); //make the request
	if err != nil {
		panic(err);
	}

	defer resp.Body.Close();

	//print info for debug
	fmt.Println("response Status:", resp.Status);
	fmt.Println("response Headers:", resp.Header);
	body, _ := ioutil.ReadAll(resp.Body);
	sbody := string(body);
	fmt.Println("response Body:", sbody);
}

// helper function to get a random LoggerID
func (rp *RelyingParty) GetRandomLoggerID() (string){
	rand.Seed(time.Now().Unix())
	return rp.LogIDs[rand.Intn(len(rp.LogIDs))]
}

// helper function to get a random MonitorID
func (rp *RelyingParty) GetRandomMonitorID() (string){
	rand.Seed(time.Now().Unix())
	return rp.MonitorIDs[rand.Intn(len(rp.MonitorIDs))]
}
