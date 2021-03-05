package main

import (
	"fmt";
	rp "ct-relying-party/relyingparty"
	"os"
)

func main() {
	//create a relying party, with a given set of logs, and monitors, and a config file
	relyingparty, err := rp.NewRelyingParty("relyingparty/log_list.json", "relyingparty/monitor_list.json", "relyingparty/relyingpartyconfig.json")
	if(err != nil) {  //report error if there is one
		fmt.Printf("problem creating relying party %v\n", err);
		os.Exit(-1); //quit the program if there is an error
	}

	//run the relying party, to query a given log, veryfy the results and if theyre valid, audit them using a given monitor
	err = relyingparty.QueryVerifyAndAudit(relyingparty.GetRandomLoggerID(), relyingparty.GetRandomMonitorID())
	if(err != nil) { //report error if there is one
		fmt.Printf("problem querying logger %v\n", err);
		os.Exit(-1); //quit the program if there is an error
	}
}
