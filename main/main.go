package main

import (
	"os"
	"flag"
	rp "ct-relying-party/relyingparty"
	"github.com/golang/glog"
	"fmt"
)

var ( //replace with absolute paths on your machine
	log_list_filename string = "ct-relying-party/relyingparty/log_list.json";
	monitor_list_filename string = "ct-relying-party/relyingparty/monitor_list.json";
	relyingparty_config_filename string = "ct-relying-party/relyingparty/relyingpartyconfig.json";
)

func main() {
	flag.Parse() //parse flags for glog
	defer glog.Flush()
	//create a relying party, with a given set of logs, and monitors, and a config file
	relyingparty, err := rp.NewRelyingParty(log_list_filename, monitor_list_filename, relyingparty_config_filename)
	if(err != nil) {  //log error if there is one
		glog.Infoln(fmt.Sprintf("problem creating relying party %v\n", err))
		glog.Flush()
		os.Exit(-1) //quit the program if there is an error
	}

	//run the relying party, to query a given log, veryfy the results and if theyre valid, audit them using a given monitor
	auditOK, err := relyingparty.QueryVerifyAndAudit(relyingparty.GetRandomLoggerID(), relyingparty.GetRandomMonitorID())
	if(err != nil) { //log error if there is one
		glog.Infoln(fmt.Sprintf("problem querying logger %v\n", err))
		glog.Flush()
		os.Exit(-1) //quit the program if there is an error
	}

	//fmt.Printf("auditOK recived: %v\n", auditOK)
	glog.Infoln(fmt.Sprintf("auditOK recived: %v\n", auditOK)) //log audit OK
	glog.Flush()
}
