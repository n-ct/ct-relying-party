package testing

import (
	rp "ct-relying-party/relyingparty"
	"testing"
)

var ( //replace with absolute paths on your machine
	log_list_filename string = "ct-relying-party/relyingparty/log_list.json";
	monitor_list_filename string = "ct-relying-party/relyingparty/monitor_list.json";
	relyingparty_config_filename string = "ct-relying-party/relyingparty/relyingpartyconfig.json";
	testLoggerID string = "sh4FzIuizYogTodm+Su5iiUgZ2va+nDnsklTLe+LkF4=";
	testMonitorID string = "monitor1";
)

//function that returns a new relying party type, or an error if creation fails
func mustCreateRelyingParty(t *testing.T) (*rp.RelyingParty, error){
	t.Helper()
	relyingparty, err := rp.NewRelyingParty(log_list_filename, monitor_list_filename, relyingparty_config_filename)
	return relyingparty, err
}

//function to test creating a new relying party
func TestNewRelyingParty(t *testing.T) {
	_, err := mustCreateRelyingParty(t)
	if err != nil {
		t.Fatalf("failed to create RelyingParty with loglist @ (%s), monitor list @ (%s), and config @ (%s): %v",log_list_filename, monitor_list_filename, relyingparty_config_filename, err)
	}
}
//function to test the 3 major functionalities of the relying party
func TestQueryVerifyAndAudit(t *testing.T) {
	relyingparty, _ := mustCreateRelyingParty(t)
	_, err := relyingparty.QueryVerifyAndAudit(testLoggerID, testMonitorID)
    if err != nil {
       t.Fatalf("Query verify and audit failed: %v",err)
    }
}
