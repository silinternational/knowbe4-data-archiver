package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

const exampleSecurityTest = `{
    "campaign_id": 3423,
    "pst_id": 16142,
    "status": "Closed",
    "name": "Corporate Test",
    "groups": [
      {
        "group_id": 16342,
        "name": "Corporate Employees"
      },
      {
        "group_id": 16343,
        "name": "Volunteers"
      }
    ],
    "phish_prone_percentage": 0.5,
    "started_at": "2019-04-02T15:02:38.000Z",
    "duration": 1,
    "categories": [
      {
        "category_id": 4237,
        "name": "Current Events"
      },
      {
        "category_id": 4238,
        "name": "Other"
      }
    ],
    "template": {
      "id": 11428,
      "name": "CNN Breaking News"
    },
    "landing-page": {
      "id": 1842,
      "name": "SEI Landing Page"
    },
    "scheduled_count": 42,
    "delivered_count": 4,
    "opened_count": 24,
    "clicked_count": 20,
    "replied_count": 0,
    "attachment_open_count": 3,
    "macro_enabled_count": 0,
    "data_entered_count": 0,
    "vulnerable_plugin_count": 0,
    "exploited_count": 2,
    "reported_count": 0,
    "bounced_count": 0
  }`

const exampleFlatSecurityTest = `{
    "campaign_id": 3423,
    "pst_id": 16142,
    "status": "Closed",
    "name": "Corporate Test",
    "all_groups": "Corporate Employees,Volunteers",
    "phish_prone_percentage": 0.5,
    "started_at": "2019-04-02T15:02:38.000Z",
    "duration": 1,
    "all_categories": "Current Events,Other",
    "template_id": 11428,
    "template_name": "CNN Breaking News",
    "landing_page_id": 1842,
    "landing_page_name": "SEI Landing Page",
    "scheduled_count": 42,
    "delivered_count": 4,
    "opened_count": 24,
    "clicked_count": 20,
    "replied_count": 0,
    "attachment_open_count": 3,
    "macro_enabled_count": 0,
    "data_entered_count": 0,
    "vulnerable_plugin_count": 0,
    "exploited_count": 2,
    "reported_count": 0,
    "bounced_count": 0
  }`

const exampleRecipient = `{
    "recipient_id": 3077742,
    "pst_id": 14240,
    "user": {
      "id": 264215,
      "active_directory_guid": null,
      "first_name": "Bob",
      "last_name": "Ross",
      "email": "bob.r@kb4-demo.com"
    },
    "template": {
      "id": 2,
      "name": "Your Amazon Order"
    },
    "scheduled_at": "2019-04-02T15:02:38.000Z",
    "delivered_at": "2019-04-02T15:02:38.000Z",
    "opened_at": "2019-04-02T15:02:38.000Z",
    "clicked_at": "2019-04-02T15:02:38.000Z",
    "replied_at": "2019-04-02T15:02:38.000Z",
    "attachment_opened_at": null,
    "macro_enabled_at": null,
    "data_entered_at": "2019-04-02T15:02:38.000Z",
    "vulnerable-plugins_at": null,
    "exploited_at": null,
    "reported_at": null,
    "bounced_at": null,
    "ip": "XX.XX.XXX.XXX",
    "ip_location": "St.Petersburg, FL",
    "browser": "Chrome",
    "browser_version": "48.0",
    "os": "MacOSX"
  }`

const exampleFlatRecipient = `{
    "recipient_id": 3077742,
    "pst_id": 14240,
    "user_id": 264215,
    "user_active_directory_guid": null,
    "user_first_name": "Bob",
    "user_last_name": "Ross",
    "user_email": "bob.r@kb4-demo.com",
    "template_id": 2,
    "template_name": "Your Amazon Order",
    "scheduled_at": "2019-04-02T15:02:38.000Z",
    "delivered_at": "2019-04-02T15:02:38.000Z",
    "opened_at": "2019-04-02T15:02:38.000Z",
    "clicked_at": "2019-04-02T15:02:38.000Z",
    "replied_at": "2019-04-02T15:02:38.000Z",
    "attachment_opened_at": null,
    "macro_enabled_at": null,
    "data_entered_at": "2019-04-02T15:02:38.000Z",
    "vulnerable-plugins_at": null,
    "exploited_at": null,
    "reported_at": null,
    "bounced_at": null,
    "ip": "XX.XX.XXX.XXX",
    "ip_location": "St.Petersburg, FL",
    "browser": "Chrome",
    "browser_version": "48.0",
    "os": "MacOSX"
  }`

func TestGetAllSecurityTests(t *testing.T) {
	assert := require.New(t)
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)

	handler := func(w http.ResponseWriter, req *http.Request) {
		jsonBytes, err := json.Marshal("[" + exampleSecurityTest + "]")
		if err != nil {
			t.Errorf("Unable to marshal fixture results, error: %s", err.Error())
			t.FailNow()
		}

		w.WriteHeader(200)
		w.Header().Set("content-type", "application/json")

		s, _ := strconv.Unquote(string(jsonBytes))
		_, _ = fmt.Fprintf(w, s)
	}

	mux.HandleFunc("/"+securityTestURLPath, handler)

	var want []KnowBe4FlatSecurityTest

	exBytes := []byte(("[" + exampleFlatSecurityTest + "]"))
	err := json.Unmarshal(exBytes, &want)
	assert.NoError(err, "error unmarshalling fixtures")

	gotData, got, err := getAllSecurityTests(LambdaConfig{APIBaseURL: server.URL})
	assert.NoError(err)

	assert.Equal(want, got, "bad struct results")
	assert.Contains(string(gotData), "campaign_id", "bad json results")
}

func TestGetAllRecipientsForSecurityTest(t *testing.T) {
	assert := require.New(t)
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)

	handler := func(w http.ResponseWriter, req *http.Request) {
		jsonBytes, err := json.Marshal("[" + exampleRecipient + "]")
		if err != nil {
			t.Errorf("Unable to marshal fixture results, error: %s", err.Error())
			t.FailNow()
		}

		w.WriteHeader(200)
		w.Header().Set("content-type", "application/json")

		s, _ := strconv.Unquote(string(jsonBytes))
		_, _ = fmt.Fprintf(w, s)
	}

	secTestID := 111
	url := fmt.Sprintf(recipientsURLPath, secTestID)
	mux.HandleFunc("/"+url, handler)

	var want []KnowBe4FlatRecipient

	exBytes := []byte(("[" + exampleFlatRecipient + "]"))
	err := json.Unmarshal(exBytes, &want)
	assert.NoError(err, "error unmarshalling fixtures")

	gotData, got, err := getAllRecipientsForSecurityTest(secTestID, LambdaConfig{APIBaseURL: server.URL})
	assert.NoError(err)

	assert.Equal(want, got, "bad struct results")
	assert.Contains(string(gotData), "recipient_id", "bad json results")
}
