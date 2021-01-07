package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

const exampleResult = `{
    "campaign_id": 3423,
    "pst_id": 16142,
    "status": "Closed",
    "name": "Corporate Test",
    "groups": [
      {
        "group_id": 16342,
        "name": "Corporate Employees"
      }
    ],
    "phish_prone_percentage": 0.5,
    "started_at": "2019-04-02T15:02:38.000Z",
    "duration": 1,
    "categories": [
      {
        "category_id": 4237,
        "name": "Current Events"
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

func TestStub(t *testing.T) {
	assert := require.New(t)
	var kb4Result KnowBe4SecurityTest
	exBytes := []byte(exampleResult)
	err := json.Unmarshal(exBytes, &kb4Result)
	assert.NoError(err, "error unmarshalling results")

	want := "abc"
	got := "abc"
	assert.Equal(want, got, "bad results")
}


func TestGetReport(t *testing.T) {
	assert := require.New(t)
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)

	resultsString := "[" + exampleResult + "]"

	handler := func(w http.ResponseWriter, req *http.Request) {
		jsonBytes, err := json.Marshal(resultsString)
		if err != nil {
			t.Errorf("Unable to marshal fixture results, error: %s", err.Error())
			t.FailNow()
		}

		w.WriteHeader(200)
		w.Header().Set("content-type", "application/json")
		_, _ = fmt.Fprintf(w, string(jsonBytes))
	}

	mux.HandleFunc("/" + securityTestURLPath, handler)

	var want []KnowBe4SecurityTest

	exBytes := []byte(resultsString)
	err := json.Unmarshal(exBytes, &want)
	assert.NoError(err, "error unmarshalling fixtures")

	gotData, got, err := getReport(LambdaConfig{APIBaseURL: server.URL})
	assert.NoError(err)

	assert.Equal(want, got, "bad struct results")
	assert.Contains(string(gotData), "campaign_id", "bad json results")
}