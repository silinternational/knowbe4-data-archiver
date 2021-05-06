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

func Test_getAllSecurityTests(t *testing.T) {
	assert := require.New(t)

	testURL := getTestServer("/"+securityTestURLPath, "["+exampleSecurityTest+"]")

	var want []KnowBe4FlatSecurityTest

	exBytes := []byte(("[" + exampleFlatSecurityTest + "]"))
	err := json.Unmarshal(exBytes, &want)
	assert.NoError(err, "error unmarshalling fixtures")

	gotData, got, err := getAllSecurityTests(LambdaConfig{APIBaseURL: testURL})
	assert.NoError(err)

	assert.Equal(want, got, "bad struct results")
	assert.Contains(string(gotData), "campaign_id", "bad json results")
}

func Test_getAllRecipientsForSecurityTest(t *testing.T) {
	assert := require.New(t)

	const secTestID = 111
	path := "/" + fmt.Sprintf(recipientsURLPath, secTestID)
	testURL := getTestServer(path, "["+exampleRecipient+"]")

	var want []KnowBe4FlatRecipient

	exBytes := []byte(("[" + exampleFlatRecipient + "]"))
	err := json.Unmarshal(exBytes, &want)
	assert.NoError(err, "error unmarshalling fixtures")

	gotData, got, err := getAllRecipientsForSecurityTest(secTestID, LambdaConfig{APIBaseURL: testURL})
	assert.NoError(err)

	assert.Equal(want, got, "bad struct results")
	assert.Contains(string(gotData), "recipient_id", "bad json results")
}

func Test_getAllCampaigns(t *testing.T) {
	assert := require.New(t)

	testURL := getTestServer("/"+campaignsURLPath, exampleCampaigns)

	var want []KnowBe4FlatCampaign

	exBytes := []byte((exampleFlatCampaigns))
	err := json.Unmarshal(exBytes, &want)
	assert.NoError(err, "error unmarshalling fixtures")

	got, err := getAllCampaigns(LambdaConfig{APIBaseURL: testURL})
	assert.NoError(err)

	assert.Equal(want, got, "bad struct results")
}

func Test_getAllGroups(t *testing.T) {
	assert := require.New(t)

	testURL := getTestServer("/"+groupsURLPath, exampleGroups)

	var want []KnowBe4Group
	err := json.Unmarshal([]byte(exampleGroups), &want)
	assert.NoError(err, "error unmarshalling fixtures")

	got, err := getAllGroups(LambdaConfig{APIBaseURL: testURL})
	assert.NoError(err)

	assert.Equal(want, got, "bad struct results")
}

func Test_flattenGroups(t *testing.T) {
	assert := require.New(t)

	var fixture []KnowBe4Group
	err := json.Unmarshal([]byte(exampleGroups), &fixture)
	assert.NoError(err, "error unmarshalling groups")

	var want []KnowBe4FlatGroup
	err = json.Unmarshal([]byte(exampleFlatGroups), &want)
	assert.NoError(err, "error unmarshalling flat groups")

	got, err := flattenGroups(fixture)
	assert.NoError(err, "unexpected error from flattenGroups")
	assert.Equal(want, got, "bad struct results")
}

func getTestHandler(responseBody string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		jsonBytes, err := json.Marshal(responseBody)
		if err != nil {
			panic("Unable to marshal fixture results, error:" + err.Error())
		}

		w.WriteHeader(200)
		w.Header().Set("content-type", "application/json")

		s, _ := strconv.Unquote(string(jsonBytes))
		_, _ = fmt.Fprintf(w, s)
	}
}

func getTestServer(path, response string) string {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)

	handler := getTestHandler(response)

	mux.HandleFunc(path, handler)

	return server.URL
}
