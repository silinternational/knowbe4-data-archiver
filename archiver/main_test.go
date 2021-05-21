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

	var want []KnowBe4SecurityTest

	exBytes := []byte(("[" + exampleSecurityTest + "]"))
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

	var want []KnowBe4Recipient

	exBytes := []byte(("[" + exampleRecipient + "]"))
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

	var want []KnowBe4Campaign

	exBytes := []byte((exampleCampaigns))
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

func Test_getAllUsers(t *testing.T) {
	assert := require.New(t)

	testURL := getTestServer("/"+ usersURLPath, exampleUsers)

	var want []KnowBe4User
	err := json.Unmarshal([]byte(exampleUsers), &want)
	assert.NoError(err, "error unmarshalling fixtures")

	got, err := getAllUsers(LambdaConfig{APIBaseURL: testURL})
	assert.NoError(err)

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

func Test_marshalJsonLines(t *testing.T) {
	tests := []struct {
		name    string
		input   interface{}
		want    []byte
		wantErr bool
	}{
		{
			name:    "nil",
			input:   nil,
			want:    nil,
			wantErr: true,
		},
		{
			name:    "not an array",
			input:   KnowBe4Group{},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "empty array",
			input:   []interface{}{},
			want:    nil,
			wantErr: false,
		},
		{
			name:    "single int",
			input:   []interface{}{1},
			want:    []byte("1\n"),
			wantErr: false,
		},
		{
			name: "single struct",
			input: []interface{}{GroupSummary{
				GroupID: 1,
				Name:    "name",
			}},
			want:    []byte(`{"group_id":1,"name":"name"}` + "\n"),
			wantErr: false,
		},
		{
			name:    "two int items",
			input:   []interface{}{1, 2},
			want:    []byte("1\n2\n"),
			wantErr: false,
		},
		{
			name: "two struct items",
			input: []interface{}{
				GroupSummary{
					GroupID: 1,
					Name:    "name 1",
				},
				GroupSummary{
					GroupID: 2,
					Name:    "name 2",
				},
			},
			want:    []byte(`{"group_id":1,"name":"name 1"}` + "\n" + `{"group_id":2,"name":"name 2"}` + "\n"),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := marshalJsonLines(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("marshalJsonLines() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			require.Equal(t, tt.want, got)
		})
	}
}
