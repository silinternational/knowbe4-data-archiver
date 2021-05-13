package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"sync"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
)

const (
	countPerPage     = 500
	maxErrorsAllowed = 5
)

const (
	// https://developer.knowbe4.com/reporting/#tag/Phishing/paths/~1v1~1phishing~1campaigns/get
	campaignsURLPath = "v1/phishing/campaigns"

	// https://developer.knowbe4.com/reporting/#tag/Groups/paths/~1v1~1groups/get
	groupsURLPath = "v1/groups"

	// https://developer.knowbe4.com/reporting/#tag/Phishing/paths/~1v1~1phishing~1security_tests~1{pst_id}~1recipients/get
	recipientsURLPath = "v1/phishing/security_tests/%v/recipients"

	// https://developer.knowbe4.com/reporting/#tag/Phishing/paths/~1v1~1phishing~1security_tests/get
	securityTestURLPath = "v1/phishing/security_tests"
)

const (
	campaignsFilename          = "campaigns/knowbe4_campaigns.jsonl"
	groupsFilename             = "groups/knowbe4_groups.jsonl"
	phishingTestsFilename      = "campaigns/pst/knowbe4_security_tests.jsonl"
	riskScoreHistoryFilename   = "groups_history/risk_score_history.jsonl"
	s3RecipientsFilenamePrefix = "recipients/knowbe4_recipients_"
)

const (
	EnvAPIBaseURL   = "API_BASE_URL"
	EnvAPIAuthToken = "API_AUTH_TOKEN"
	EnvAWSS3Bucket  = "AWS_S3_BUCKET"
)

type LambdaConfig struct {
	APIBaseURL    string `json:"APIBaseURL"`
	APIAuthToken  string `json:"APIAuthToken"`
	AWSS3Bucket   string `json:"AWSS3Bucket"`
	AWSS3Filename string `json:"AWSS3FileName"`
	MaxFileCount  int    `json:"MaxFileCount"`
}

func (c *LambdaConfig) init() error {
	if err := getRequiredString(EnvAPIBaseURL, &c.APIBaseURL); err != nil {
		return err
	}
	if err := getRequiredString(EnvAPIAuthToken, &c.APIAuthToken); err != nil {
		return err
	}
	if err := getRequiredString(EnvAWSS3Bucket, &c.AWSS3Bucket); err != nil {
		return err
	}

	return nil
}

func getRequiredString(envKey string, configEntry *string) error {
	if *configEntry != "" {
		return nil
	}

	value := os.Getenv(envKey)
	if value == "" {
		return fmt.Errorf("required value missing for environment variable %s", envKey)
	}
	*configEntry = value

	return nil
}

func callAPI(urlPath string, config LambdaConfig, queryParams map[string]string) (*http.Response, error) {
	var err error
	var req *http.Request

	url := config.APIBaseURL + "/" + urlPath

	req, err = http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("error preparing http request: %s", err)
	}

	req.Header.Set("Authorization", "Bearer "+config.APIAuthToken)
	req.Header.Set("Accept", "application/json")

	// Add query parameters
	q := req.URL.Query()
	for key, val := range queryParams {
		q.Add(key, val)
	}
	req.URL.RawQuery = q.Encode()

	client := &http.Client{}

	resp, err := client.Do(req)

	if err != nil {
		return nil, fmt.Errorf("error making http request: %s", err)
	} else if resp.StatusCode >= 300 {
		err := fmt.Errorf("API returned an error. URL: %s, Code: %v, Status: %s Body: %s",
			url, resp.StatusCode, resp.Status, resp.Body)
		return nil, err
	}

	return resp, nil
}

func getSecurityTestsPage(pageNum int, config LambdaConfig) ([]byte, []KnowBe4SecurityTest, error) {
	queryParams := map[string]string{
		"per_page": strconv.Itoa(countPerPage),
		"page":     strconv.Itoa(pageNum),
	}

	// Make http call
	resp, err := callAPI(securityTestURLPath, config, queryParams)
	if err != nil {
		return nil, nil, err
	}

	defer resp.Body.Close()
	bodyBytes, _ := ioutil.ReadAll(resp.Body)

	var pageTests []KnowBe4SecurityTest

	if err := json.Unmarshal(bodyBytes, &pageTests); err != nil {
		return nil, nil, fmt.Errorf("error decoding response json for security tests: %s", err)
	}

	return bodyBytes, pageTests, nil
}

func getAllSecurityTests(config LambdaConfig) ([]byte, []KnowBe4SecurityTest, error) {
	var allData []byte
	var allTests []KnowBe4SecurityTest

	for i := 1; ; i++ {
		data, nextTests, err := getSecurityTestsPage(i, config)
		if err != nil {
			err = fmt.Errorf("error fetching page %v ... %s", i, err)
			return nil, nil, err
		}

		allData = append(allData, data...)
		allTests = append(allTests, nextTests...)

		if len(nextTests) < countPerPage {
			break
		}
	}

	return allData, allTests, nil
}

func getRecipientsPage(pstID, pageNum int, config LambdaConfig) ([]byte, []KnowBe4Recipient, error) {
	queryParams := map[string]string{
		"per_page": strconv.Itoa(countPerPage),
		"page":     strconv.Itoa(pageNum),
	}

	url := fmt.Sprintf(recipientsURLPath, pstID)

	// Make http call
	resp, err := callAPI(url, config, queryParams)
	if err != nil {
		return nil, nil, err
	}

	defer resp.Body.Close()
	bodyBytes, _ := ioutil.ReadAll(resp.Body)

	var pageRecipients []KnowBe4Recipient

	if err := json.Unmarshal(bodyBytes, &pageRecipients); err != nil {
		return nil, nil, fmt.Errorf("error decoding response json for recipients for security test %v: %s", pstID, err)
	}

	return bodyBytes, pageRecipients, nil
}

func getAllRecipientsForSecurityTest(secTestID int, config LambdaConfig) ([]byte, []KnowBe4Recipient, error) {
	var allData []byte
	var allRecipients []KnowBe4Recipient

	for i := 1; ; i++ {
		data, nextRecipient, err := getRecipientsPage(secTestID, i, config)
		if err != nil {
			err = fmt.Errorf("error fetching recipients for security test %v page %v ... %s",
				secTestID, i, err)
			return nil, nil, err
		}

		allData = append(allData, data...)
		allRecipients = append(allRecipients, nextRecipient...)

		if len(nextRecipient) < countPerPage {
			break
		}
	}

	return allData, allRecipients, nil
}

func getCampaignsPage(pageNum int, config LambdaConfig) ([]KnowBe4Campaign, error) {
	queryParams := map[string]string{
		"per_page": strconv.Itoa(countPerPage),
		"page":     strconv.Itoa(pageNum),
	}

	// Make http call
	resp, err := callAPI(campaignsURLPath, config, queryParams)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	bodyBytes, _ := ioutil.ReadAll(resp.Body)

	var campaigns []KnowBe4Campaign

	if err := json.Unmarshal(bodyBytes, &campaigns); err != nil {
		return nil, fmt.Errorf("error decoding response json for campaigns: %s", err)
	}

	return campaigns, nil
}

func getAllCampaigns(config LambdaConfig) ([]KnowBe4Campaign, error) {
	var allCampaigns []KnowBe4Campaign

	for i := 1; ; i++ {
		c, err := getCampaignsPage(i, config)
		if err != nil {
			err = fmt.Errorf("error fetching page %v ... %s", i, err)
			return nil, err
		}

		allCampaigns = append(allCampaigns, c...)

		if len(c) < countPerPage {
			break
		}
	}

	return allCampaigns, nil
}

func getGroupsPage(pageNum int, config LambdaConfig) ([]KnowBe4Group, error) {
	queryParams := map[string]string{
		"per_page": strconv.Itoa(countPerPage),
		"page":     strconv.Itoa(pageNum),
	}

	// Make http call
	resp, err := callAPI(groupsURLPath, config, queryParams)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	bodyBytes, _ := ioutil.ReadAll(resp.Body)

	var groups []KnowBe4Group

	if err := json.Unmarshal(bodyBytes, &groups); err != nil {
		return nil, fmt.Errorf("error decoding response json for groups: %s", err)
	}

	return groups, nil
}

func getAllGroups(config LambdaConfig) ([]KnowBe4Group, error) {
	var allGroups []KnowBe4Group

	for i := 1; ; i++ {
		c, err := getGroupsPage(i, config)
		if err != nil {
			err = fmt.Errorf("error fetching page %v ... %s", i, err)
			return nil, err
		}

		allGroups = append(allGroups, c...)

		if len(c) < countPerPage {
			break
		}
	}

	return allGroups, nil
}

func saveRecipientsForSecTest(secTestID int, config LambdaConfig, wg *sync.WaitGroup, c chan error) {
	defer wg.Done()

	_, recipients, err := getAllRecipientsForSecurityTest(secTestID, config)
	if err != nil {
		err = fmt.Errorf("error gettings reciptients from api for security test %v ... %s", secTestID, err)
		c <- err
		return
	}

	filename := fmt.Sprintf("%s%v.jsonl", s3RecipientsFilenamePrefix, secTestID)

	list := make([]interface{}, len(recipients))
	for i := range recipients {
		list[i] = recipients[i]
	}
	if err := saveToS3(list, config.AWSS3Bucket, filename); err != nil {
		err = fmt.Errorf("error saving recipients to S3 for security test %v ... %s", secTestID, err)
		c <- err
		return
	}

	c <- nil
	return
}

func saveRecipientsToS3Async(config LambdaConfig, secTests []KnowBe4SecurityTest) error {
	c := make(chan error) // Declare a unbuffered channel
	var lastErr error

	errCount := 0
	stIndex := -1
	stCount := len(secTests)
	workingGroupCount := 5

	allDone := false

	for {
		var wg sync.WaitGroup

		for i := 0; i < workingGroupCount; i++ {
			stIndex += 1
			if stIndex >= stCount {
				allDone = true
				break
			}
			nextID := secTests[stIndex].PstID
			wg.Add(1)
			go saveRecipientsForSecTest(nextID, config, &wg, c)

			newErr := <-c
			if newErr != nil {
				log.Print(newErr.Error())
				errCount += 1
			}
		}

		wg.Wait()

		if errCount >= maxErrorsAllowed {
			lastErr = fmt.Errorf("aborting due to getting too many (%v) errors", errCount)
		}

		if allDone {
			break
		}
	}

	close(c)

	log.Printf("saved %d test recipient files to S3 with %d errors", stCount-errCount, errCount)

	return lastErr
}

func saveToS3(data interface{}, bucketName, fileName string) error {
	b, err := marshalJsonLines(data)
	if err != nil {
		return errors.New("error marshalling data for saving to S3 ..." + err.Error())
	}

	uploader := s3manager.NewUploader(session.Must(session.NewSession()))
	_, err = uploader.Upload(&s3manager.UploadInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(fileName),
		Body:   bytes.NewReader(b),
	})
	if err != nil {
		return fmt.Errorf("error saving data to %s/%s ... %s", bucketName, fileName, err)
	}

	return nil
}

func handler(config LambdaConfig) error {
	if err := config.init(); err != nil {
		return err
	}

	if err := getAndSaveCampaigns(config); err != nil {
		return errors.New("error saving campaigns ... " + err.Error())
	}

	if err := getAndSaveGroups(config); err != nil {
		return errors.New("error saving groups ... " + err.Error())
	}

	_, stResults, err := getAllSecurityTests(config)
	if err != nil {
		return errors.New("error getting security tests from api ..." + err.Error())
	}

	if err := saveTestsToS3(config, stResults); err != nil {
		return err
	}

	count := config.MaxFileCount
	if count == 0 {
		count = len(stResults)
	}
	return saveRecipientsToS3Async(config, stResults[:count])
}

func saveTestsToS3(config LambdaConfig, stResults []KnowBe4SecurityTest) error {
	list := make([]interface{}, len(stResults))
	for i := range stResults {
		list[i] = stResults[i]
	}
	if err := saveToS3(list, config.AWSS3Bucket, phishingTestsFilename); err != nil {
		return errors.New("error saving security test results to S3 ..." + err.Error())
	}

	log.Printf("saved %d security tests to S3", len(stResults))
	return nil
}

func getAndSaveCampaigns(config LambdaConfig) error {
	campaigns, err := getAllCampaigns(config)
	if err != nil {
		return errors.New("error getting campaigns from KnowBe4 ..." + err.Error())
	}
	list := make([]interface{}, len(campaigns))
	for i := range campaigns {
		list[i] = campaigns[i]
	}
	if err := saveToS3(list, config.AWSS3Bucket, campaignsFilename); err != nil {
		return errors.New("error saving campaigns to S3 ..." + err.Error())
	}
	log.Printf("saved %d campaigns to S3", len(campaigns))
	return nil
}

func getAndSaveGroups(config LambdaConfig) error {
	groups, err := getAllGroups(config)
	if err != nil {
		return errors.New("error getting groups from KnowBe4 ..." + err.Error())
	}

	list := make([]interface{}, len(groups))
	for i := range groups {
		list[i] = groups[i]
	}
	if err := saveToS3(list, config.AWSS3Bucket, groupsFilename); err != nil {
		return errors.New("error saving groups to S3 ..." + err.Error())
	}

	log.Printf("saved %d groups to S3", len(groups))
	return nil
}

func manualRun() {
	var config LambdaConfig
	if err := config.init(); err != nil {
		panic("error initializing config ... " + err.Error())
	}

	config.MaxFileCount = 2

	if err := handler(config); err != nil {
		panic("error calling handler ... " + err.Error())
	}

	log.Printf("Success saving to s3\n")
}

func main() {
	lambda.Start(handler)
	// manualRun()
}

// marshalJsonLines is a partial implementation of JSON Lines
// It only supports lists of objects. It will not generate the simplified case with no nested objects
// as shown in the first example on https://jsonlines.org
func marshalJsonLines(input interface{}) ([]byte, error) {
	if input == nil {
		return nil, fmt.Errorf("marshalJsonLines nil input")
	}
	list, ok := input.([]interface{})
	if !ok {
		return nil, fmt.Errorf("marshalJsonLines input is not []interface{}")
	}
	buf := new(bytes.Buffer)
	for _, row := range list {
		b, err := json.Marshal(row)
		if err != nil {
			return nil, err
		}
		buf.Write(append(b, '\n'))
	}
	return buf.Bytes(), nil
}
