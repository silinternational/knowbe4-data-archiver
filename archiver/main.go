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
	"strings"
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
	campaignsFilename          = "campaigns/knowbe4_campaigns.json"
	groupsFilename             = "groups/knowbe4_groups.json"
	phishingTestsFilename      = "campaigns/pst/knowbe4_security_tests.json"
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

func getAllSecurityTests(config LambdaConfig) ([]byte, []KnowBe4FlatSecurityTest, error) {
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

	flatResults, err := flattenTests(allTests)

	return allData, flatResults, err
}

func getRecipientsPage(pstID, pageNum int, config LambdaConfig) ([]byte, []KnowBe4FlatRecipient, error) {
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

	flatRecipients, err := flattenRecipients(pageRecipients)
	if err != nil {
		return nil, nil, err
	}

	return bodyBytes, flatRecipients, nil
}

func getAllRecipientsForSecurityTest(secTestID int, config LambdaConfig) ([]byte, []KnowBe4FlatRecipient, error) {
	var allData []byte
	var allRecipients []KnowBe4FlatRecipient

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

func getAllCampaigns(config LambdaConfig) ([]KnowBe4FlatCampaign, error) {
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

	flatResults, err := flattenCampaigns(allCampaigns)

	return flatResults, err
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

func getAllGroups(config LambdaConfig) ([]KnowBe4FlatGroup, error) {
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

	flatResults, err := flattenGroups(allGroups)

	return flatResults, err
}

func saveRecipientsForSecTest(secTestID int, config LambdaConfig, wg *sync.WaitGroup, c chan error) {
	defer wg.Done()

	_, recipients, err := getAllRecipientsForSecurityTest(secTestID, config)
	if err != nil {
		err = fmt.Errorf("error gettings reciptients from api for security test %v ... %s", secTestID, err)
		c <- err
		return
	}

	filename := fmt.Sprintf("%s%v.json", s3RecipientsFilenamePrefix, secTestID)

	if err := saveToS3(&recipients, config.AWSS3Bucket, filename); err != nil {
		err = fmt.Errorf("error saving recipients to S3 for security test %v ... %s", secTestID, err)
		c <- err
		return
	}

	c <- nil
	return
}

func saveRecipientsToS3Async(config LambdaConfig, secTests []KnowBe4FlatSecurityTest) error {
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
	return lastErr
}

func saveToS3(data interface{}, bucketName, fileName string) error {
	b, err := json.Marshal(data)
	if err != nil {
		return errors.New("error marshalling security tests results for saving to S3 ..." + err.Error())
	}

	sess := session.Must(session.NewSession())
	uploader := s3manager.NewUploader(sess)
	_, err = uploader.Upload(&s3manager.UploadInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(fileName),
		Body:   bytes.NewReader(b),
	})
	if err != nil {
		return fmt.Errorf("Error saving data to %s/%s ... %s", bucketName, fileName, err)
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

func saveTestsToS3(config LambdaConfig, stResults []KnowBe4FlatSecurityTest) error {
	if err := saveToS3(&stResults, config.AWSS3Bucket, phishingTestsFilename); err != nil {
		return errors.New("error saving security test results to S3 ..." + err.Error())
	}

	log.Printf("Success saving %v security tests to S3.", len(stResults))
	return nil
}

func getAndSaveCampaigns(config LambdaConfig) error {
	campaigns, err := getAllCampaigns(config)
	if err != nil {
		return errors.New("error getting campaigns from KnowBe4 ..." + err.Error())
	}
	if err := saveToS3(&campaigns, config.AWSS3Bucket, campaignsFilename); err != nil {
		return errors.New("error saving campaigns to S3 ..." + err.Error())
	}
	return nil
}

func getAndSaveGroups(config LambdaConfig) error {
	groups, err := getAllGroups(config)
	if err != nil {
		return errors.New("error getting groups from KnowBe4 ..." + err.Error())
	}
	if err := saveToS3(&groups, config.AWSS3Bucket, groupsFilename); err != nil {
		return errors.New("error saving groups to S3 ..." + err.Error())
	}
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

	fmt.Printf("Success saving to s3\n")
}

func main() {
	lambda.Start(handler)
	// manualRun()
}

func flattenTests(tests []KnowBe4SecurityTest) ([]KnowBe4FlatSecurityTest, error) {
	flatTests := make([]KnowBe4FlatSecurityTest, len(tests))
	for i, t := range tests {
		flatTest, err := flattenTest(t)
		if err != nil {
			return flatTests, err
		}
		flatTests[i] = flatTest
	}
	return flatTests, nil
}

func flattenTest(test KnowBe4SecurityTest) (KnowBe4FlatSecurityTest, error) {
	var flatTest KnowBe4FlatSecurityTest
	if err := ConvertToOtherType(test, &flatTest); err != nil {
		return flatTest, err
	}

	flatTest.Groups = flattenGroupSummaries(test.Groups)
	flatTest.Categories = flattenCategories(test.Categories)
	flatTest.TemplateID = test.Template.ID
	flatTest.TemplateName = test.Template.Name
	flatTest.LandingPageID = test.LandingPage.ID
	flatTest.LandingPageName = test.LandingPage.Name

	return flatTest, nil
}

func flattenGroupSummaries(groups []GroupSummary) string {
	groupNames := make([]string, len(groups))
	for i := range groups {
		groupNames[i] = groups[i].Name
	}
	return strings.Join(groupNames, ",")
}

func flattenCategories(categories []struct {
	CategoryID int    `json:"category_id"`
	Name       string `json:"name"`
}) string {
	categoryNames := make([]string, len(categories))
	for i := range categories {
		categoryNames[i] = categories[i].Name
	}
	return strings.Join(categoryNames, ",")
}

func flattenRecipients(recipients []KnowBe4Recipient) ([]KnowBe4FlatRecipient, error) {
	flatRecipients := make([]KnowBe4FlatRecipient, len(recipients))
	for i, recipient := range recipients {
		flatRecipient, err := flattenRecipient(recipient)
		if err != nil {
			return flatRecipients, err
		}
		flatRecipients[i] = flatRecipient
	}
	return flatRecipients, nil
}

func flattenRecipient(recipient KnowBe4Recipient) (KnowBe4FlatRecipient, error) {
	var flatRecipient KnowBe4FlatRecipient
	if err := ConvertToOtherType(recipient, &flatRecipient); err != nil {
		return flatRecipient, err
	}

	flatRecipient.UserID = recipient.User.ID
	flatRecipient.UserActiveDirectoryGUID = recipient.User.ActiveDirectoryGUID
	flatRecipient.UserFirstName = recipient.User.FirstName
	flatRecipient.UserLastName = recipient.User.LastName
	flatRecipient.UserEmail = recipient.User.Email
	flatRecipient.TemplateID = recipient.Template.ID
	flatRecipient.TemplateName = recipient.Template.Name

	return flatRecipient, nil
}

func flattenCampaigns(campaigns []KnowBe4Campaign) ([]KnowBe4FlatCampaign, error) {
	flatCampaigns := make([]KnowBe4FlatCampaign, len(campaigns))
	for i, recipient := range campaigns {
		flatCampaign, err := flattenCampaign(recipient)
		if err != nil {
			return flatCampaigns, err
		}
		flatCampaigns[i] = flatCampaign
	}
	return flatCampaigns, nil
}

func flattenCampaign(campaign KnowBe4Campaign) (KnowBe4FlatCampaign, error) {
	var flatCampaign KnowBe4FlatCampaign
	if err := ConvertToOtherType(campaign, &flatCampaign); err != nil {
		return flatCampaign, err
	}

	flatCampaign.Groups = flattenGroupSummaries(campaign.Groups)
	flatCampaign.DifficultyFilter = flattenIntSlice(campaign.DifficultyFilter)
	flatCampaign.Psts = flattenPstSlice(campaign.Psts)

	return flatCampaign, nil
}

func flattenIntSlice(intSlice []int) string {
	stringSlice := make([]string, len(intSlice))
	for i := range intSlice {
		stringSlice[i] = strconv.Itoa(intSlice[i])
	}
	return strings.Join(stringSlice, ",")
}

func flattenPstSlice(pstSlice []PstSummary) string {
	stringSlice := make([]string, len(pstSlice))
	for i := range pstSlice {
		stringSlice[i] = strconv.Itoa(pstSlice[i].PstId)
	}
	return strings.Join(stringSlice, ",")
}

func flattenGroups(groups []KnowBe4Group) ([]KnowBe4FlatGroup, error) {
	flatGroups := make([]KnowBe4FlatGroup, len(groups))
	for i, group := range groups {
		flatGroup, err := flattenGroup(group)
		if err != nil {
			return flatGroups, err
		}
		flatGroups[i] = flatGroup
	}
	return flatGroups, nil
}

func flattenGroup(group KnowBe4Group) (KnowBe4FlatGroup, error) {
	var flatGroup KnowBe4FlatGroup
	if err := ConvertToOtherType(group, &flatGroup); err != nil {
		return flatGroup, err
	}

	return flatGroup, nil
}

// ConvertToOtherType uses json marshal/unmarshal to convert one type to another.
// Output parameter should be a pointer to the receiving struct
func ConvertToOtherType(input, output interface{}) error {
	str, err := json.Marshal(input)
	if err != nil {
		return fmt.Errorf("failed to convert to apitype. marshal error: %s", err.Error())
	}
	if err := json.Unmarshal(str, output); err != nil {
		return fmt.Errorf("failed to convert to apitype. unmarshal error: %s", err.Error())
	}

	return nil
}
