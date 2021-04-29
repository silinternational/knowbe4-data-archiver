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
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
)

const (
	countPerPage               = 500
	maxErrorsAllowed           = 5
	securityTestURLPath        = "v1/phishing/security_tests"
	recipientsURLPath          = "v1/phishing/security_tests/%v/recipients"
	s3DefaultFilename          = "knowbe4_security_tests.json"
	s3RecipientsFilenamePrefix = "knowbe4_recipients_"
)

const (
	EnvAPIBaseURL    = "API_BASE_URL"
	EnvAPIAuthToken  = "API_AUTH_TOKEN"
	EnvAWSS3Filename = "AWS_S3_FILENAME"
	EnvAWSS3Bucket   = "AWS_S3_BUCKET"
)

type KnowBe4Recipient struct {
	RecipientID int `json:"recipient_id"`
	PstID       int `json:"pst_id"`
	User        struct {
		ID                  int     `json:"id"`
		ActiveDirectoryGUID *string `json:"active_directory_guid"`
		FirstName           string  `json:"first_name"`
		LastName            string  `json:"last_name"`
		Email               string  `json:"email"`
	} `json:"user"`
	Template struct {
		ID   int    `json:"id"`
		Name string `json:"name"`
	} `json:"template"`
	ScheduledAt         time.Time  `json:"scheduled_at"`
	DeliveredAt         time.Time  `json:"delivered_at"`
	OpenedAt            time.Time  `json:"opened_at"`
	ClickedAt           time.Time  `json:"clicked_at"`
	RepliedAt           *time.Time `json:"replied_at"`
	AttachmentOpenedAt  *time.Time `json:"attachment_opened_at"`
	MacroEnabledAt      *time.Time `json:"macro_enabled_at"`
	DataEnteredAt       time.Time  `json:"data_entered_at"`
	VulnerablePluginsAt *time.Time `json:"vulnerable-plugins_at"`
	ExploitedAt         *time.Time `json:"exploited_at"`
	ReportedAt          *time.Time `json:"reported_at"`
	BouncedAt           *time.Time `json:"bounced_at"`
	IP                  string     `json:"ip"`
	IPLocation          string     `json:"ip_location"`
	Browser             string     `json:"browser"`
	BrowserVersion      string     `json:"browser_version"`
	Os                  string     `json:"os"`
}

type KnowBe4FlatRecipient struct {
	RecipientID             int        `json:"recipient_id"`
	PstID                   int        `json:"pst_id"`
	UserID                  int        `json:"user_id"`
	UserActiveDirectoryGUID *string    `json:"user_active_directory_guid"`
	UserFirstName           string     `json:"user_first_name"`
	UserLastName            string     `json:"user_last_name"`
	UserEmail               string     `json:"user_email"`
	TemplateID              int        `json:"template_id"`
	TemplateName            string     `json:"template_name"`
	ScheduledAt             time.Time  `json:"scheduled_at"`
	DeliveredAt             time.Time  `json:"delivered_at"`
	OpenedAt                time.Time  `json:"opened_at"`
	ClickedAt               time.Time  `json:"clicked_at"`
	RepliedAt               *time.Time `json:"replied_at"`
	AttachmentOpenedAt      *time.Time `json:"attachment_opened_at"`
	MacroEnabledAt          *time.Time `json:"macro_enabled_at"`
	DataEnteredAt           time.Time  `json:"data_entered_at"`
	VulnerablePluginsAt     *time.Time `json:"vulnerable-plugins_at"`
	ExploitedAt             *time.Time `json:"exploited_at"`
	ReportedAt              *time.Time `json:"reported_at"`
	BouncedAt               *time.Time `json:"bounced_at"`
	IP                      string     `json:"ip"`
	IPLocation              string     `json:"ip_location"`
	Browser                 string     `json:"browser"`
	BrowserVersion          string     `json:"browser_version"`
	Os                      string     `json:"os"`
}

type KnowBe4SecurityTest struct {
	CampaignID int    `json:"campaign_id"`
	PstID      int    `json:"pst_id"`
	Status     string `json:"status"`
	Name       string `json:"name"`
	Groups     []struct {
		GroupID int    `json:"group_id"`
		Name    string `json:"name"`
	} `json:"groups"`
	PhishPronePercentage float64   `json:"phish_prone_percentage"`
	StartedAt            time.Time `json:"started_at"`
	Duration             int       `json:"duration"`
	Categories           []struct {
		CategoryID int    `json:"category_id"`
		Name       string `json:"name"`
	} `json:"categories"`
	Template struct {
		ID   int    `json:"id"`
		Name string `json:"name"`
	} `json:"template"`
	LandingPage struct {
		ID   int    `json:"id"`
		Name string `json:"name"`
	} `json:"landing-page"`
	ScheduledCount        int `json:"scheduled_count"`
	DeliveredCount        int `json:"delivered_count"`
	OpenedCount           int `json:"opened_count"`
	ClickedCount          int `json:"clicked_count"`
	RepliedCount          int `json:"replied_count"`
	AttachmentOpenCount   int `json:"attachment_open_count"`
	MacroEnabledCount     int `json:"macro_enabled_count"`
	DataEnteredCount      int `json:"data_entered_count"`
	VulnerablePluginCount int `json:"vulnerable_plugin_count"`
	ExploitedCount        int `json:"exploited_count"`
	ReportedCount         int `json:"reported_count"`
	BouncedCount          int `json:"bounced_count"`
}

type KnowBe4FlatSecurityTest struct {
	CampaignID            int       `json:"campaign_id"`
	PstID                 int       `json:"pst_id"`
	Status                string    `json:"status"`
	Name                  string    `json:"name"`
	Groups                string    `json:"all_groups"`
	PhishPronePercentage  float64   `json:"phish_prone_percentage"`
	StartedAt             time.Time `json:"started_at"`
	Duration              int       `json:"duration"`
	Categories            string    `json:"all_categories"`
	TemplateID            int       `json:"template_id"`
	TemplateName          string    `json:"template_name"`
	LandingPageID         int       `json:"landing_page_id"`
	LandingPageName       string    `json:"landing_page_name"`
	ScheduledCount        int       `json:"scheduled_count"`
	DeliveredCount        int       `json:"delivered_count"`
	OpenedCount           int       `json:"opened_count"`
	ClickedCount          int       `json:"clicked_count"`
	RepliedCount          int       `json:"replied_count"`
	AttachmentOpenCount   int       `json:"attachment_open_count"`
	MacroEnabledCount     int       `json:"macro_enabled_count"`
	DataEnteredCount      int       `json:"data_entered_count"`
	VulnerablePluginCount int       `json:"vulnerable_plugin_count"`
	ExploitedCount        int       `json:"exploited_count"`
	ReportedCount         int       `json:"reported_count"`
	BouncedCount          int       `json:"bounced_count"`
}

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

	if c.AWSS3Filename == "" {
		filename := os.Getenv(EnvAWSS3Filename)
		if filename == "" {
			filename = s3DefaultFilename
		}
		c.AWSS3Filename = filename
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

func saveRecipientsForSecTest(secTestID int, config LambdaConfig, wg *sync.WaitGroup, c chan error) {
	defer wg.Done()

	_, recipients, err := getAllRecipientsForSecurityTest(secTestID, config)
	if err != nil {
		err = fmt.Errorf("error gettings reciptients from api for security test %v ... %s", secTestID, err)
		c <- err
		return
	}

	var cleanBytes []byte
	if cleanBytes, err = json.Marshal(&recipients); err != nil {
		err = fmt.Errorf("error marshalling recipients results for security test %v for saving to S3 ... %s", secTestID, err)
		c <- err
		return
	}

	filename := fmt.Sprintf("%s%v.json", s3RecipientsFilenamePrefix, secTestID)

	if err := saveToS3(cleanBytes, config.AWSS3Bucket, filename); err != nil {
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

func saveToS3(data []byte, bucketName, fileName string) error {
	sess := session.Must(session.NewSession())
	uploader := s3manager.NewUploader(sess)
	_, err := uploader.Upload(&s3manager.UploadInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(fileName),
		Body:   bytes.NewReader(data),
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

	_, stResults, err := getAllSecurityTests(config)
	if err != nil {
		return fmt.Errorf("error gettings security tests from api ... %s", err)
	}

	var cleanBytes []byte
	if cleanBytes, err = json.Marshal(&stResults); err != nil {
		err = errors.New("error marshalling security tests results for saving to S3 ... " + err.Error())
		return err
	}

	if err := saveToS3(cleanBytes, config.AWSS3Bucket, config.AWSS3Filename); err != nil {
		err = errors.New("error saving security test results to S3 ... " + err.Error())
		return err
	}

	log.Printf("Success saving %v security tests to S3.", len(stResults))

	count := config.MaxFileCount
	if count == 0 {
		count = len(stResults)
	}
	return saveRecipientsToS3Async(config, stResults[:count])
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

	flatTest.Groups = flattenGroups(test.Groups)
	flatTest.Categories = flattenCategories(test.Categories)
	flatTest.TemplateID = test.Template.ID
	flatTest.TemplateName = test.Template.Name
	flatTest.LandingPageID = test.LandingPage.ID
	flatTest.LandingPageName = test.LandingPage.Name

	return flatTest, nil
}

func flattenGroups(groups []struct {
	GroupID int    `json:"group_id"`
	Name    string `json:"name"`
}) string {
	flatGroups := ""
	for i := range groups {
		flatGroups += groups[i].Name
	}
	return flatGroups
}

func flattenCategories(categories []struct {
	CategoryID int    `json:"category_id"`
	Name       string `json:"name"`
}) string {
	flatCategories := ""
	for i := range categories {
		flatCategories += categories[i].Name
	}
	return flatCategories
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
