package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
)

const countPerPage = 500
const securityTestURLPath = "v1/phishing/security_tests"
const s3DefaultFilename = "knowbe4_data"

const (
	EnvAPIBaseURL = "API_BASE_URL"
	EnvAPIAuthToken = "API_AUTH_TOKEN"
	EnvAWSS3Filename = "AWS_S3_FILENAME"
	EnvAWSS3Bucket = "AWS_S3_BUCKET"
)


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

type LambdaConfig struct {
	APIBaseURL string `json:"APIBaseURL"`
	APIAuthToken string `json:"APIAuthToken"`
	AWSS3Bucket string `json:"AWSS3Bucket"`
	AWSS3Filename string `json:"AWSS3FileName"`
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

	req.Header.Set("Authorization", "Bearer " + config.APIAuthToken)
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
		"page": strconv.Itoa(pageNum),
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

	for i := 1;; i++ {
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

func saveToS3(data []byte, config LambdaConfig) error {
	sess := session.Must(session.NewSession())
	uploader := s3manager.NewUploader(sess)
	_, err := uploader.Upload(&s3manager.UploadInput{
		Bucket: aws.String(config.AWSS3Bucket),
		Key:    aws.String(config.AWSS3Filename),
		Body:   bytes.NewReader(data),
	})

	if err != nil {
		return fmt.Errorf("Error saving data to %s/%s ... %s", config.AWSS3Bucket, config.AWSS3Filename, err)
	}

	return nil
}

func handler(config LambdaConfig) error {
	if err := config.init(); err != nil {
		return err
	}

	_, results, err := getAllSecurityTests(config)
	if err != nil {
		return err
	}

	var cleanBytes []byte
	if cleanBytes, err = json.Marshal(&results); err != nil {
		err = errors.New( "error marshalling results for saving to S3 ... " + err.Error())
		return err
	}

	return saveToS3(cleanBytes, config)
}

func manualRun() {
	var config LambdaConfig
	if err := config.init(); err != nil {
		panic("error initializing config ... " + err.Error())
	}

	if err := handler(config); err != nil {
		panic("error calling handler ... " + err.Error())
	}

	fmt.Printf("Success saving to s3\n")
}

func main() {
	lambda.Start(handler)
	//manualRun()
}

