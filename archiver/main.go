package main

import (
	"bytes"
	"encoding/json"
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

const securityTestURLPath = "v1/phishing/security_tests"
const s3DefaultFilename = "knowbe4_data"

const EnvAPIBaseURL = "API_BASE_URL"
const EnvAPIAuthToken = "API_AUTH_TOKEN"
const EnvAWSS3Filename = "AWS_S3_FILENAME"

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

	if c.AWSS3Filename == "" {
		filename := os.Getenv(EnvAWSS3Filename)
		if filename == "" {
			filename = s3DefaultFilename
		}
		c.AWSS3Filename = filename
	}

	return nil
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

func callAPI(urlPath string, config LambdaConfig) (*http.Response, error) {
	var err error
	var req *http.Request

	url := config.APIBaseURL + "/" + urlPath

	req, err = http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("error preparing http request: %s", err)
	}

	req.Header.Set("Authorization", "Bearer " + config.APIAuthToken)
	req.Header.Set("Content-Type", "application/json")

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

func getReport(config LambdaConfig) ([]byte, []KnowBe4SecurityTest, error) {
	// Make http call
	resp, err := callAPI(securityTestURLPath, config)
	if err != nil {
		return nil, nil, err
	}

	defer resp.Body.Close()
	bodyBytes, _ := ioutil.ReadAll(resp.Body)

	var allTests []KnowBe4SecurityTest

	s, _ := strconv.Unquote(string(bodyBytes))
	if err := json.Unmarshal([]byte(s), &allTests); err != nil {
		return nil, nil, fmt.Errorf("error decoding response json for security tests: %s", err)
	}

	return bodyBytes, allTests, nil
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

	data, _, err := getReport(config)
	if err != nil {
		return err
	}

	return saveToS3(data, config)
}

func main() {
	lambda.Start(handler)
}

