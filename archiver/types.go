package main

import "time"

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
	ScheduledAt         *time.Time `json:"scheduled_at"`
	DeliveredAt         *time.Time `json:"delivered_at"`
	OpenedAt            *time.Time `json:"opened_at"`
	ClickedAt           *time.Time `json:"clicked_at"`
	RepliedAt           *time.Time `json:"replied_at"`
	AttachmentOpenedAt  *time.Time `json:"attachment_opened_at"`
	MacroEnabledAt      *time.Time `json:"macro_enabled_at"`
	DataEnteredAt       *time.Time `json:"data_entered_at"`
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

type KnowBe4SecurityTest struct {
	CampaignID           int            `json:"campaign_id"`
	PstID                int            `json:"pst_id"`
	Status               string         `json:"status"`
	Name                 string         `json:"name"`
	Groups               []GroupSummary `json:"groups"`
	PhishPronePercentage float64        `json:"phish_prone_percentage"`
	StartedAt            *time.Time     `json:"started_at"`
	Duration             int            `json:"duration"`
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

type KnowBe4Campaign struct {
	CampaignID               int            `json:"campaign_id"`
	Name                     string         `json:"name"`
	Groups                   []GroupSummary `json:"groups"`
	LastPhishPronePercentage float64        `json:"last_phish_prone_percentage"`
	LastRun                  *time.Time     `json:"last_run"`
	Status                   string         `json:"status"`
	Hidden                   bool           `json:"hidden"`
	SendDuration             string         `json:"send_duration"`
	TrackDuration            string         `json:"track_duration"`
	Frequency                string         `json:"frequency"`
	DifficultyFilter         []int          `json:"difficulty_filter"`
	CreateDate               *time.Time     `json:"create_date"`
	PstsCount                int            `json:"psts_count"`
	Psts                     []PstSummary   `json:"psts"`
}

type GroupSummary struct {
	GroupID int    `json:"group_id"`
	Name    string `json:"name"`
}

type PstSummary struct {
	PstId                int        `json:"pst_id"`
	Status               string     `json:"status"`
	StartDate            *time.Time `json:"start_date"`
	UsersCount           int        `json:"users_count"`
	PhishPronePercentage float64    `json:"phish_prone_percentage"`
}

type KnowBe4Group struct {
	Id               int                `json:"id"`
	Name             string             `json:"name"`
	GroupType        string             `json:"group_type"`
	AdiGuid          string             `json:"adi_guid"`
	MemberCount      int                `json:"member_count"`
	CurrentRiskScore float64            `json:"current_risk_score"`
	RiskScoreHistory []RiskScoreHistory `json:"risk_score_history"`
	Status           string             `json:"status"`
}

type RiskScoreHistory struct {
	GroupID   int     `json:"group_id,omitempty"`
	RiskScore float64 `json:"risk_score"`
	Date      string  `json:"date"`
}

type KnowBe4User struct {
	Id                   int                `json:"id"`
	EmployeeNumber       string             `json:"employee_number"`
	FirstName            string             `json:"first_name"`
	LastName             string             `json:"last_name"`
	JobTitle             string             `json:"job_title"`
	Email                string             `json:"email"`
	PhishPronePercentage float64            `json:"phish_prone_percentage"`
	PhoneNumber          string             `json:"phone_number"`
	Extension            string             `json:"extension"`
	MobilePhoneNumber    string             `json:"mobile_phone_number"`
	Location             string             `json:"location"`
	Division             string             `json:"division"`
	ManagerName          string             `json:"manager_name"`
	ManagerEmail         string             `json:"manager_email"`
	AdiManageable        bool               `json:"adi_manageable"`
	AdiGuid              string             `json:"adi_guid"`
	Groups               []int              `json:"groups"`
	CurrentRiskScore     float64            `json:"current_risk_score"`
	RiskScoreHistory     []RiskScoreHistory `json:"risk_score_history"`
	Aliases              []string           `json:"aliases"`
	JoinedOn             *time.Time         `json:"joined_on"`
	LastSignIn           *time.Time         `json:"last_sign_in"`
	Status               string             `json:"status"`
	Organization         string             `json:"organization"`
	Department           string             `json:"department"`
	Language             string             `json:"language"`
	Comment              string             `json:"comment"`
	EmployeeStartDate    *time.Time         `json:"employee_start_date"`
	ArchivedAt           *time.Time         `json:"archived_at"`
	CustomField1         string             `json:"custom_field_1"`
	CustomField2         string             `json:"custom_field_2"`
	CustomField3         string             `json:"custom_field_3"`
	CustomField4         string             `json:"custom_field_4"`
	CustomDate1          *time.Time         `json:"custom_date_1"`
	CustomDate2          *time.Time         `json:"custom_date_2"`
	SnapshotDate         string             `json:"snapshot_date"`
}
