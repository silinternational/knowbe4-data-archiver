package main

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

const exampleCampaigns = `[
{
    "campaign_id": 242333,
    "name": "One Time Phishing Security Test",
    "groups": [
      {
        "group_id": 0,
        "name": "All Users"
      },
      {
        "group_id": 1,
        "name": "Contractors"
      }
    ],
    "last_phish_prone_percentage": 0.3,
    "last_run": "2019-04-02T15:02:38.000Z",
    "status": "Closed",
    "hidden": false,
    "send_duration": "3 Business Days",
    "track_duration": "3 Days",
    "frequency": "One Time",
    "difficulty_filter": [
      1,
      2,
      3,
      4,
      5
    ],
    "create_date": "2019-04-02T15:02:38.000Z",
    "psts_count": 2,
    "psts": [
      {
        "pst_id": 1,
        "status": "Closed",
        "start_date": "2019-04-02T15:02:38.000Z",
        "users_count": 123,
        "phish_prone_percentage": 0.3
      },
      {
        "pst_id": 29,
        "status": "Open",
        "start_date": "2019-04-03T16:08:38.000Z",
        "users_count": 2,
        "phish_prone_percentage": 0.5
      }
    ]
  },
  {
    "campaign_id": 242399
  }
]`

const exampleGroups = `[
  {
    "id": 2184841,
    "name": "!SawPhish Monitors",
    "group_type": "console_group",
    "adi_guid": null,
    "member_count": 0,
    "current_risk_score": 0.0,
    "risk_score_history": [],
    "status": "active"
  },
  {
    "id": 1629520,
    "name": "!SG - Advanced Phishing",
    "group_type": "smart_group",
    "adi_guid": null,
    "member_count": 3432,
    "current_risk_score": 35.18206022600573,
    "risk_score_history": [
      {
        "risk_score": 32.7108,
        "date": "2020-11-06"
      },
      {
        "risk_score": 32.6839,
        "date": "2020-11-07"
      },
      {
        "risk_score": 33.0323,
        "date": "2020-11-08"
      }
    ],
    "status": "active"
  }
]`

const exampleUsers = `[
  {
    "id": 667542,
    "employee_number": "19425",
    "first_name": "William",
    "last_name": "Marcoux",
    "job_title": "VP of Sales",
    "email": "wmarcoux@kb4-demo.com",
    "phish_prone_percentage": 14.235,
    "phone_number": "555-554-2222",
    "extension": "42",
    "mobile_phone_number": "555-553-4422",
    "location": "Office A",
    "division": "Sales",
    "manager_name": "Michael Scott",
    "manager_email": "mscott@kb4-demo.com",
    "adi_manageable": false,
    "adi_guid": null,
    "groups": [
    3264
    ],
    "current_risk_score": 45.742,
    "risk_score_history": [
    {
    "risk_score": 45.742,
    "date": "2019-03-12"
    }
    ],
    "aliases": [
    "alias_email@kb4-demo.com"
    ],
    "joined_on": "2019-04-02T15:02:38.000Z",
    "last_sign_in": "2019-04-02T15:02:38.000Z",
    "status": "active",
    "organization": "KB4-Demo",
    "department": "Sales",
    "language": "English - United States",
    "comment": "Low PPP",
    "employee_start_date": "2019-04-02T15:02:38.000Z",
    "archived_at": null,
    "custom_field_1": "Building C, 4th Floor",
    "custom_field_2": null,
    "custom_field_3": null,
    "custom_field_4": null,
    "custom_date_1": null,
    "custom_date_2": null
    }
]`
