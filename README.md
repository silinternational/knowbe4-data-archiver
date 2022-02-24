# knowbe4-data-archiver
A serverless function to export/archive KnowBe4 data for analytics and reporting

## Credential Rotation

### AWS Serverless User

1. Copy the aes key from Codeship
2. Paste it in a new file `codeship.aes`
3. Run `jet decrypt aws.env.encrypted aws.env`
4. (Optional) Compare the key in `aws.env` with the key in the most recent Terraform Cloud output
5. Use the Terraform CLI to taint the old access key
6. Run a new plan on Terraform Cloud
7. Review the new plan and apply if it is correct
8. Copy the new key and secret from the Terraform output into the aws.env file, overwriting the old values
9. Run `jet encrypt aws.env aws.env.encrypted`
10. Commit the new `aws.env.encrypted` file on the `develop` branch and push it to Github
11. Submit a PR to release the change to the `main` branch

### KnowBe4

(TBD)
