#!/usr/bin/env bash

# Exit script with error if any step fails.
set -e

# Build binaries
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
$DIR/build.sh

# Export env vars
export AWS_REGION="${AWS_REGION}"
export API_BASE_URL="${API_BASE_URL}"
export API_AUTH_TOKEN="${API_AUTH_TOKEN}"
export AWS_S3_FILENAME="${AWS_S3_FILENAME}"
export AWS_S3_BUCKET="${AWS_S3_BUCKET}"

serverless deploy -v --stage prod