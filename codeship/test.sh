#!/usr/bin/env bash

# Exit script with error if any step fails.
set -e

go test -v ./archiver/
