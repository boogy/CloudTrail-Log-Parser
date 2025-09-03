#!/usr/bin/env bash

set -eux -o pipefail

# get json values from stdin
eval "$(jq -r '@sh "ZIP_NAME=\(.zip_name)"')"

SCRIPT_DIR=$(cd $(dirname "${BASH_SOURCE[0]}") && pwd)
PROJECT_DIR=$(cd $SCRIPT_DIR/.. && pwd)
OUTPUT_DIR=$PROJECT_DIR/dist
OUTPUT_FILE_ZIP=${OUTPUT_DIR}/${ZIP_NAME}.zip
RULES_FILE=$PROJECT_DIR/rules.yaml
LAMBDA_HANDLER=bootstrap

# build the lambda handler for linux arm64 architecture and strip the binary
(test -d ${OUTPUT_DIR} || mkdir -p ${OUTPUT_DIR}) &>/dev/null
(test -d ${OUTPUT_DIR} && rm -rf ${OUTPUT_DIR}/*) &>/dev/null

GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "-w" -o ${OUTPUT_DIR}/${LAMBDA_HANDLER} -tags lambda.norpc,prod ${PROJECT_DIR}/cmd/... &>/dev/null

# create a zip file with the lambda handler and rules file
zip -j ${OUTPUT_FILE_ZIP} ${OUTPUT_DIR}/${LAMBDA_HANDLER} ${RULES_FILE} &>/dev/null
rm -f ${OUTPUT_DIR}/${LAMBDA_HANDLER} &>/dev/null

# return the zip file path as json
ZIP_FILE=${OUTPUT_FILE_ZIP}
jq -n --arg file_path "$ZIP_FILE" '{"filename": "\($file_path)"}'
