#!/bin/sh

set -e

md5sum_q() {
  md5sum "${@}" | awk '{print $1}'
}

# Get the JWT token
TOKEN="$(curl -s -H "Content-Type: application/json" -X POST -d '{"username": "'${DOCKER_USERNAME}'", "password": "'${DOCKER_PASSWORD}'"}' https://hub.docker.com/v2/users/login/ | jq -r .token)"
if [ -z "${TOKEN}" -o "${TOKEN}" = "null" ]
then
  echo "ERROR: Invalid or no JWT TOKEN returned!" 1>&2
  exit 1
fi

BCSUM1="`jq -r .nonce < /dev/null | md5sum_q`"
BCSUM2="`echo | md5sum_q`"

API_URL="https://hub.docker.com/v2/repositories/${DOCKER_REPO}/"
OLDCSUM="`curl -s -H "Authorization: JWT ${TOKEN}" "${API_URL}" | jq -r .full_description | md5sum_q`"
NEWCSUM="`md5sum_q "${1}"`"
if [ "${OLDCSUM}" = "${NEWCSUM}" ]
then
  # description is up to date already
  exit 0
fi
if [ "${OLDCSUM}" = "${BCSUM1}" -o "${OLDCSUM}" = "${BCSUM2}" ]
then
  echo "ERROR: Empty description read!" 1>&2
  exit 1
fi

MYNAME="`basename "${0}"`"
DESCRIPTION_FILE="`mktemp -t ${MYNAME}.XXXXXXX`"
echo '{"full_description": "' > "${DESCRIPTION_FILE}"
perl -0777 -p -e 's|\n\z||' "${1}" | perl -p -e 's|\n|\\n\n|' >> "${DESCRIPTION_FILE}"
echo '"}' >> "${DESCRIPTION_FILE}"

# Update the description on DockerHub
curl -X PATCH -H "Content-Type: application/json" -H "Authorization: JWT ${TOKEN}" -d @"${DESCRIPTION_FILE}" "${API_URL}"
rm "${DESCRIPTION_FILE}"
