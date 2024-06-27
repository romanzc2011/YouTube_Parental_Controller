#!/bin/bash
#
cd ../../youtube_creds
set -a
source .env
set +a
cd ../YouTube_Parental_Controller/src

./main
