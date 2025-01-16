#!/bin/bash

## NOTE: when starting up from scratch on local tapis:
# 1. edit the local bigburnup to exit right before authenticator. 
# 2. once the other services are up:
#   a. edit config-local-kprice.json with the correct svc pass
#   b. edit docker-compose-kprice.yml so authenticator-ldap has the correct ldap rootpass
# 3. run this script
# addl. note: admin/verification/authenticator-test won't work unless you run the burnup for authenticator & have the env file in the data dir.

make clean
make build
make init_dbs
make migrate.upgrade
# make run.api
# make test
