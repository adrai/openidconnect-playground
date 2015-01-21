#!/usr/bin/env bash

# {
#   redirect_uris: [ 'http://localhost:3001/callback' ],
#   application_type: 'web',
#   client_name: 'taibika-customer-app',
#   token_endpoint_auth_method: 'client_secret_basic',
#   client_secret: '123456789',
#   trusted: 'true',
#   _id: '110bb6e0-0bda-44f9-a724-dbe55176b8c0'
# }
nv add client "{\"_id\":\"110bb6e0-0bda-44f9-a724-dbe55176b8c0\",\"client_name\":\"taibika-customer-app\",\"application_type\":\"web\",\"token_endpoint_auth_method\":\"client_secret_basic\",\"client_secret\":\"123456789\",\"trusted\":\"true\",\"redirect_uris\":[\"http://localhost:3001/callback\"]}"

# {
#   givenName: 'Hans',
#   familyName: 'Muster',
#   email: 'a@b.c',
#   _id: '327c06ef-caa2-455a-8687-541be74a214e'
# }
nv add user "{\"_id\":\"327c06ef-caa2-455a-8687-541be74a214e\",\"email\":\"a@b.c\",\"password\":\"123\",\"givenName\":\"Hans\",\"familyName\":\"Muster\"}"

nv assign a@b.c authority
