export BASE_URL=https://dev.develop.tapis.io

# add the tacc ldap
curl -H "X-Tapis-Token: $jwt" $BASE_URL/v3/tenants/ldaps -H "content-type: application/json" -d '{"url":"ldaps://ldap.tacc.utexas.edu", "port": 636, "use_ssl": true, "user_dn": "ou=People,dc=tacc,dc=utexas,dc=edu", "bind_dn": "uid=ldapbind,ou=People,dc=tacc,dc=utexas,dc=edu", "bind_credential": "ldap.tacc.password", "account_type": "user", "ldap_id": "tacc-all"}' | jq

# add the tenant
curl -H "X-Tapis-Token: $jwt" $BASE_URL/v3/tenants -H "content-type: application/json" -d '{"tenant_id":"tacc", "base_url": "https://tacc.develop.tapis.io", "token_service": "https://tacc.develop.tapis.io/token/v3", "security_kernel": "https://tacc.develop.tapis.io/security/v3", "owner": "CICSupport@tacc.utexas.edu", "user_ldap_connection_id": "tacc-all", "description": "Production tenant for all TACC users.", "is_owned_by_associate_site": false, "allowable_x_tenant_ids": ["tacc"], "authenticator": "https://tacc.develop.tapis.io/v3/oauth2"}' | jq