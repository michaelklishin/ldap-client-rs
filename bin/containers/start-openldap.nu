#!/usr/bin/env nu

# Start an OpenLDAP container for integration testing.
# Idempotent: re-running will reuse the existing container.

const CONTAINER_NAME = "ldap-client-rs-openldap"
const IMAGE = "osixia/openldap:1.5.0"
const LDAP_PORT = 1389
const LDAPS_PORT = 1636

def main [] {
    # Check if container already exists
    let existing = (docker ps -a --filter $"name=($CONTAINER_NAME)" --format "{{.Status}}" | str trim)

    if ($existing | is-not-empty) {
        if ($existing | str starts-with "Up") {
            print $"✓ Container ($CONTAINER_NAME) is already running"
            return
        }
        print $"Starting stopped container ($CONTAINER_NAME)..."
        docker start $CONTAINER_NAME
    } else {
        print $"Creating container ($CONTAINER_NAME)..."
        (docker run -d
            --name $CONTAINER_NAME
            -p $"($LDAP_PORT):389"
            -p $"($LDAPS_PORT):636"
            -e "LDAP_ORGANISATION=Example Inc"
            -e "LDAP_DOMAIN=example.com"
            -e "LDAP_ADMIN_PASSWORD=adminpassword"
            $IMAGE)
    }

    # Wait for LDAP to be ready
    print "Waiting for OpenLDAP to be ready..."
    mut ready = false
    for _ in 0..30 {
        let result = (do { docker exec $CONTAINER_NAME ldapsearch -x -H ldap://localhost -b "dc=example,dc=com" -D "cn=admin,dc=example,dc=com" -w adminpassword "(objectClass=*)" } | complete)
        if $result.exit_code == 0 {
            $ready = true
            break
        }
        sleep 1sec
    }

    if $ready {
        print $"✓ OpenLDAP ready on ports ($LDAP_PORT)/($LDAPS_PORT)"
    } else {
        print "✗ OpenLDAP failed to start within 30 seconds"
        exit 1
    }
}
