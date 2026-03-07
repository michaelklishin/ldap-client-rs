#!/usr/bin/env nu

# Stop and remove the OpenLDAP container.
# Idempotent: safe to run even if container doesn't exist.

const CONTAINER_NAME = "ldap-client-rs-openldap"

def main [] {
    let existing = (docker ps -a --filter $"name=($CONTAINER_NAME)" --format "{{.ID}}" | str trim)

    if ($existing | is-empty) {
        print $"✓ Container ($CONTAINER_NAME) does not exist"
        return
    }

    print $"Stopping container ($CONTAINER_NAME)..."
    docker stop $CONTAINER_NAME
    docker rm $CONTAINER_NAME
    print $"✓ Container ($CONTAINER_NAME) removed"
}
