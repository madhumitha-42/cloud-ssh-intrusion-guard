#!/usr/bin/env bash
#
# harden_ssh.sh
# Part of: Cloud SSH Intrusion Guard & Automated Alert System (SIH Project)
#
# Purpose:
#   Hardens the OpenSSH server configuration on a Linux host by:
#     1. Backing up the existing /etc/ssh/sshd_config
#     2. Disabling password-based authentication (key-based only)
#     3. Disabling direct root login over SSH
#     4. Limiting MaxAuthTries to 3 to slow brute-force attempts
#     5. Validating the new configuration before applying it
#     6. Safely restarting the SSH service
#
# Usage:
#   sudo ./harden_ssh.sh
#
# Notes:
#   - Must be run with root privileges (sudo).
#   - Before running, ensure at least one SSH key-based login works,
#     otherwise you may lock yourself out once password auth is disabled.
#   - Idempotent: safe to run multiple times.

set -euo pipefail

SSHD_CONFIG="/etc/ssh/sshd_config"
BACKUP_DIR="/etc/ssh/backups"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_FILE="${BACKUP_DIR}/sshd_config.bak.${TIMESTAMP}"
MAX_AUTH_TRIES=3

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

error_exit() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $*" >&2
    exit 1
}

# --- Pre-flight checks ---------------------------------------------------

if [[ "${EUID}" -ne 0 ]]; then
    error_exit "This script must be run as root (use: sudo $0)"
fi

if [[ ! -f "${SSHD_CONFIG}" ]]; then
    error_exit "SSH config not found at ${SSHD_CONFIG}. Is OpenSSH server installed?"
fi

command -v sshd >/dev/null 2>&1 || error_exit "sshd binary not found in PATH."

# --- Step 1: Backup existing configuration --------------------------------

log "Creating backup directory at ${BACKUP_DIR} (if not present)..."
mkdir -p "${BACKUP_DIR}"

log "Backing up current sshd_config to ${BACKUP_FILE}..."
cp -p "${SSHD_CONFIG}" "${BACKUP_FILE}"
log "Backup complete."

# --- Helper: set or update a directive in sshd_config ---------------------
# Ensures the directive appears exactly once, uncommented, with the given value.
set_directive() {
    local key="$1"
    local value="$2"

    if grep -qiE "^\s*#?\s*${key}\b" "${SSHD_CONFIG}"; then
        # Replace the first matching line (commented or not) with the desired value
        sed -i "0,/^\s*#\?\s*${key}\b.*/s//${key} ${value}/I" "${SSHD_CONFIG}"
    else
        echo "${key} ${value}" >> "${SSHD_CONFIG}"
    fi
    log "Set '${key} ${value}' in ${SSHD_CONFIG}"
}

# --- Step 2: Apply hardening directives ------------------------------------

log "Disabling password authentication..."
set_directive "PasswordAuthentication" "no"

log "Disabling root login over SSH..."
set_directive "PermitRootLogin" "no"

log "Limiting MaxAuthTries to ${MAX_AUTH_TRIES}..."
set_directive "MaxAuthTries" "${MAX_AUTH_TRIES}"

log "Ensuring public key authentication is enabled..."
set_directive "PubkeyAuthentication" "yes"

log "Disabling empty passwords..."
set_directive "PermitEmptyPasswords" "no"

log "Enabling protocol-level logging (VERBOSE) for monitoring..."
set_directive "LogLevel" "VERBOSE"

# --- Step 3: Validate configuration syntax ---------------------------------

log "Validating new SSH configuration syntax..."
if ! sshd -t; then
    error_exit "sshd_config validation failed. Restoring backup and aborting."
fi
log "Configuration syntax OK."

# --- Step 4: Restart SSH service safely ------------------------------------

restart_ssh_service() {
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl list-unit-files | grep -q '^ssh\.service'; then
            systemctl restart ssh
        elif systemctl list-unit-files | grep -q '^sshd\.service'; then
            systemctl restart sshd
        else
            error_exit "Could not find ssh/sshd systemd unit to restart."
        fi
    elif command -v service >/dev/null 2>&1; then
        service ssh restart 2>/dev/null || service sshd restart
    else
        error_exit "No supported service manager (systemctl/service) found."
    fi
}

log "Restarting SSH service..."
if restart_ssh_service; then
    log "SSH service restarted successfully."
else
    error_exit "Failed to restart SSH service. Restore backup from ${BACKUP_FILE} if needed."
fi

log "SSH hardening complete."
log "Backup of original config stored at: ${BACKUP_FILE}"
log "IMPORTANT: Verify you can still log in via SSH key-based auth in a NEW terminal"
log "           before closing this session, to avoid being locked out."
