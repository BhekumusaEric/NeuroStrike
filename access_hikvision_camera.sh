#!/bin/bash

# Script to access Hikvision camera system at 192.168.89.2
# Created by NeuroStrike Red Agent

echo "Hikvision Camera Access Tool"
echo "==========================="
echo ""
echo "This script helps you access the Hikvision camera system at 192.168.89.2"
echo "Credentials: admin / 12345"
echo ""

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to open web browser
open_web_interface() {
    echo "Opening web interface in your default browser..."

    if command_exists xdg-open; then
        xdg-open "http://192.168.89.2/" &
    elif command_exists open; then
        open "http://192.168.89.2/" &
    else
        echo "Could not detect a way to open a browser. Please manually navigate to:"
        echo "http://192.168.89.2/"
    fi

    echo "Use the following credentials:"
    echo "Username: admin"
    echo "Password: 12345"
}

# Function to test connectivity
test_connectivity() {
    echo "Testing connectivity to camera system..."
    if ping -c 1 192.168.89.2 &> /dev/null; then
        echo "Camera system is reachable."
        return 0
    else
        echo "ERROR: Camera system is not reachable. Please check your network connection."
        return 1
    fi
}

# Function to stream RTSP
stream_rtsp() {
    echo "Attempting to stream RTSP feed..."

    if ! command_exists ffplay; then
        echo "FFplay not found. Installing ffmpeg..."
        sudo apt-get update && sudo apt-get install -y ffmpeg
    fi

    echo "Starting RTSP stream (press Q to quit)..."
    ffplay -rtsp_transport tcp "rtsp://admin:12345@192.168.89.2:554/Streaming/Channels/101"
}

# Function to check camera status
check_status() {
    echo "Checking camera system status..."

    # Try to access the web interface
    status_code=$(curl -s -o /dev/null -w "%{http_code}" -u admin:12345 http://192.168.89.2/)

    if [ "$status_code" = "200" ]; then
        echo "Camera system is online and accessible."
        echo "Authentication successful."
    else
        echo "Camera system returned status code: $status_code"
        echo "Authentication may have failed or the system is in an unusual state."
    fi
}

# Main menu
show_menu() {
    echo ""
    echo "Select an option:"
    echo "1) Open web interface"
    echo "2) Stream RTSP feed"
    echo "3) Check camera status"
    echo "4) Exit"
    echo ""
    read -p "Enter your choice (1-4): " choice

    case $choice in
        1) open_web_interface ;;
        2) stream_rtsp ;;
        3) check_status ;;
        4) echo "Exiting..."; exit 0 ;;
        *) echo "Invalid choice. Please try again."; show_menu ;;
    esac

    # Return to menu after action completes
    echo ""
    read -p "Press Enter to return to the menu..."
    show_menu
}

# Start script
if test_connectivity; then
    show_menu
else
    echo "Exiting due to connectivity issues."
    exit 1
fi
