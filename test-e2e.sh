#!/bin/bash

# End-to-end test script for distributed-topic-tracker
# This script runs multiple Docker containers and waits for them to discover each other

set -e

echo "Starting end-to-end test..."

# Clean up any existing containers
docker-compose down --remove-orphans || true

# Build and start the containers
echo "Building and starting containers..."
docker-compose up --build -d

# Function to check if a container has printed "Joined topic"
check_joined_topic() {
    local container_name=$1
    local timeout=${2:-60}
    local count=0
    
    echo "Waiting for $container_name to join topic..."
    
    while [ $count -lt $timeout ]; do
        if docker logs $container_name 2>&1 | grep -q "Joined topic"; then
            echo "$container_name successfully joined topic"
            return 0
        fi
        sleep 1
        count=$((count + 1))
    done
    
    echo "$container_name failed to join topic within $timeout seconds"
    echo "Container logs:"
    docker logs $container_name
    return 1
}

# Wait for all nodes to join the topic
success=true

check_joined_topic "dtt-node1" 120 || success=false
check_joined_topic "dtt-node2" 120 || success=false
check_joined_topic "dtt-node3" 120 || success=false

# Clean up
echo "Cleaning up containers..."
docker-compose down

if [ "$success" = true ]; then
    echo "End-to-end test PASSED: All nodes successfully joined the topic"
    exit 0
else
    echo "End-to-end test FAILED: One or more nodes failed to join the topic"
    exit 1
fi
