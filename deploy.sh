#!/bin/bash
# FinGuardAI Docker Deployment Script

# Stop running containers
echo "Stopping any running FinGuardAI containers..."
docker-compose down

# Remove old containers and images
echo "Cleaning up old containers and images..."
docker system prune -f

# Build and start containers
echo "Building and starting FinGuardAI containers..."
docker-compose up -d --build

# Wait for services to start
echo "Waiting for services to start..."
sleep 5

# Check if services are running
echo "Checking service status..."
docker-compose ps

echo "FinGuardAI deployment complete!"
echo "- Frontend: http://localhost:3000"
echo "- Backend API: http://localhost:5001"
echo ""
echo "To view logs:"
echo "  docker-compose logs -f"
