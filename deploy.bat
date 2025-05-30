@echo off
REM FinGuardAI Docker Deployment Script for Windows

echo Stopping any running FinGuardAI containers...
docker-compose down

echo Cleaning up old containers and images...
docker system prune -f

echo Building and starting FinGuardAI containers...
docker-compose up -d --build

echo Waiting for services to start...
timeout /t 5 /nobreak > NUL

echo Checking service status...
docker-compose ps

echo.
echo FinGuardAI deployment complete!
echo - Frontend: http://localhost:3000
echo - Backend API: http://localhost:5001
echo.
echo To view logs:
echo   docker-compose logs -f
