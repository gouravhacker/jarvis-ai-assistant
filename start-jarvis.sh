#!/bin/bash

# JARVIS AI Assistant Startup Script
# This script starts the JARVIS AI Assistant system

set -e

echo "🤖 Starting JARVIS AI Assistant..."
echo "=================================="

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

# Check if .env file exists
if [ ! -f "backend/.env" ]; then
    echo "⚠️  No .env file found. Creating from template..."
    cp backend/.env.example backend/.env
    echo "📝 Please edit backend/.env with your API keys and configuration"
    echo "   Minimum required: OPENAI_API_KEY"
    echo ""
    read -p "Press Enter to continue after editing .env file..."
fi

# Create necessary directories
echo "📁 Creating necessary directories..."
mkdir -p backend/data
mkdir -p backend/logs
mkdir -p shared/types

# Check if OpenAI API key is set
if ! grep -q "OPENAI_API_KEY=sk-" backend/.env; then
    echo "⚠️  OpenAI API key not found in .env file"
    echo "   Please add your OpenAI API key to backend/.env"
    echo "   Example: OPENAI_API_KEY=sk-your-key-here"
    echo ""
    read -p "Press Enter to continue anyway (some features will not work)..."
fi

# Start the services
echo "🚀 Starting JARVIS services..."
docker-compose up -d

# Wait for services to be ready
echo "⏳ Waiting for services to start..."
sleep 10

# Check service health
echo "🔍 Checking service health..."

# Check backend
if curl -f http://localhost:8001/ &> /dev/null; then
    echo "✅ Backend service is running"
else
    echo "❌ Backend service failed to start"
    echo "   Check logs with: docker-compose logs backend"
fi

# Check frontend
if curl -f http://localhost:3000/ &> /dev/null; then
    echo "✅ Frontend service is running"
else
    echo "❌ Frontend service failed to start"
    echo "   Check logs with: docker-compose logs frontend"
fi

echo ""
echo "🎉 JARVIS AI Assistant is starting up!"
echo "=================================="
echo "🌐 Frontend: http://localhost:3000"
echo "🔧 Backend API: http://localhost:8001"
echo "📊 API Docs: http://localhost:8001/docs"
echo ""
echo "📋 Useful commands:"
echo "   View logs: docker-compose logs -f"
echo "   Stop JARVIS: docker-compose down"
echo "   Restart: docker-compose restart"
echo ""
echo "⚠️  Security Notice:"
echo "   - JARVIS has system monitoring capabilities"
echo "   - Only use on systems you own or have permission to monitor"
echo "   - Review security settings before enabling deep web access"
echo ""
echo "🔧 First-time setup:"
echo "   1. Open http://localhost:3000"
echo "   2. Test voice interface (allow microphone access)"
echo "   3. Run a security scan to verify system monitoring"
echo "   4. Configure AI settings and security thresholds"
echo ""

# Open browser (optional)
if command -v xdg-open &> /dev/null; then
    echo "🌐 Opening JARVIS in your default browser..."
    xdg-open http://localhost:3000 &
elif command -v open &> /dev/null; then
    echo "🌐 Opening JARVIS in your default browser..."
    open http://localhost:3000 &
fi

echo "✨ JARVIS is ready to assist you!"
