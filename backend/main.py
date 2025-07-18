from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import uvicorn
import asyncio
import json
import logging
from datetime import datetime
from typing import List, Dict, Any
import os
from dotenv import load_dotenv

# Import our modules
from ai.engine import AIEngine
from system.monitor import SystemMonitor
from security.monitor import SecurityMonitor
from web.scraper import WebScraper

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('jarvis.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="JARVIS AI Assistant",
    description="Personal AI Assistant with System Control and Security Features",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:3001"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer()

# Global instances
ai_engine = None
system_monitor = None
security_monitor = None
web_scraper = None

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"WebSocket connected. Total connections: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        logger.info(f"WebSocket disconnected. Total connections: {len(self.active_connections)}")

    async def send_personal_message(self, message: str, websocket: WebSocket):
        try:
            await websocket.send_text(message)
        except Exception as e:
            logger.error(f"Error sending message: {e}")

    async def broadcast(self, message: str):
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception as e:
                logger.error(f"Error broadcasting message: {e}")
                disconnected.append(connection)
        
        # Remove disconnected connections
        for conn in disconnected:
            self.disconnect(conn)

manager = ConnectionManager()

@app.on_event("startup")
async def startup_event():
    """Initialize all components on startup"""
    global ai_engine, system_monitor, security_monitor, web_scraper
    
    logger.info("Starting JARVIS AI Assistant...")
    
    try:
        # Initialize AI Engine
        ai_engine = AIEngine()
        logger.info("AI Engine initialized")
        
        # Initialize System Monitor
        system_monitor = SystemMonitor()
        logger.info("System Monitor initialized")
        
        # Initialize Security Monitor
        security_monitor = SecurityMonitor()
        logger.info("Security Monitor initialized")
        
        # Initialize Web Scraper
        web_scraper = WebScraper()
        logger.info("Web Scraper initialized")
        
        # Start background monitoring tasks
        asyncio.create_task(background_monitoring())
        
        logger.info("JARVIS AI Assistant started successfully!")
        
    except Exception as e:
        logger.error(f"Failed to initialize JARVIS: {e}")
        raise

async def background_monitoring():
    """Background task for continuous monitoring"""
    while True:
        try:
            # Get system status
            system_status = await system_monitor.get_status()
            
            # Get security alerts
            security_alerts = await security_monitor.check_threats()
            
            # Broadcast updates if there are alerts
            if security_alerts:
                await manager.broadcast(json.dumps({
                    "type": "security_alert",
                    "data": security_alerts,
                    "timestamp": datetime.now().isoformat()
                }))
            
            # Broadcast system status every 30 seconds
            await manager.broadcast(json.dumps({
                "type": "system_status",
                "data": system_status,
                "timestamp": datetime.now().isoformat()
            }))
            
        except Exception as e:
            logger.error(f"Error in background monitoring: {e}")
        
        await asyncio.sleep(30)  # Check every 30 seconds

# API Routes

@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "status": "online",
        "message": "JARVIS AI Assistant is running",
        "timestamp": datetime.now().isoformat()
    }

@app.post("/api/voice/command")
async def process_voice_command(command_data: Dict[str, Any]):
    """Process voice commands through AI engine"""
    try:
        command = command_data.get("command", "")
        if not command:
            raise HTTPException(status_code=400, detail="No command provided")
        
        logger.info(f"Processing voice command: {command}")
        
        # Process through AI engine
        response = await ai_engine.process_command(command)
        
        # Log the interaction
        logger.info(f"AI Response: {response}")
        
        return {
            "success": True,
            "response": response,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error processing voice command: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/system/status")
async def get_system_status():
    """Get current system status"""
    try:
        status = await system_monitor.get_status()
        return {
            "success": True,
            "data": status,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Error getting system status: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/security/scan")
async def run_security_scan():
    """Run a security scan"""
    try:
        logger.info("Starting security scan...")
        results = await security_monitor.run_full_scan()
        
        return {
            "success": True,
            "data": results,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Error running security scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/web/search")
async def web_search(query: str, deep_web: bool = False):
    """Perform web search"""
    try:
        if not query:
            raise HTTPException(status_code=400, detail="Query parameter required")
        
        logger.info(f"Web search query: {query}, deep_web: {deep_web}")
        
        results = await web_scraper.search(query, use_tor=deep_web)
        
        return {
            "success": True,
            "data": results,
            "query": query,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Error in web search: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/ai/decide")
async def ai_decision(decision_data: Dict[str, Any]):
    """Let AI make autonomous decisions"""
    try:
        context = decision_data.get("context", "")
        options = decision_data.get("options", [])
        constraints = decision_data.get("constraints", [])
        
        if not context:
            raise HTTPException(status_code=400, detail="Context required for decision making")
        
        logger.info(f"AI decision request: {context}")
        
        decision = await ai_engine.make_decision(context, options, constraints)
        
        return {
            "success": True,
            "decision": decision,
            "context": context,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Error in AI decision making: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/ai/selfdevelop")
async def self_develop_endpoint(data: Dict[str, Any]):
    """Self-development analysis endpoint"""
    context = data.get("context", "")
    if not context:
        raise HTTPException(status_code=400, detail="Context is required for self-development analysis")
    try:
        suggestions = await ai_engine.self_develop(context)
        return {
            "success": True,
            "suggestions": suggestions,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Error in self_develop endpoint: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/security/scan/network")
async def run_network_scan(target: str = "127.0.0.1"):
    """Run Nmap network scan"""
    try:
        if not security_monitor.nmap:
            raise HTTPException(status_code=503, detail="Nmap scanning not available")
        security_monitor.nmap.scan(target, arguments='-sS -T4')
        report = security_monitor.nmap.csv()
        return {
            "success": True,
            "target": target,
            "report": report,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Error running network scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/security/scan/web")
async def run_web_scan(target_url: str):
    """Run Nikto web vulnerability scan (placeholder)"""
    try:
        # Placeholder: Implement nikto scan via subprocess or python wrapper
        # For now, return dummy response
        return {
            "success": True,
            "target_url": target_url,
            "report": "Nikto scan results placeholder",
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Error running web scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.websocket("/ws/voice")
async def websocket_voice(websocket: WebSocket):
    """WebSocket for real-time voice communication"""
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            message_data = json.loads(data)
            
            if message_data.get("type") == "voice_command":
                command = message_data.get("command", "")
                response = await ai_engine.process_command(command)
                
                await manager.send_personal_message(json.dumps({
                    "type": "voice_response",
                    "response": response,
                    "timestamp": datetime.now().isoformat()
                }), websocket)
                
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        manager.disconnect(websocket)

@app.websocket("/ws/system")
async def websocket_system(websocket: WebSocket):
    """WebSocket for real-time system updates"""
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive and send periodic updates
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"System WebSocket error: {e}")
        manager.disconnect(websocket)

@app.websocket("/ws/security")
async def websocket_security(websocket: WebSocket):
    """WebSocket for real-time security alerts"""
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"Security WebSocket error: {e}")
        manager.disconnect(websocket)

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8001,
        reload=True,
        log_level="info"
    )
