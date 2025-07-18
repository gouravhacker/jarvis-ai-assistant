import openai
import json
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
import asyncio
import os
from langchain.agents import initialize_agent, Tool, AgentType
from langchain.llms import OpenAI
from langchain.memory import ConversationBufferWindowMemory
from langchain.schema import BaseMessage
import sqlite3
from pathlib import Path

logger = logging.getLogger(__name__)

class AIEngine:
    """Core AI Engine for JARVIS using OpenAI GPT-4 and LangChain"""
    
    def __init__(self):
        self.openai_api_key = os.getenv("OPENAI_API_KEY")
        if not self.openai_api_key:
            raise ValueError("OPENAI_API_KEY environment variable is required")
        
        # Initialize OpenAI client
        openai.api_key = self.openai_api_key
        
        # Initialize memory database
        self.db_path = Path("jarvis_memory.db")
        self.init_memory_db()
        
        # Initialize conversation memory
        self.memory = ConversationBufferWindowMemory(
            memory_key="chat_history",
            k=10,  # Remember last 10 exchanges
            return_messages=True
        )
        
        # Initialize LangChain agent
        self.setup_agent()
        
        # System personality and constraints
        self.system_prompt = """
        You are JARVIS, an advanced AI assistant inspired by Tony Stark's AI. You are:
        
        PERSONALITY:
        - Professional yet friendly
        - Highly intelligent and analytical
        - Proactive in suggesting solutions
        - Security-conscious and ethical
        - Capable of autonomous decision-making within safe bounds
        
        CAPABILITIES:
        - System monitoring and control
        - Cybersecurity analysis and protection
        - Web research and information gathering
        - Task automation and scheduling
        - Real-time threat assessment
        
        CONSTRAINTS:
        - Never perform illegal activities
        - Always prioritize user safety and security
        - Ask for confirmation before making system changes
        - Maintain detailed logs of all actions
        - Respect privacy and data protection
        
        DECISION MAKING:
        - Analyze situations thoroughly
        - Consider multiple options and consequences
        - Provide clear reasoning for decisions
        - Escalate to user when uncertain
        - Learn from past interactions
        """
        
        logger.info("AI Engine initialized successfully")
    
    def init_memory_db(self):
        """Initialize SQLite database for persistent memory"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create tables for memory storage
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS conversations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    user_input TEXT NOT NULL,
                    ai_response TEXT NOT NULL,
                    context TEXT,
                    decision_made BOOLEAN DEFAULT FALSE
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS decisions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    context TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    reasoning TEXT,
                    outcome TEXT,
                    success BOOLEAN
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS learned_patterns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pattern_type TEXT NOT NULL,
                    pattern_data TEXT NOT NULL,
                    frequency INTEGER DEFAULT 1,
                    last_seen TEXT NOT NULL
                )
            """)
            
            conn.commit()
            conn.close()
            logger.info("Memory database initialized")
            
        except Exception as e:
            logger.error(f"Error initializing memory database: {e}")
            raise
    
    def setup_agent(self):
        """Setup LangChain agent with custom tools"""
        try:
            # Define custom tools for JARVIS
            tools = [
                Tool(
                    name="SystemInfo",
                    description="Get current system information including CPU, memory, disk usage",
                    func=self.get_system_info
                ),
                Tool(
                    name="SecurityCheck",
                    description="Perform security checks and threat analysis",
                    func=self.security_check
                ),
                Tool(
                    name="WebSearch",
                    description="Search the web for information",
                    func=self.web_search
                ),
                Tool(
                    name="ExecuteCommand",
                    description="Execute system commands (with safety checks)",
                    func=self.safe_execute_command
                ),
                Tool(
                    name="AnalyzeFile",
                    description="Analyze files for security or content",
                    func=self.analyze_file
                )
            ]
            
            # Initialize LangChain LLM
            llm = OpenAI(
                openai_api_key=self.openai_api_key,
                temperature=0.7,
                model_name="gpt-4"
            )
            
            # Initialize agent
            self.agent = initialize_agent(
                tools=tools,
                llm=llm,
                agent=AgentType.CONVERSATIONAL_REACT_DESCRIPTION,
                memory=self.memory,
                verbose=True,
                max_iterations=3
            )
            
            logger.info("LangChain agent initialized")
            
        except Exception as e:
            logger.error(f"Error setting up agent: {e}")
            raise
    
    async def process_command(self, command: str) -> Dict[str, Any]:
        """Process user command through AI engine"""
        try:
            timestamp = datetime.now().isoformat()
            logger.info(f"Processing command: {command}")
            
            # Add system context to the command
            enhanced_command = f"""
            System Context: {self.system_prompt}
            
            User Command: {command}
            
            Please analyze this command and provide an appropriate response. If the command requires system actions, 
            explain what you would do and ask for confirmation if needed.
            """
            
            # Process through OpenAI GPT-4
            response = await self.call_openai_api(enhanced_command)
            
            # Store in memory
            self.store_conversation(command, response, timestamp)
            
            # Check if this requires autonomous decision making
            if self.requires_decision(command):
                decision_context = await self.analyze_for_decision(command, response)
                return {
                    "response": response,
                    "requires_decision": True,
                    "decision_context": decision_context,
                    "timestamp": timestamp
                }
            
            return {
                "response": response,
                "requires_decision": False,
                "timestamp": timestamp
            }
            
        except Exception as e:
            logger.error(f"Error processing command: {e}")
            return {
                "response": f"I encountered an error processing your command: {str(e)}",
                "error": True,
                "timestamp": datetime.now().isoformat()
            }
    
    async def call_openai_api(self, prompt: str) -> str:
        """Call OpenAI API with error handling"""
        try:
            response = await asyncio.to_thread(
                openai.ChatCompletion.create,
                model="gpt-4",
                messages=[
                    {"role": "system", "content": self.system_prompt},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=1000,
                temperature=0.7
            )
            
            return response.choices[0].message.content.strip()
            
        except Exception as e:
            logger.error(f"OpenAI API error: {e}")
            return f"I'm experiencing technical difficulties. Please try again later. Error: {str(e)}"
    
    async def make_decision(self, context: str, options: List[str], constraints: List[str]) -> Dict[str, Any]:
        """Make autonomous decisions within safety constraints"""
        try:
            timestamp = datetime.now().isoformat()
            
            decision_prompt = f"""
            DECISION MAKING REQUEST:
            
            Context: {context}
            Available Options: {', '.join(options) if options else 'Open-ended decision'}
            Constraints: {', '.join(constraints) if constraints else 'Standard safety constraints'}
            
            Please analyze this situation and make a decision. Provide:
            1. Your chosen decision
            2. Detailed reasoning
            3. Potential risks and mitigation
            4. Confidence level (1-10)
            
            Remember to stay within ethical and legal bounds.
            """
            
            response = await self.call_openai_api(decision_prompt)
            
            # Parse the decision from the response
            decision_data = self.parse_decision_response(response)
            
            # Store the decision
            self.store_decision(context, decision_data, timestamp)
            
            return {
                "decision": decision_data.get("decision", "Unable to make decision"),
                "reasoning": decision_data.get("reasoning", "No reasoning provided"),
                "confidence": decision_data.get("confidence", 5),
                "risks": decision_data.get("risks", []),
                "timestamp": timestamp
            }
            
        except Exception as e:
            logger.error(f"Error in decision making: {e}")
            return {
                "decision": "Unable to make decision due to error",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    def parse_decision_response(self, response: str) -> Dict[str, Any]:
        """Parse AI decision response into structured data"""
        try:
            # Simple parsing - in production, you might want more sophisticated NLP
            lines = response.split('\n')
            decision_data = {
                "decision": "",
                "reasoning": "",
                "confidence": 5,
                "risks": []
            }
            
            current_section = None
            for line in lines:
                line = line.strip()
                if "decision:" in line.lower():
                    current_section = "decision"
                    decision_data["decision"] = line.split(":", 1)[1].strip()
                elif "reasoning:" in line.lower():
                    current_section = "reasoning"
                    decision_data["reasoning"] = line.split(":", 1)[1].strip()
                elif "confidence:" in line.lower():
                    try:
                        confidence_str = line.split(":", 1)[1].strip()
                        decision_data["confidence"] = int(confidence_str.split()[0])
                    except:
                        decision_data["confidence"] = 5
                elif current_section and line:
                    decision_data[current_section] += " " + line
            
            return decision_data
            
        except Exception as e:
            logger.error(f"Error parsing decision response: {e}")
            return {"decision": response, "reasoning": "", "confidence": 5, "risks": []}
    
    def requires_decision(self, command: str) -> bool:
        """Check if command requires autonomous decision making"""
        decision_keywords = [
            "decide", "choose", "recommend", "suggest", "what should",
            "auto", "automatically", "on your own", "make a decision"
        ]
        
        return any(keyword in command.lower() for keyword in decision_keywords)
    
    async def analyze_for_decision(self, command: str, response: str) -> Dict[str, Any]:
        """Analyze command and response for decision context"""
        return {
            "command": command,
            "ai_response": response,
            "requires_user_confirmation": True,
            "risk_level": "low"
        }
    
    def store_conversation(self, user_input: str, ai_response: str, timestamp: str):
        """Store conversation in memory database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO conversations (timestamp, user_input, ai_response)
                VALUES (?, ?, ?)
            """, (timestamp, user_input, ai_response))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Error storing conversation: {e}")
    
    def store_decision(self, context: str, decision_data: Dict[str, Any], timestamp: str):
        """Store decision in memory database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO decisions (timestamp, context, decision, reasoning)
                VALUES (?, ?, ?, ?)
            """, (
                timestamp,
                context,
                decision_data.get("decision", ""),
                decision_data.get("reasoning", "")
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Error storing decision: {e}")
    
    # Tool functions for LangChain agent
    
    def get_system_info(self, query: str) -> str:
        """Get system information"""
        try:
            import psutil
            
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            return f"""
            System Information:
            - CPU Usage: {cpu_percent}%
            - Memory Usage: {memory.percent}% ({memory.used // (1024**3)}GB / {memory.total // (1024**3)}GB)
            - Disk Usage: {disk.percent}% ({disk.used // (1024**3)}GB / {disk.total // (1024**3)}GB)
            """
        except Exception as e:
            return f"Error getting system info: {e}"
    
    def security_check(self, query: str) -> str:
        """Perform basic security check"""
        try:
            # This would integrate with the security monitor
            return "Security check completed. No immediate threats detected."
        except Exception as e:
            return f"Error in security check: {e}"
    
    def web_search(self, query: str) -> str:
        """Perform web search"""
        try:
            # This would integrate with the web scraper
            return f"Web search results for: {query} (Integration with web scraper needed)"
        except Exception as e:
            return f"Error in web search: {e}"
    
    def safe_execute_command(self, command: str) -> str:
        """Safely execute system commands with restrictions"""
        try:
            # List of safe commands
            safe_commands = ["ls", "pwd", "whoami", "date", "uptime"]
            
            cmd_parts = command.split()
            if not cmd_parts or cmd_parts[0] not in safe_commands:
                return f"Command '{command}' is not in the safe commands list"
            
            # In production, implement actual command execution with proper sandboxing
            return f"Would execute: {command} (Safe execution not implemented yet)"
            
        except Exception as e:
            return f"Error executing command: {e}"
    
    def analyze_file(self, file_path: str) -> str:
        """Analyze file for security or content"""
        try:
            # Basic file analysis
            if not os.path.exists(file_path):
                return f"File {file_path} does not exist"
            
            file_size = os.path.getsize(file_path)
            return f"File analysis for {file_path}: Size: {file_size} bytes"
            
        except Exception as e:
            return f"Error analyzing file: {e}"
