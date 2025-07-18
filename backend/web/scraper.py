import asyncio
import aiohttp
import requests
from bs4 import BeautifulSoup
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
import json
import re
import time
from urllib.parse import urljoin, urlparse
import hashlib
import os
from pathlib import Path

logger = logging.getLogger(__name__)

class WebScraper:
    """Advanced web scraping module with Tor support for JARVIS"""
    
    def __init__(self):
        self.session = None
        self.tor_session = None
        self.rate_limit_delay = 1  # seconds between requests
        self.max_retries = 3
        self.timeout = 30
        
        # User agents for rotation
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        ]
        
        # Initialize sessions
        self.init_sessions()
        
        logger.info("Web Scraper initialized")
    
    def init_sessions(self):
        """Initialize HTTP sessions"""
        try:
            # Regular session
            self.session = requests.Session()
            self.session.headers.update({
                'User-Agent': self.user_agents[0],
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            })
            
            # Tor session (if Tor is available)
            self.tor_session = requests.Session()
            self.tor_session.proxies = {
                'http': 'socks5://127.0.0.1:9050',
                'https': 'socks5://127.0.0.1:9050'
            }
            self.tor_session.headers.update(self.session.headers)
            
        except Exception as e:
            logger.error(f"Error initializing sessions: {e}")
    
    async def search(self, query: str, use_tor: bool = False, max_results: int = 10) -> Dict[str, Any]:
        """Perform web search using multiple search engines"""
        try:
            logger.info(f"Web search: {query}, use_tor: {use_tor}")
            
            results = {
                "query": query,
                "timestamp": datetime.now().isoformat(),
                "use_tor": use_tor,
                "results": [],
                "sources": []
            }
            
            # Search multiple engines
            search_engines = [
                {"name": "DuckDuckGo", "func": self.search_duckduckgo},
                {"name": "Bing", "func": self.search_bing},
            ]
            
            if not use_tor:
                search_engines.append({"name": "Google", "func": self.search_google})
            
            for engine in search_engines:
                try:
                    engine_results = await engine["func"](query, use_tor, max_results // len(search_engines))
                    results["results"].extend(engine_results)
                    results["sources"].append(engine["name"])
                    
                    # Rate limiting
                    await asyncio.sleep(self.rate_limit_delay)
                    
                except Exception as e:
                    logger.error(f"Error searching {engine['name']}: {e}")
                    continue
            
            # Remove duplicates and limit results
            results["results"] = self.deduplicate_results(results["results"])[:max_results]
            
            # Get additional information for top results
            if results["results"]:
                enhanced_results = await self.enhance_search_results(results["results"][:5], use_tor)
                results["enhanced_results"] = enhanced_results
            
            return results
            
        except Exception as e:
            logger.error(f"Error in web search: {e}")
            return {
                "query": query,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    async def search_duckduckgo(self, query: str, use_tor: bool, max_results: int) -> List[Dict[str, Any]]:
        """Search using DuckDuckGo"""
        results = []
        
        try:
            session = self.tor_session if use_tor else self.session
            
            # DuckDuckGo instant answer API
            url = "https://api.duckduckgo.com/"
            params = {
                'q': query,
                'format': 'json',
                'no_html': '1',
                'skip_disambig': '1'
            }
            
            response = session.get(url, params=params, timeout=self.timeout)
            response.raise_for_status()
            
            data = response.json()
            
            # Parse results
            if data.get('AbstractText'):
                results.append({
                    "title": data.get('Heading', query),
                    "url": data.get('AbstractURL', ''),
                    "snippet": data.get('AbstractText', ''),
                    "source": "DuckDuckGo"
                })
            
            # Related topics
            for topic in data.get('RelatedTopics', [])[:max_results-1]:
                if isinstance(topic, dict) and 'Text' in topic:
                    results.append({
                        "title": topic.get('Text', '').split(' - ')[0],
                        "url": topic.get('FirstURL', ''),
                        "snippet": topic.get('Text', ''),
                        "source": "DuckDuckGo"
                    })
            
        except Exception as e:
            logger.error(f"Error in DuckDuckGo search: {e}")
        
        return results
    
    async def search_bing(self, query: str, use_tor: bool, max_results: int) -> List[Dict[str, Any]]:
        """Search using Bing (web scraping)"""
        results = []
        
        try:
            session = self.tor_session if use_tor else self.session
            
            url = "https://www.bing.com/search"
            params = {'q': query, 'count': max_results}
            
            response = session.get(url, params=params, timeout=self.timeout)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Parse search results
            for result in soup.find_all('li', class_='b_algo')[:max_results]:
                title_elem = result.find('h2')
                if title_elem:
                    title = title_elem.get_text(strip=True)
                    link_elem = title_elem.find('a')
                    url = link_elem.get('href') if link_elem else ''
                    
                    snippet_elem = result.find('p')
                    snippet = snippet_elem.get_text(strip=True) if snippet_elem else ''
                    
                    results.append({
                        "title": title,
                        "url": url,
                        "snippet": snippet,
                        "source": "Bing"
                    })
            
        except Exception as e:
            logger.error(f"Error in Bing search: {e}")
        
        return results
    
    async def search_google(self, query: str, use_tor: bool, max_results: int) -> List[Dict[str, Any]]:
        """Search using Google (web scraping - use carefully due to rate limits)"""
        results = []
        
        try:
            session = self.tor_session if use_tor else self.session
            
            url = "https://www.google.com/search"
            params = {'q': query, 'num': max_results}
            
            # Rotate user agent
            session.headers['User-Agent'] = self.user_agents[hash(query) % len(self.user_agents)]
            
            response = session.get(url, params=params, timeout=self.timeout)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Parse search results
            for result in soup.find_all('div', class_='g')[:max_results]:
                title_elem = result.find('h3')
                if title_elem:
                    title = title_elem.get_text(strip=True)
                    
                    link_elem = result.find('a')
                    url = link_elem.get('href') if link_elem else ''
                    
                    snippet_elem = result.find('span', class_='aCOpRe')
                    if not snippet_elem:
                        snippet_elem = result.find('div', class_='s')
                    snippet = snippet_elem.get_text(strip=True) if snippet_elem else ''
                    
                    results.append({
                        "title": title,
                        "url": url,
                        "snippet": snippet,
                        "source": "Google"
                    })
            
        except Exception as e:
            logger.error(f"Error in Google search: {e}")
        
        return results
    
    def deduplicate_results(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate search results"""
        seen_urls = set()
        unique_results = []
        
        for result in results:
            url = result.get('url', '')
            if url and url not in seen_urls:
                seen_urls.add(url)
                unique_results.append(result)
        
        return unique_results
    
    async def enhance_search_results(self, results: List[Dict[str, Any]], use_tor: bool) -> List[Dict[str, Any]]:
        """Enhance search results with additional metadata"""
        enhanced = []
        
        for result in results:
            try:
                enhanced_result = result.copy()
                
                # Get page metadata
                metadata = await self.get_page_metadata(result.get('url', ''), use_tor)
                enhanced_result.update(metadata)
                
                enhanced.append(enhanced_result)
                
                # Rate limiting
                await asyncio.sleep(self.rate_limit_delay)
                
            except Exception as e:
                logger.error(f"Error enhancing result: {e}")
                enhanced.append(result)
        
        return enhanced
    
    async def get_page_metadata(self, url: str, use_tor: bool) -> Dict[str, Any]:
        """Get metadata from a web page"""
        metadata = {
            "page_title": "",
            "description": "",
            "keywords": [],
            "content_length": 0,
            "last_modified": "",
            "content_type": ""
        }
        
        try:
            if not url:
                return metadata
            
            session = self.tor_session if use_tor else self.session
            
            response = session.get(url, timeout=self.timeout)
            response.raise_for_status()
            
            # Basic metadata
            metadata["content_length"] = len(response.content)
            metadata["content_type"] = response.headers.get('content-type', '')
            metadata["last_modified"] = response.headers.get('last-modified', '')
            
            # Parse HTML metadata
            if 'text/html' in metadata["content_type"]:
                soup = BeautifulSoup(response.content, 'html.parser')
                
                # Page title
                title_elem = soup.find('title')
                if title_elem:
                    metadata["page_title"] = title_elem.get_text(strip=True)
                
                # Meta description
                desc_elem = soup.find('meta', attrs={'name': 'description'})
                if desc_elem:
                    metadata["description"] = desc_elem.get('content', '')
                
                # Meta keywords
                keywords_elem = soup.find('meta', attrs={'name': 'keywords'})
                if keywords_elem:
                    keywords = keywords_elem.get('content', '')
                    metadata["keywords"] = [k.strip() for k in keywords.split(',')]
        
        except Exception as e:
            logger.error(f"Error getting page metadata for {url}: {e}")
        
        return metadata
    
    async def scrape_page_content(self, url: str, use_tor: bool = False) -> Dict[str, Any]:
        """Scrape full content from a web page"""
        try:
            session = self.tor_session if use_tor else self.session
            
            response = session.get(url, timeout=self.timeout)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Remove script and style elements
            for script in soup(["script", "style"]):
                script.decompose()
            
            # Extract text content
            text_content = soup.get_text()
            
            # Clean up text
            lines = (line.strip() for line in text_content.splitlines())
            chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
            text_content = ' '.join(chunk for chunk in chunks if chunk)
            
            # Extract links
            links = []
            for link in soup.find_all('a', href=True):
                absolute_url = urljoin(url, link['href'])
                links.append({
                    "text": link.get_text(strip=True),
                    "url": absolute_url
                })
            
            # Extract images
            images = []
            for img in soup.find_all('img', src=True):
                absolute_url = urljoin(url, img['src'])
                images.append({
                    "alt": img.get('alt', ''),
                    "url": absolute_url
                })
            
            return {
                "url": url,
                "title": soup.find('title').get_text(strip=True) if soup.find('title') else '',
                "text_content": text_content,
                "word_count": len(text_content.split()),
                "links": links[:50],  # Limit to first 50 links
                "images": images[:20],  # Limit to first 20 images
                "scraped_at": datetime.now().isoformat(),
                "use_tor": use_tor
            }
            
        except Exception as e:
            logger.error(f"Error scraping page content from {url}: {e}")
            return {
                "url": url,
                "error": str(e),
                "scraped_at": datetime.now().isoformat()
            }
    
    async def get_real_time_info(self, info_type: str) -> Dict[str, Any]:
        """Get real-time information from various sources"""
        try:
            if info_type == "news":
                return await self.get_latest_news()
            elif info_type == "weather":
                return await self.get_weather_info()
            elif info_type == "crypto":
                return await self.get_crypto_prices()
            elif info_type == "stocks":
                return await self.get_stock_info()
            else:
                return {"error": f"Unknown info type: {info_type}"}
                
        except Exception as e:
            logger.error(f"Error getting real-time info: {e}")
            return {"error": str(e)}
    
    async def get_latest_news(self) -> Dict[str, Any]:
        """Get latest news headlines"""
        try:
            # Using RSS feeds for news
            news_sources = [
                {"name": "BBC", "url": "http://feeds.bbci.co.uk/news/rss.xml"},
                {"name": "Reuters", "url": "http://feeds.reuters.com/reuters/topNews"},
                {"name": "CNN", "url": "http://rss.cnn.com/rss/edition.rss"}
            ]
            
            all_news = []
            
            for source in news_sources:
                try:
                    response = self.session.get(source["url"], timeout=self.timeout)
                    response.raise_for_status()
                    
                    soup = BeautifulSoup(response.content, 'xml')
                    
                    for item in soup.find_all('item')[:5]:  # Top 5 from each source
                        title = item.find('title')
                        link = item.find('link')
                        description = item.find('description')
                        pub_date = item.find('pubDate')
                        
                        all_news.append({
                            "source": source["name"],
                            "title": title.get_text(strip=True) if title else '',
                            "url": link.get_text(strip=True) if link else '',
                            "description": description.get_text(strip=True) if description else '',
                            "published": pub_date.get_text(strip=True) if pub_date else ''
                        })
                    
                except Exception as e:
                    logger.error(f"Error getting news from {source['name']}: {e}")
                    continue
            
            return {
                "type": "news",
                "articles": all_news,
                "retrieved_at": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error getting latest news: {e}")
            return {"error": str(e)}
    
    async def get_weather_info(self, location: str = "New York") -> Dict[str, Any]:
        """Get weather information (placeholder - would need API key)"""
        try:
            # This would integrate with a weather API like OpenWeatherMap
            # For now, return placeholder data
            return {
                "type": "weather",
                "location": location,
                "message": "Weather API integration needed - requires API key",
                "retrieved_at": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error getting weather info: {e}")
            return {"error": str(e)}
    
    async def get_crypto_prices(self) -> Dict[str, Any]:
        """Get cryptocurrency prices"""
        try:
            # Using CoinGecko API (free, no API key required)
            url = "https://api.coingecko.com/api/v3/simple/price"
            params = {
                'ids': 'bitcoin,ethereum,cardano,polkadot,chainlink',
                'vs_currencies': 'usd',
                'include_24hr_change': 'true'
            }
            
            response = self.session.get(url, params=params, timeout=self.timeout)
            response.raise_for_status()
            
            data = response.json()
            
            return {
                "type": "crypto",
                "prices": data,
                "retrieved_at": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error getting crypto prices: {e}")
            return {"error": str(e)}
    
    async def get_stock_info(self) -> Dict[str, Any]:
        """Get stock market information (placeholder)"""
        try:
            # This would integrate with a stock API
            return {
                "type": "stocks",
                "message": "Stock API integration needed - requires API key",
                "retrieved_at": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error getting stock info: {e}")
            return {"error": str(e)}
    
    def check_tor_connection(self) -> bool:
        """Check if Tor connection is working"""
        try:
            response = self.tor_session.get('https://check.torproject.org/', timeout=10)
            return 'Congratulations' in response.text
        except:
            return False
    
    async def search_deep_web(self, query: str, max_results: int = 5) -> Dict[str, Any]:
        """Search deep web resources (legal access only)"""
        try:
            if not self.check_tor_connection():
                return {
                    "error": "Tor connection not available",
                    "message": "Deep web search requires Tor to be running on port 9050"
                }
            
            # Legal deep web resources
            deep_web_sources = [
                "https://3g2upl4pq6kufc4m.onion",  # DuckDuckGo onion
                # Add other legal .onion sites here
            ]
            
            results = []
            
            for source in deep_web_sources:
                try:
                    # Perform search on deep web source
                    # This is a simplified implementation
                    response = self.tor_session.get(source, timeout=30)
                    if response.status_code == 200:
                        results.append({
                            "source": source,
                            "status": "accessible",
                            "timestamp": datetime.now().isoformat()
                        })
                except Exception as e:
                    logger.error(f"Error accessing {source}: {e}")
                    continue
            
            return {
                "query": query,
                "deep_web_results": results,
                "warning": "Only legal deep web resources accessed",
                "retrieved_at": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error in deep web search: {e}")
            return {"error": str(e)}
    
    def __del__(self):
        """Cleanup sessions"""
        try:
            if self.session:
                self.session.close()
            if self.tor_session:
                self.tor_session.close()
        except:
            pass
