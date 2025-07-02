import requests
import json
import time
import hashlib
import datetime
from typing import Optional, List

class SmartCTFSolver:
    def __init__(self, base_url: str, session_cookie: str):
        self.base_url = base_url
        self.session_cookie = session_cookie
        
    def create_session(self) -> requests.Session:
        session = requests.Session()
        session.headers.update({
            'Content-Type': 'application/json',
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0',
            'Accept': '*/*',
            'Origin': self.base_url,
        })
        session.cookies.set('connect.sid', self.session_cookie)
        return session
    
    def analyze_graphql_schema(self) -> dict:
        """Try to get GraphQL schema information"""
        print("🔍 Analyzing GraphQL schema...")
        session = self.create_session()
        
        # Try introspection query
        introspection_query = """
        query IntrospectionQuery {
            __schema {
                queryType { name }
                mutationType { name }
                subscriptionType { name }
                types {
                    ...FullType
                }
            }
        }
        fragment FullType on __Type {
            kind
            name
            description
            fields(includeDeprecated: true) {
                name
                description
                args {
                    ...InputValue
                }
                type {
                    ...TypeRef
                }
            }
        }
        fragment InputValue on __InputValue {
            name
            description
            type { ...TypeRef }
            defaultValue
        }
        fragment TypeRef on __Type {
            kind
            name
            ofType {
                kind
                name
                ofType {
                    kind
                    name
                }
            }
        }
        """
        
        try:
            response = session.post(
                f"{self.base_url}/graphql",
                json={"query": introspection_query},
                timeout=10
            )
            
            if response.ok:
                data = response.json()
                if 'data' in data and '__schema' in data['data']:
                    print("✅ GraphQL introspection successful!")
                    return data['data']['__schema']
                else:
                    print("❌ Introspection disabled or failed")
            else:
                print(f"❌ HTTP {response.status_code}")
        except Exception as e:
            print(f"❌ Error: {e}")
        
        return {}
    
    def test_graphql_vulnerabilities(self) -> List[str]:
        """Test for common GraphQL vulnerabilities"""
        print("🔍 Testing GraphQL vulnerabilities...")
        session = self.create_session()
        findings = []
        
        # Test 1: Query depth/complexity
        deep_query = """
        query {
            guessNumber(number: 1) {
                correct
                message
                flag
            }
        }
        """
        
        # Test 2: Try to get hints from error messages
        malformed_queries = [
            "query { guessNumber }",  # Missing argument
            "query { guessNumber(number: \"abc\") { correct } }",  # Wrong type
            "query { guessNumber(number: -1) { correct } }",  # Invalid range
            "query { guessNumber(number: 100001) { correct } }",  # Out of range
        ]
        
        for i, query in enumerate(malformed_queries):
            try:
                response = session.post(
                    f"{self.base_url}/graphql",
                    json={"query": query},
                    timeout=10
                )
                
                if response.ok:
                    data = response.json()
                    if 'errors' in data:
                        error_msg = data['errors'][0]['message']
                        print(f"Test {i+1}: {error_msg}")
                        findings.append(f"Error {i+1}: {error_msg}")
                
                time.sleep(1)  # Avoid rate limiting
            except Exception as e:
                print(f"Test {i+1} failed: {e}")
        
        return findings
    
    def analyze_patterns(self) -> Optional[int]:
        """Look for patterns in the target number"""
        print("🔍 Analyzing potential patterns...")
        
        # Pattern 1: Time-based
        now = datetime.datetime.now()
        time_patterns = [
            now.hour * 100 + now.minute,  # HHMM
            now.day * 100 + now.month,    # DDMM
            now.year,                     # YYYY
            int(now.timestamp()) % 100000, # Unix timestamp mod
            now.hour * 1000 + now.minute * 10 + now.second // 10,  # HHMMS
        ]
        
        print("Time-based patterns to try:")
        for pattern in time_patterns:
            if 1 <= pattern <= 100000:
                print(f"  - {pattern}")
        
        # Pattern 2: Hash-based (session cookie)
        cookie_hash = hashlib.md5(self.session_cookie.encode()).hexdigest()
        hash_patterns = [
            int(cookie_hash[:5], 16) % 100000,  # First 5 hex chars
            int(cookie_hash[-5:], 16) % 100000,  # Last 5 hex chars
            sum(ord(c) for c in cookie_hash) % 100000,  # Sum of ASCII values
        ]
        
        print("Hash-based patterns to try:")
        for pattern in hash_patterns:
            print(f"  - {pattern}")
        
        return time_patterns + hash_patterns
    
    def try_smart_guesses(self) -> Optional[str]:
        """Try smart guesses based on patterns and analysis"""
        print("🎯 Trying smart guesses...")
        session = self.create_session()
        
        # Get patterns to try
        patterns = self.analyze_patterns()
        
        # Add some CTF-common numbers
        ctf_numbers = [
            1337, 31337, 42, 69, 420, 666, 777, 1234, 12345,
            2023, 2024, 1000, 10000, 99999, 12321, 54321
        ]
        
        all_guesses = list(set(patterns + ctf_numbers))
        all_guesses = [n for n in all_guesses if 1 <= n <= 100000]
        
        print(f"Trying {len(all_guesses)} smart guesses...")
        
        for i, number in enumerate(all_guesses):
            print(f"[{i+1}/{len(all_guesses)}] Trying {number}")
            
            query = f"""
                query {{
                    guessNumber(number: {number}) {{
                        correct
                        message
                        flag
                    }}
                }}
            """
            
            try:
                response = session.post(
                    f"{self.base_url}/graphql",
                    json={"query": query},
                    timeout=10
                )
                
                if response.status_code == 429:
                    print("Rate limited, waiting 5s...")
                    time.sleep(5)
                    continue
                
                if response.ok:
                    data = response.json()
                    if 'data' in data and data['data']['guessNumber']['correct']:
                        flag = data['data']['guessNumber']['flag']
                        print(f"🎉 SUCCESS! Number: {number}, Flag: {flag}")
                        return flag
                    else:
                        print(f"❌ {number}: Incorrect")
                
                time.sleep(2)  # Conservative delay
                
            except Exception as e:
                print(f"Error with {number}: {e}")
        
        return None
    
    def check_for_hints(self) -> List[str]:
        """Look for hints in the page source or responses"""
        print("🔍 Looking for hints...")
        session = self.create_session()
        hints = []
        
        try:
            # Get the main page
            response = session.get(self.base_url)
            if response.ok:
                content = response.text.lower()
                
                # Look for hidden comments or hints
                if '<!--' in content:
                    print("Found HTML comments - check manually!")
                    hints.append("HTML comments found")
                
                # Look for suspicious strings
                suspicious = ['hint', 'answer', 'secret', 'flag', 'number']
                for word in suspicious:
                    if word in content and word not in ['number', 'flag']:  # Exclude obvious ones
                        hints.append(f"Found '{word}' in page source")
                
        except Exception as e:
            print(f"Error checking page: {e}")
        
        return hints

def main():
    BASE_URL = "https://abfb9883.bsidesmumbai.in"
    SESSION_COOKIE = "s%3A8H3YfNRzjXBOq0CActnOAdFX_ogyTFuJ.ch4gTVPPtSaCs%2Fevvr3VQ8j1J0%2FLi2sJHydDsr9A99Y"
    
    solver = SmartCTFSolver(BASE_URL, SESSION_COOKIE)
    
    print("🧠 Smart CTF Solver")
    print("=" * 50)
    
    # Step 1: Analyze GraphQL
    schema = solver.analyze_graphql_schema()
    
    # Step 2: Test vulnerabilities
    vulns = solver.test_graphql_vulnerabilities()
    
    # Step 3: Look for hints
    hints = solver.check_for_hints()
    if hints:
        print("🔍 Hints found:")
        for hint in hints:
            print(f"  - {hint}")
    
    # Step 4: Try smart guesses
    flag = solver.try_smart_guesses()
    
    if flag:
        print(f"\n🏆 SUCCESS! Flag: {flag}")
    else:
        print("\n❌ Smart approaches didn't work")
        print("\n💡 Next steps:")
        print("1. Check the page source manually for hidden hints")
        print("2. Try different session cookies if you have them")
        print("3. Look for patterns in the challenge description")
        print("4. Consider if the number changes based on time/date")
        print("5. Check if there are other endpoints or parameters")

if __name__ == "__main__":
    main()
