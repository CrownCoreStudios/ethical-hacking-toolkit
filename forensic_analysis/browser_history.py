#!/usr/bin/env python3
"""Browser History Analyzer - Extracts browsing history from Chrome, Firefox, and Edge."""

import os
import sqlite3
import json
import glob
from typing import List, Dict, Any
from pathlib import Path

class BrowserHistory:
    """Extract and analyze browser history."""
    
    @staticmethod
    def get_chrome_history() -> List[Dict[str, Any]]:
        """Extract Chrome/Chromium history."""
        entries = []
        paths = [
            '~/.config/google-chrome/Default/History',
            '~/AppData/Local/Google/Chrome/User Data/Default/History',
            '~/Library/Application Support/Google/Chrome/Default/History'
        ]
        
        for path in map(os.path.expanduser, paths):
            if os.path.isfile(path):
                try:
                    conn = sqlite3.connect(f'file:{path}?immutable=1', uri=True)
                    cursor = conn.cursor()
                    cursor.execute("""
                        SELECT url, title, 
                               datetime((last_visit_time/1000000)-11644473600, 'unixepoch', 'localtime')
                        FROM urls 
                        ORDER BY last_visit_time DESC
                        LIMIT 1000
                    """)
                    entries.extend({
                        'url': row[0],
                        'title': row[1] or 'No Title',
                        'last_visit': row[2],
                        'browser': 'Chrome'
                    } for row in cursor.fetchall())
                    conn.close()
                except Exception as e:
                    print(f"Error reading {path}: {e}")
        return entries
    
    @staticmethod
    def get_firefox_history() -> List[Dict[str, Any]]:
        """Extract Firefox history."""
        entries = []
        profiles = glob.glob(os.path.expanduser('~/.mozilla/firefox/*.default*/places.sqlite'))
        profiles.extend(glob.glob(os.path.expanduser('~/AppData/Roaming/Mozilla/Firefox/Profiles/*.default*/places.sqlite')))
        
        for profile in profiles:
            try:
                conn = sqlite3.connect(f'file:{profile}?immutable=1', uri=True)
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT url, title, 
                           datetime(last_visit_date/1000000, 'unixepoch', 'localtime')
                    FROM moz_places
                    ORDER BY last_visit_date DESC
                    LIMIT 1000
                """)
                entries.extend({
                    'url': row[0],
                    'title': row[1] or 'No Title',
                    'last_visit': row[2],
                    'browser': 'Firefox'
                } for row in cursor.fetchall())
                conn.close()
            except Exception as e:
                print(f"Error reading {profile}: {e}")
        return entries
    
    @classmethod
    def get_all_history(cls) -> List[Dict[str, Any]]:
        """Get history from all browsers."""
        history = []
        history.extend(cls.get_chrome_history())
        history.extend(cls.get_firefox_history())
        return sorted(history, key=lambda x: x.get('last_visit', ''), reverse=True)

def main():
    """Main function."""
    print("Extracting browser history...")
    history = BrowserHistory.get_all_history()
    
    # Save to JSON
    output_file = 'browser_history.json'
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(history, f, indent=2)
    
    print(f"\nFound {len(history)} history entries")
    print(f"Results saved to {output_file}")
    
    # Print summary
    print("\nRecent browsing history:")
    for entry in history[:5]:
        print(f"{entry['last_visit']} - {entry['browser']}: {entry['title'][:60]}...")

if __name__ == "__main__":
    main()
