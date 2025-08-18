#!/usr/bin/env python3
"""
HTB Writeup Table Updater

This script automatically updates the HTB writeup tables in the _tabs directory
by extracting information from posts in the _posts/HTB directory.

Author: iven
Date: 2025-08-18
"""

import os
import re
import yaml
from pathlib import Path
from typing import Dict, List, Optional

class HTBTableUpdater:
    def __init__(self, base_path: str = "."):
        self.base_path = Path(base_path)
        self.posts_dir = self.base_path / "_posts" / "HTB"
        self.tabs_dir = self.base_path / "_tabs"
        
        # Difficulty mappings
        self.difficulty_dirs = {
            "Easy": "Easy",
            "Medium": "Medium", 
            "Hard": "Hard"
        }
        
        # Points mapping
        self.points_mapping = {
            "Easy": 20,
            "Medium": 30,
            "Hard": 40
        }
        
        print("🚀 HTB Writeup Table Updater initialized")
        print(f"📁 Base path: {self.base_path.absolute()}")
        print(f"📝 Posts directory: {self.posts_dir}")
        print(f"📋 Tabs directory: {self.tabs_dir}")

    def extract_machine_info(self, post_path: Path) -> Optional[Dict]:
        """Extract machine information from a post file"""
        try:
            with open(post_path, 'r', encoding='utf-8') as file:
                content = file.read()
            
            # Split front matter from content
            if not content.startswith('---'):
                return None
                
            parts = content.split('---', 2)
            if len(parts) < 3:
                return None
            
            front_matter = yaml.safe_load(parts[1])
            
            # Extract machine name from title
            title = front_matter.get('title', '')
            machine_name = self._extract_machine_name(title)
            
            if not machine_name:
                return None
            
            # Skip _pwned files (duplicates)
            if post_path.stem.endswith('_pwned'):
                return None
            
            # Only include published posts
            if not front_matter.get('published', True):
                print(f"⏸️  Skipping unpublished: {machine_name}")
                return None
            
            # Extract categories to determine difficulty
            categories = front_matter.get('categories', [])
            difficulty = None
            for cat in categories:
                if cat in ['Easy', 'Medium', 'Hard']:
                    difficulty = cat
                    break
            
            if not difficulty:
                print(f"⚠️  No difficulty found for: {machine_name}")
                return None
            
            # Extract OS from content or infer from context
            os_type = self._extract_os_type(content, categories)
            
            # Extract image path
            image_info = front_matter.get('image', {})
            if isinstance(image_info, dict):
                image_path = image_info.get('path', '')
            else:
                image_path = ''
            
            # Generate post URL (remove date prefix and extension)
            post_filename = post_path.stem
            # Remove date prefix (YYYY-MM-DD-)
            url_name = re.sub(r'^\d{4}-\d{2}-\d{2}-', '', post_filename)
            post_url = f"../posts/{url_name}"
            
            return {
                'machine_name': machine_name,
                'difficulty': difficulty,
                'os': os_type,
                'points': self.points_mapping[difficulty],
                'post_url': post_url,
                'image_path': image_path,
                'date': front_matter.get('date', ''),
                'file_path': post_path
            }
            
        except Exception as e:
            print(f"❌ Error processing {post_path}: {e}")
            return None
    
    def _extract_machine_name(self, title: str) -> Optional[str]:
        """Extract machine name from post title"""
        # Common patterns for HTB titles
        patterns = [
            r'HTB\s+([A-Za-z0-9_-]+)\s+Writeup',
            r'HTB\s+([A-Za-z0-9_-]+)\s+Walkthrough',
            r'HackTheBox\s+[:-]\s*([A-Za-z0-9_-]+)',
            r'([A-Za-z0-9_-]+)\s+Writeup',
            r'([A-Za-z0-9_-]+)\s+Walkthrough',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, title, re.IGNORECASE)
            if match:
                machine_name = match.group(1)
                # Clean up common suffixes
                machine_name = re.sub(r'\s+(Machine|Box|HTB)$', '', machine_name, flags=re.IGNORECASE)
                return machine_name.strip()
        
        return None
    
    def _extract_os_type(self, content: str, categories: List) -> str:
        """Extract OS type from content or categories"""
        # Check content for OS mentions
        content_lower = content.lower()
        
        if 'freebsd' in content_lower or 'FreeBSD' in categories:
            return 'FreeBSD'
        elif 'windows' in content_lower or 'Windows' in categories:
            return 'Windows'
        elif 'linux' in content_lower or 'Linux' in categories:
            return 'Linux'
        else:
            # Default to Linux for most HTB machines
            return 'Linux'
    
    def _format_image_path(self, image_path: str, difficulty: str, machine_name: str) -> str:
        """Format and normalize image path"""
        if not image_path:
            # Generate default path
            return f"../assets/img/{difficulty.lower()}/{machine_name}.png"
        
        # Convert relative paths to absolute from tabs perspective
        if image_path.startswith('../../assets/'):
            return image_path.replace('../../assets/', '../assets/')
        elif image_path.startswith('../assets/'):
            return image_path
        else:
            return f"../assets/{image_path}"
    
    def scan_htb_posts(self) -> Dict[str, List[Dict]]:
        """Scan all HTB posts and organize by difficulty"""
        results = {
            'Easy': [],
            'Medium': [],
            'Hard': []
        }
        
        print("\n🔍 Scanning HTB posts...")
        
        for difficulty in self.difficulty_dirs.keys():
            difficulty_dir = self.posts_dir / difficulty
            
            if not difficulty_dir.exists():
                print(f"⚠️  Directory not found: {difficulty_dir}")
                continue
            
            print(f"\n📂 Scanning {difficulty} posts...")
            
            for post_file in difficulty_dir.glob("*.md"):
                machine_info = self.extract_machine_info(post_file)
                
                if machine_info:
                    results[difficulty].append(machine_info)
                    print(f"✅ Found: {machine_info['machine_name']} ({machine_info['os']})")
                else:
                    print(f"⏭️  Skipped: {post_file.name}")
        
        # Sort by machine name
        for difficulty in results:
            results[difficulty].sort(key=lambda x: x['machine_name'].lower())
        
        return results
    
    def generate_table_content(self, machines: List[Dict], difficulty: str) -> str:
        """Generate markdown table content for a difficulty level"""
        if not machines:
            return "| No machines found | - | - | - | - |\n"
        
        table_rows = []
        
        for machine in machines:
            machine_name = machine['machine_name']
            os_type = machine['os']
            points = machine['points']
            post_url = machine['post_url']
            
            # Format image path
            image_path = self._format_image_path(
                machine['image_path'], 
                difficulty, 
                machine_name
            )
            
            # Create table row
            row = f"| {machine_name:<15} | {os_type:<7} | {points:<6} | [Click here]({post_url}) | <img src=\"{image_path}\" height=\"40px\" width=\"40px\"> |"
            table_rows.append(row)
        
        return '\n'.join(table_rows) + '\n'
    
    def update_tab_file(self, difficulty: str, machines: List[Dict]):
        """Update a specific HTB writeup tab file"""
        tab_file = self.tabs_dir / f"HTB-Writeup [{difficulty}].md"
        
        if not tab_file.exists():
            print(f"❌ Tab file not found: {tab_file}")
            return False
        
        try:
            # Read current content
            with open(tab_file, 'r', encoding='utf-8') as file:
                content = file.read()
            
            # Generate new table content
            new_table = self.generate_table_content(machines, difficulty)
            
            # Find table boundaries
            table_header = "| Machines"
            table_start_pattern = r'\| Machines.*?\n\|[-\s\|]+\n'
            table_end_pattern = r'\n(?=\n|\Z|-----)'
            
            # Find the start of the table
            header_match = re.search(table_start_pattern, content)
            if not header_match:
                print(f"❌ Could not find table header in {tab_file}")
                return False
            
            # Find the end of the table (next empty line or end of file)
            table_start = header_match.end()
            remaining_content = content[table_start:]
            
            # Find where table ends (empty line, horizontal rule, or end of file)
            table_end_match = re.search(r'\n\n|-----|\Z', remaining_content)
            if table_end_match:
                table_end = table_start + table_end_match.start()
            else:
                table_end = len(content)
            
            # Replace table content
            new_content = (
                content[:table_start] + 
                new_table + 
                content[table_end:]
            )
            
            # Write updated content
            with open(tab_file, 'w', encoding='utf-8') as file:
                file.write(new_content)
            
            print(f"✅ Updated {tab_file} with {len(machines)} machines")
            return True
            
        except Exception as e:
            print(f"❌ Error updating {tab_file}: {e}")
            return False
    
    def update_all_tabs(self):
        """Update all HTB writeup tab files"""
        print("\n🔄 Starting HTB writeup table update...")
        
        # Scan all posts
        machine_data = self.scan_htb_posts()
        
        # Update each tab file
        updated_count = 0
        total_machines = 0
        
        print("\n📝 Updating tab files...")
        
        for difficulty, machines in machine_data.items():
            print(f"\n🎯 Updating {difficulty} tab...")
            print(f"   Found {len(machines)} machines")
            
            if self.update_tab_file(difficulty, machines):
                updated_count += 1
                total_machines += len(machines)
        
        print(f"\n🎉 Update complete!")
        print(f"   Updated {updated_count}/3 tab files")
        print(f"   Total machines processed: {total_machines}")
        
        # Summary by difficulty
        print(f"\n📊 Summary by difficulty:")
        for difficulty, machines in machine_data.items():
            print(f"   {difficulty}: {len(machines)} machines")

def main():
    """Main execution function"""
    print("=" * 60)
    print("🤖 HTB Writeup Table Updater")
    print("=" * 60)
    
    # Initialize updater
    updater = HTBTableUpdater()
    
    # Update all tabs
    updater.update_all_tabs()
    
    print("\n" + "=" * 60)
    print("✨ All done! Your HTB writeup tables are now up to date.")
    print("=" * 60)

if __name__ == "__main__":
    main()
