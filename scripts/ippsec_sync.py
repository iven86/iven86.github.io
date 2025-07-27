#!/usr/bin/env python3
"""
Scrape the last N videos from @ippsec and flip
`published: true` in any _posts/* that match the CTF name.
"""
import os, re, yaml, feedparser, pathlib

YOUTUBE_RSS = "https://www.youtube.com/feeds/videos.xml?channel_id=UCa6eh7gCkpPo5XXUDfygQQA"
POST_DIR    = pathlib.Path("../_posts")  # Go up one level from scripts/ to _posts/

def ctf_name_from_title(title: str):
    """Extract CTF name from various title formats"""
    patterns = [
        r'\bhtb\s+([a-zA-Z0-9_-]+)(?:\s+(?:writeup|walkthrough|retired))?',
        r'hackthebox\s+([a-zA-Z0-9_-]+)',
        r'([a-zA-Z0-9_-]+)\s+htb',
    ]
    
    for pattern in patterns:
        m = re.search(pattern, title, flags=re.I)
        if m:
            return m.group(1).lower().strip()
    return None

def update_published_status_only(file_path, new_status=True):
    """Update only the published field while preserving original formatting"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Use regex to find and replace only the published line
        patterns = [
            r'^(\s*published:\s*)false(\s*)$',  # published: false
            r'^(\s*published:\s*)False(\s*)$', # published: False
        ]
        
        updated = False
        for pattern in patterns:
            if re.search(pattern, content, re.MULTILINE):
                content = re.sub(pattern, rf'\g<1>true\g<2>', content, flags=re.MULTILINE)
                updated = True
                break
        
        if updated:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            return True
        else:
            print(f"⚠️  Could not find 'published: false' pattern in {file_path}")
            return False
            
    except Exception as e:
        print(f"❌ Error updating {file_path}: {e}")
        return False

def main():
    feed = feedparser.parse(YOUTUBE_RSS)
    if feed.bozo:
        raise RuntimeError(f"RSS fetch failed: {feed.bozo_exception}")

    print(f"Found {len(feed.entries)} entries from IppSec's channel")

    # Build set of published CTF names
    published_ctfs = set()
    
    print("\n--- Recent IppSec Videos ---")
    for i, entry in enumerate(feed.entries[:20], 1):
        ctf_name = ctf_name_from_title(entry.title)
        if ctf_name:
            published_ctfs.add(ctf_name)
            print(f"{i:2d}. {entry.title} -> CTF: '{ctf_name}'")
        else:
            print(f"{i:2d}. {entry.title} -> No CTF match")
    
    print(f"\nAll extracted CTF names: {sorted(published_ctfs)}")

    # Walk through _posts and check matches
    print("\n--- Checking Posts ---")
    updated_count = 0
    
    for post_path in POST_DIR.rglob("*.md"):
        try:
            content = post_path.read_text(encoding="utf-8")
            
            if not content.startswith("---\n"):
                continue
                
            parts = content.split("---\n", 2)
            if len(parts) < 3:
                continue
                
            front_matter_raw = parts[1]
            
            try:
                meta = yaml.safe_load(front_matter_raw)
            except yaml.YAMLError as e:
                print(f"❌ YAML error in {post_path}: {e}")
                continue
            
            if not meta:
                continue
                
            post_title = meta.get("title", "")
            post_ctf = ctf_name_from_title(post_title)
            is_published = meta.get("published", True)
            categories = meta.get("categories", [])
            
            # Only process HTB writeups
            if not ("HackTheBox" in categories and "Writeup" in categories):
                continue
            
            print(f"File: {post_path.relative_to(POST_DIR)}")
            print(f"  Title     : {post_title}")
            print(f"  CTF Name  : '{post_ctf}'")
            print(f"  Published : {is_published}")
            
            # Check for match
            if (post_ctf and 
                post_ctf in published_ctfs and 
                is_published == False):
                
                print(f"🎯 MATCH FOUND! Video exists for '{post_ctf}'")
                
                # Update only the published field
                if update_published_status_only(post_path, True):
                    print(f"✅ UPDATED: {post_path.name} -> published=true (formatting preserved)")
                    updated_count += 1
                else:
                    print(f"❌ FAILED to update: {post_path.name}")
            else:
                reasons = []
                if not post_ctf:
                    reasons.append("no CTF name extracted")
                elif post_ctf not in published_ctfs:
                    reasons.append(f"'{post_ctf}' not in published videos")
                elif is_published != False:
                    reasons.append("already published")
                
                print(f"ℹ️  No update: {', '.join(reasons)}")
            
            print()
            
        except Exception as e:
            print(f"❌ Error processing {post_path}: {e}")
            print()
    
    print(f"🎉 Summary: Updated {updated_count} posts")

if __name__ == "__main__":
    main()