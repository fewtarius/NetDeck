# CLIO Project Instructions - NetDeck Distribution

**Project:** NetDeck Distribution Package  
**Language:** TypeScript/React (frontend) + Python (backend)  
**Type:** Decky Loader Plugin for Steam Deck  
**Purpose:** Advanced network management plugin with MAC spoofing, WiFi hotspot, internet sharing


## CRITICAL: READ FIRST BEFORE ANY WORK

### The Unbroken Method (Core Principles)

This project follows **The Unbroken Method** for human-AI collaboration. This isn't just project style—it's the core operational framework.

**The Seven Pillars:**

1. **Continuous Context** - Never break the conversation. Maintain momentum through collaboration checkpoints.
2. **Complete Ownership** - If you find a bug, fix it. No "out of scope."
3. **Investigation First** - Read code before changing it. Never assume.
4. **Root Cause Focus** - Fix problems, not symptoms.
5. **Complete Deliverables** - No partial solutions. Finish what you start.
6. **Structured Handoffs** - Document everything for the next session.
7. **Learning from Failure** - Document mistakes to prevent repeats.

**If you skip this, you will violate the project's core methodology.**

### Collaboration Checkpoint Discipline

**Use `user_collaboration` tool at EVERY key decision point:**

| Checkpoint | When | Purpose |
|-----------|------|---------|
| Session Start | Always | Confirm context & plan |
| After Investigation | Before implementation | Share findings, get approval |
| After Implementation | Before commit | Show results, get OK |
| Session End | When work complete | Summary & handoff |

**[FAIL]** Create documentation/implementations alone  
**[OK]** Investigate freely, but checkpoint before committing changes


## Quick Start for NEW DEVELOPERS

### Before Touching Code

1. **Understand the system:**
   ```bash
   cat README.md                    # Distribution overview
   ls -la dist/ backend/            # Check package structure
   cat plugin.json                  # Plugin manifest
   ```

2. **Know the standards:**
   - Distribution packages are **pre-built artifacts** ready to deploy
   - VERSION file must be synchronized with source repository
   - `plugin.json` must be valid JSON with complete metadata
   - All artifacts must be reproducible from source
   - Changes here typically reflect source repository updates

3. **Use the toolchain:**
   ```bash
   # Verify package integrity
   cat VERSION
   cat plugin.json
   ls -la dist/ backend/
   
   # Check git status
   git status
   git log --oneline -10
   ```

### Core Workflow

```
1. Read current state (investigation)
2. Use collaboration tool (get approval)
3. Update artifacts/metadata (implementation)
4. Verify completeness (testing)
5. Commit with clear message (handoff)
```


## Key Directories & Files

### Distribution Contents
| File/Directory | Purpose | Status |
|----------------|---------|--------|
| `VERSION` | Current plugin version (sync with source) | **CRITICAL** |
| `plugin.json` | Plugin manifest and metadata | **CRITICAL** |
| `README.md` | User-facing documentation | [OK] Complete |
| `dist/` | Compiled React frontend bundle | [OK] Pre-built |
| `backend/` | Python plugin backend code | [OK] Pre-built |
| `main.py` | Backend entry point | [OK] Complete |
| `package.json` | Frontend dependencies (reference) | [OK] Complete |

### Key Features to Document
- **MAC Address Spoofing** - Change MAC for network access
- **WiFi Hotspot Creation** - Turn Steam Deck into WiFi AP
- **Internet Sharing** - Share connection with other devices
- **Network Management** - Advanced network configuration


## Architecture Overview

```
Steam Deck (Decky Loader)
    v
NetDeck Plugin Loaded
    v
React Frontend (dist/)
    ├─ Network Status Display
    ├─ MAC Spoofing Controls
    ├─ Hotspot Configuration
    └─ Settings Panel
    v
Python Backend (backend/)
    ├─ Network Interface Management
    ├─ MAC Address Modification
    ├─ Hostapd Integration (WiFi AP)
    ├─ iptables/NAT Configuration
    └─ System Command Execution
    v
System Network Stack
    ├─ NetworkManager Integration
    ├─ Kernel Network Interfaces
    └─ WiFi Hardware Control
```


## Code Standards: MANDATORY

### Version Management
```bash
# [CORRECT] Always sync VERSION with source tag
echo "1.2.3" > VERSION
# Update plugin.json to match
```

### Plugin Manifest (plugin.json)
```json
{
  "name": "NetDeck",
  "version": "1.2.3",
  "author": "Author Name",
  "description": "Advanced network management for Steam Deck",
  "main": "main.py",
  "api_version": 1
}
```

**Requirements:**
- Must be valid JSON (no trailing commas, proper escaping)
- Version must match VERSION file
- All required fields present
- Description is user-facing, clear and concise


## Distribution Maintenance Standards

### Before ANY Commit

```bash
# 1. Verify VERSION file is current
cat VERSION

# 2. Verify plugin.json is valid JSON
python3 -m json.tool plugin.json > /dev/null && echo "Valid JSON"

# 3. Check that version numbers match
grep '"version"' plugin.json
cat VERSION

# 4. Verify all artifacts present
ls -la dist/index.js backend/main.py

# 5. README matches current features
cat README.md
```

### Checklist Before Release

- [ ] VERSION file updated to new version
- [ ] `plugin.json` version matches VERSION file
- [ ] `plugin.json` is valid JSON
- [ ] All compiled artifacts present in `dist/`
- [ ] Backend Python code is complete in `backend/`
- [ ] README.md is current and user-friendly
- [ ] Changelog/release notes updated (if applicable)
- [ ] Plugin loads successfully in Decky Loader
- [ ] Core features verified working (MAC spoofing, hotspot, etc.)
- [ ] No debug output or development artifacts


## Testing Requirements

### Manual Plugin Testing

```bash
# 1. Deploy to Steam Deck test environment
# (Copy plugin directory to Decky plugins folder)

# 2. Restart Decky Loader service
sudo systemctl restart plugin_loader

# 3. Verify plugin appears in Decky menu

# 4. Test core features:
# - MAC address spoofing works
# - WiFi hotspot creates successfully
# - Internet sharing routes traffic
# - Settings persist correctly

# 5. Check for errors in Decky logs
journalctl -u plugin_loader -n 50
```


## Commit Workflow

### Commit Message Format
```bash
type(scope): brief description

Problem: What was missing/incorrect/outdated
Solution: How you fixed it
Testing: How you verified the fix
```

**Types:** release, fix, docs, chore  
**Scope:** version, manifest, dist, backend, docs

**Example:**
```bash
git add VERSION plugin.json README.md
git commit -m "release(version): update NetDeck to v1.2.3

Problem: Distribution package out of sync with source v1.2.3
Solution: Updated VERSION, plugin.json manifest, and README with new features
Testing: Verified plugin.json is valid JSON, VERSION matches manifest"
```


## Anti-Patterns: NEVER DO THESE

| Anti-Pattern | Why | What To Do Instead |
|--------------|-----|-------------------|
| Edit built artifacts directly | Changes will be overwritten | Update source, rebuild |
| Mismatched version numbers | Breaks Decky update mechanism | Always sync VERSION and plugin.json |
| Invalid JSON in plugin.json | Plugin won't load | Validate with `json.tool` |
| Skip testing plugin load | Broken releases | Always test in Decky Loader |
| Commit without version update | Confuses users about releases | Update VERSION for every release |
| Assume features without checking source | Documents wrong behavior | Read source code to verify |


## Release Process

```
1. Confirm source repository is ready
   - All features complete and tested
   - Source tagged with version number
   
2. Build artifacts from source
   - Frontend: npm run build
   - Backend: ensure all .py files present
   
3. Update VERSION file
   - Match source repository tag
   
4. Update plugin.json
   - Version matches VERSION file
   - Validate JSON syntax
   
5. Update README.md
   - Document new features
   - Update installation instructions if needed
   
6. Test in Decky Loader
   - Deploy to test Steam Deck
   - Verify all features work
   - Check for errors in logs
   
7. Commit and tag
   - Clear commit message
   - Tag with version: git tag v1.2.3
   
8. Push to repository
   - Push commits: git push
   - Push tags: git push --tags
```


## Session Handoff Procedures (MANDATORY)

### CRITICAL: Session Handoff Directory Structure

When ending a session, **ALWAYS** create a properly structured handoff directory:

```
ai-assisted/YYYYMMDD/HHMM/
├── CONTINUATION_PROMPT.md  [MANDATORY] - Next session's complete context
├── AGENT_PLAN.md           [MANDATORY] - Remaining priorities & blockers
├── CHANGELOG.md            [OPTIONAL]  - User-facing changes (if applicable)
└── NOTES.md                [OPTIONAL]  - Additional technical notes
```

**NEVER COMMIT** `ai-assisted/` directory to git. Always verify before committing:

```bash
git status  # Ensure no ai-assisted/ files staged
git add -A
git status  # Double-check
git commit -m "message"
```


## Documentation

### What Needs Documentation

- **New features** - Update README.md with user-facing description
- **Version changes** - Update VERSION and plugin.json
- **Breaking changes** - Document in README with migration guide
- **Known issues** - Add to README or separate KNOWN_ISSUES.md
- **Installation changes** - Update installation instructions

### Documentation Standards

- **User-focused** - Readers are Steam Deck users, not developers
- **Clear and concise** - Short paragraphs, bullet points
- **Actionable** - Tell users what to do, not just what exists
- **Current** - Remove outdated information immediately


## Notes

- This is a **distribution package** - source code lives elsewhere
- Keep synchronized with source repository for consistency
- Users depend on VERSION and plugin.json for updates
- README is the primary user documentation - keep it accurate
- Plugin stability is critical - Steam Deck users expect reliability
- Network features require root permissions - handle errors gracefully
- Test on actual Steam Deck hardware when possible
