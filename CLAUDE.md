# CLAUDE.md

Project-specific context for Claude Code.

## Wikimedia API User-Agent Requirements

Wikimedia sites (including wikitech.wikimedia.org, stream.wikimedia.org, en.wikipedia.org) block requests without a proper User-Agent header.

When fetching from Wikimedia URLs, always include a descriptive User-Agent:

```bash
curl -A "BotName/1.0 (https://en.wikipedia.org/wiki/User:YourBot; contact@example.com)" "https://..."
```

Example for this project:
```bash
curl -A "ClerkBot/1.0 (https://en.wikipedia.org/wiki/User:ClerkBot)" "https://wikitech.wikimedia.org/..."
```

This applies to:
- `wikitech.wikimedia.org` - Wikimedia technical documentation
- `stream.wikimedia.org` - EventStreams API
- `en.wikipedia.org/w/api.php` - MediaWiki API
- `schema.wikimedia.org` - Event schemas

## Useful API Queries for Documentation

### Log event types and actions

Query recent log events by type to see available actions and params structure:
```bash
# List protection log events
curl -A "..." "https://en.wikipedia.org/w/api.php?action=query&list=logevents&letype=protect&lelimit=5&format=json"

# List pending changes (stable) log events
curl -A "..." "https://en.wikipedia.org/w/api.php?action=query&list=logevents&letype=stable&lelimit=5&format=json"

# Filter by specific action
curl -A "..." "https://en.wikipedia.org/w/api.php?action=query&list=logevents&letype=stable&leaction=stable/config&lelimit=5&format=json"
```

### Discovering available actions for a log type

```bash
# Get 50 events and extract unique actions
curl -s -A "..." "https://en.wikipedia.org/w/api.php?action=query&list=logevents&letype=stable&lelimit=50&format=json" | \
  python3 -c "import sys, json; data = json.load(sys.stdin); print(set(e.get('action') for e in data['query']['logevents']))"
```

For stable (pending changes) log, actions are: `config`, `modify`, `reset`, `move_stable`
For protect log, actions are: `protect`, `modify`, `unprotect`, `move_prot`

### EventStreams documentation

- Docs: `https://wikitech.wikimedia.org/wiki/Event_Platform/EventStreams_HTTP_Service`
- Raw wikitext: `https://wikitech.wikimedia.org/w/index.php?title=Event_Platform/EventStreams_HTTP_Service&action=raw`
- Stream API docs: `https://stream.wikimedia.org/?doc`
- Stream spec: `https://stream.wikimedia.org/?spec`

### Sample EventStream data

```bash
# Get a few recent change events (5 second timeout)
curl -s -A "..." "https://stream.wikimedia.org/v2/stream/mediawiki.recentchange" --max-time 5 | head -50
```
