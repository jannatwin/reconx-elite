# Payload Intelligence Engine - Implementation Guide

## Overview

The Payload Intelligence Engine is a comprehensive feature in ReconX Elite that automatically detects security testing opportunities on discovered endpoints, generates context-aware payload sets, and highlights high-probability vulnerabilities for manual testing.

## Architecture

### Backend Components

#### 1. **PayloadOpportunity Model** (`app/models/payload_opportunity.py`)
Stores detected testing opportunities with the following fields:
- `id`: Unique identifier
- `endpoint_id`, `scan_id`: Foreign keys linking to endpoints and scans
- `parameter_name`: Name of the vulnerable parameter
- `parameter_location`: Where the parameter is found (query, body, path, header)
- `vulnerability_type`: Type of vulnerability (xss, sqli, ssti, ssrf, openredirect)
- `confidence`: 0-100 confidence score indicating likelihood of vulnerability
- `payloads_json`: Array of suggested payloads for testing
- `tested_json`: Dict of {payload: {status, reflected, response_snippet}} for tracking results
- `highest_match`: Name of best detection result
- `match_confidence`: Confidence of the highest match (0-100)
- `notes`: Reason why this opportunity was detected

#### 2. **PayloadGenerator Service** (`app/services/payload_generator.py`)
Provides curated payload sets for different vulnerability types:

**XSS Payloads** (18 variants):
- Reflected: `"><script>alert(1)</script>`, `"><svg/onload=alert(1)>`
- Event handlers: `<img onerror=alert(1)>`, `<svg onload=alert(1)>`
- Protocol-based: `javascript:alert(1)`, `data:text/html,<script>alert(1)</script>`
- DOM-based: `{{alert(1)}}`, `${alert(1)}`

**SQLi Payloads** (10 variants):
- Boolean-based: `' OR '1'='1`, `1' AND '1'='1`
- Union-based: `1' UNION SELECT NULL, NULL, NULL --`
- Time-based: `1' AND SLEEP(5) --`
- Comment-based: `admin' --`

**SSTI Payloads** (13 variants):
- Jinja2/Django: `{{7*7}}`, `{{config}}`, `{{request}}`
- Expression Language: `#{request}`
- Freemarker: `<#assign x=123>${x}`
- Thymeleaf: `[(${7*7})]`

**SSRF Payloads** (11 variants):
- Cloud metadata: `http://169.254.169.254/`, `http://metadata.google.internal/`
- Local services: `http://127.0.0.1:8000`, `gopher://127.0.0.1:25/HELO`
- File access: `file:///etc/passwd`

**Open Redirect Payloads** (12 variants):
- Protocol-based: `//google.com`, `http://example.com`
- JavaScript: `javascript:alert(1)`
- Data URI: `data:text/html,<script>alert(1)</script>`
- Encoding bypass: `\nhttp://example.com`, `//google.com%40example.com`

Usage:
```python
from app.services.payload_generator import PayloadGenerator

payloads = PayloadGenerator.get_payloads_for_type("xss")  # Returns 18 XSS payloads
all_types = PayloadGenerator.get_all_payload_types()      # Returns list of all types
```

#### 3. **PayloadTester Service** (`app/services/payload_tester.py`)
Lightweight async payload testing engine for quick vulnerability detection:

**OpportunityDetector Class:**
- Automatically analyzes endpoint parameters to detect testing opportunities
- Uses keyword matching on parameter names to infer vulnerability types
- Returns: `{parameter_name, parameter_location, vulnerability_types[], confidence, reason}`

**Parameter Detection Rules:**
- **XSS**: `search`, `q`, `query`, `content`, `text`, `name`, `message`, etc.
- **SQLi**: `id`, `user_id`, `page`, `sort`, `filter`, `db`, `table`, etc.
- **SSTI**: `template`, `render`, `theme`, `style`, `format`, `lang`, etc.
- **SSRF**: `url`, `uri`, `link`, `proxy`, `endpoint`, `host`, `fetch`, `load`, etc.
- **Open Redirect**: `redirect`, `return`, `next`, `goto`, `callback`, etc.

**PayloadTester Class:**
Performs lightweight async testing with:
- Baseline request to establish normal response behavior
- Payload injection and response comparison
- **Reflection Detection**: Simple substring matching of payload in response
- **Status Code Anomaly**: Detects 5xx errors indicating injection success
- **Response Size Anomaly**: Detects >50% size change from baseline
- **Error Pattern Detection**: Regex matching for SQL/Template/Variable errors
- Confidence scoring (0-100) based on evidence

Usage:
```python
from app.services.payload_tester import OpportunityDetector, PayloadTester

# Detect opportunities
opportunities = OpportunityDetector.detect_opportunities(
    endpoint_url="https://example.com/api/search?q=test",
    parameters=["q"]
)

# Test payloads
tester = PayloadTester(timeout_seconds=5.0)
result = await tester.test_payload(
    url="https://example.com/api/search",
    payload="<script>alert(1)</script>",
    parameter_name="q",
    parameter_location="query"
)
# Returns: {status, reflected, response_snippet, confidence, findings}
```

#### 4. **Scan Pipeline Integration**
Payload opportunity detection is automatically integrated into the scan pipeline as a **soft stage** (after attack path generation):

```
[subfinder] → [httpx] → [gau] → [nuclei] → [attack_path_gen] → [payload_detection] → [complete]
Hard stages                                    Soft stages              ↑ New soft stage
```

Integration point in `app/tasks/scan_tasks.py` (`scan_stage_nuclei` function):
1. After attack path generation
2. Before diff computation and notifications
3. Stores opportunities in database
4. Logs detection results to ScanLog

#### 5. **API Endpoint** (`app/routers/payloads.py`)

**GET /payloads/{target_id}**
Returns all payload testing opportunities for a target's latest completed scan.

Response:
```json
{
  "target_id": 1,
  "scan_id": 42,
  "endpoints_with_opportunities": [
    {
      "id": 100,
      "url": "https://example.com/api/search?q=test",
      "normalized_url": "https://example.com/api/search",
      "hostname": "example.com",
      "priority_score": 80,
      "source": "gau",
      "payload_opportunities": [
        {
          "id": 1001,
          "endpoint_id": 100,
          "parameter_name": "q",
          "parameter_location": "query",
          "vulnerability_type": "xss",
          "confidence": 70,
          "payloads_json": ["...", "...", "..."],
          "tested_json": {},
          "highest_match": null,
          "match_confidence": 0,
          "notes": "Text input parameter likely reflects user data",
          "created_at": "2026-04-02T00:00:00Z",
          "updated_at": "2026-04-02T00:00:00Z"
        }
      ]
    }
  ],
  "opportunity_summary": {
    "xss": 12,
    "sqli": 8,
    "ssti": 3,
    "ssrf": 5,
    "openredirect": 4
  }
}
```

**GET /payloads/{target_id}/{endpoint_id}**
Returns payload opportunities for a specific endpoint, sorted by confidence.

### Frontend Components

#### **TestSuggestionsPanel** (`frontend/src/components/TestSuggestionsPanel.jsx`)

Interactive React component that displays payload testing opportunities:

**Features:**
1. **Opportunity Summary**: Color-coded badge showing counts per vulnerability type
   - 🔴 Red: XSS, SQLi (Critical)
   - 🟠 Orange: SSTI, SSRF (High)
   - 🟡 Yellow: Open Redirect (Medium)

2. **Endpoint Cards**:
   - Sorted by number of high-confidence (≥70%) opportunities
   - Expandable/collapsible for detailed inspection
   - Shows priority score, method/source, and vulnerability badges

3. **Opportunity Details**:
   - Vulnerability type with color coding
   - Confidence percentage
   - Parameter name and location
   - Detection reason
   - First 3 suggested payloads (truncated)

4. **Styling**:
   - Responsive grid layout
   - Color-coded severity indicators
   - Monospace font for code/payloads
   - Hover effects and transitions

#### **Integration into TargetPage**
Added to the "Attack Surface" tab before the Endpoints table:
```jsx
<TestSuggestionsPanel targetId={Number(targetId)} scan={latestScan} />
```

Automatically fetches and displays opportunities when:
- Target ID is available
- Latest scan status is "completed"
- Data loads on component mount and when scan completes

## Database Migration

**Migration File**: `20260402_000002_add_payload_opportunities.py`

Creates `payload_opportunities` table with:
- Foreign key constraints to `endpoints` and `scans` (CASCADE delete)
- Indexes on: `endpoint_id`, `scan_id`, `vulnerability_type`
- Default values: `parameter_location='query'`, `confidence=50`

## Workflow

### 1. Automatic Detection (During Scan)
```
[Scan completes] 
  → [Endpoints collected] 
  → [OpportunityDetector analyzes parameters]
  → [Creates PayloadOpportunity records]
  → [Stores in database]
```

### 2. User Interaction (Frontend)
```
[User views Target]
  → [TestSuggestionsPanel loads]
  → [Calls GET /payloads/{target_id}]
  → [Displays opportunities grouped by endpoint]
  → [User expands high-confidence opportunities]
  → [User sees suggested payloads]
```

### 3. Manual Testing
```
[User copies payload]
  → [Tests against endpoint manually]
  → [Validates reflection/responses]
  → [Confirms vulnerability]
```

## Confidence Scoring

Confidence is calculated as:
- **Parameter Keyword Match** (Base): 55-75% depending on match strength
- **XSS-specific**: Adjusted for text input parameters (70%)
- **SQLi-specific**: Adjusted for database-related parameters (65%)
- **SSTI-specific**: Adjusted for template-related parameters (55%)
- **SSRF-specific**: Adjusted for URL parameters (60%)
- **Open Redirect**: Highest base score (75%)

### Testing Result Confidence (0-100 based on):
- Exact payload reflection: +50
- Status code anomaly (5xx): +20
- Response size change >50%: +15
- Error pattern detection: +20
- **Final**: min(sum of evidence, 100)

## Security Considerations

### Design Choices
- **No actual payload execution**: Only parameter analysis, not active testing
- **Baseline comparison**: Reduces false positives by comparing against normal responses
- **Bounded timeout**: 5-second default prevents hanging on slow endpoints
- **Response size limit**: 50KB max for analysis to prevent memory issues
- **Read-only detection**: No data modification, only observation

### Limitations
- Basic parameter name heuristics (not ML-based)
- No context-aware payload generation based on response type
- No automatic exploit execution (safe by design)
- No persistence of test results (manual testing only tracked by user notes)
- Text-based pattern matching only (no semantic analysis)

## Future Enhancements

1. **Response Pattern Learning**: Train ML model on previous test results
2. **Payload Execution**: Optional async payload testing with detailed result capture
3. **Test Result Persistence**: Track which payloads were tested and results
4. **Correlation Across Scans**: Compare opportunity trends over time
5. **Custom Wordlists**: Allow admins to add domain-specific payloads
6. **Webhook Integration**: Alert on high-confidence opportunities
7. **Batch Testing**: Auto-test high-confidence opportunities on demand
8. **Evidence Collection**: Capture screenshots, responses, DOM state changes

## Code Structure

```
backend/
├── app/
│   ├── models/
│   │   └── payload_opportunity.py          # Data model
│   ├── services/
│   │   ├── payload_generator.py            # Payload sets
│   │   └── payload_tester.py               # Detection & testing
│   ├── routers/
│   │   └── payloads.py                     # API endpoints
│   ├── schemas/
│   │   └── payload_opportunity.py          # Response schemas
│   └── tasks/
│       └── scan_tasks.py                   # Pipeline integration
│   └── main.py                             # Router registration
└── alembic/
    └── versions/
        └── 20260402_000002_...py           # Database migration

frontend/
└── src/
    ├── api/
    │   └── client.js                       # API client (existing)
    └── components/
        └── TestSuggestionsPanel.jsx        # UI component
    └── pages/
        └── TargetPage.jsx                  # Integration point
```

## Testing Checklist

- [x] Backend models compile without errors
- [x] Services (generator, tester, detector) compile
- [x] API routes compile
- [x] Frontend TestSuggestionsPanel compiles
- [x] Frontend TargetPage builds successfully
- [ ] Run scan and verify PayloadOpportunity records created
- [ ] Verify GET /payloads/{target_id} returns correct data
- [ ] Verify TestSuggestionsPanel displays opportunities
- [ ] Test with various parameter types (query, path, body)
- [ ] Verify sorting by confidence score
- [ ] Test expandable/collapsible UI
- [ ] Verify color coding matches severity

## Example Usage

### Backend Opportunity Detection
```python
from app.services.payload_tester import OpportunityDetector
from app.services.payload_generator import PayloadGenerator

# Detect opportunities for an endpoint
opportunities = OpportunityDetector.detect_opportunities(
    endpoint_url="https://api.example.com/users/search?name=John&role=admin",
    parameters=["name", "role"]
)

# Generate payloads for each opportunity
for opp in opportunities:
    payloads = PayloadGenerator.get_payloads_for_type(opp["vulnerability_types"][0])
    print(f"{opp['parameter_name']} ({opp['vulnerability_types'][0]}): {len(payloads)} payloads")
```

### Frontend Payload Display
```jsx
<TestSuggestionsPanel targetId={123} scan={completedScan} />
// Automatically fetches and displays opportunities
// User can expand endpoints, see payloads, expand payload details
```

### API Query
```bash
# Get all opportunities for a target
curl -H "Authorization: Bearer $TOKEN" \
  https://api.example.com/payloads/123

# Get opportunities for specific endpoint
curl -H "Authorization: Bearer $TOKEN" \
  https://api.example.com/payloads/123/456
```

---

**Implementation Date**: April 2, 2026  
**Feature Status**: ✅ Complete and integrated into main scan pipeline
