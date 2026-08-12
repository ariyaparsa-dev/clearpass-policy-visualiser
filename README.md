# ClearPass Policy Visualiser

Visualise, analyse and troubleshoot Aruba ClearPass Services, Role Mapping Policies, Enforcement Policies and Enforcement Profiles.

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11+-blue" alt="Python">
  <img src="https://img.shields.io/badge/Flask-Web_App-green" alt="Flask">
  <img src="https://img.shields.io/badge/Aruba-ClearPass-orange" alt="ClearPass">
  <img src="https://img.shields.io/badge/License-MIT-yellow" alt="License">
</p>

---

## Overview

- A Flask-based visualisation and analysis platform for Aruba ClearPass that maps Services, Role Mapping Policies, Enforcement Policies, Enforcement Profiles and Enforcement Attributes.


- Provides a graphical view of policy relationships across the complete authentication and authorisation workflow.

- Consolidates service dependencies, policy logic and enforcement actions into a single interactive interface.

- Enables administrators to trace dependencies between ClearPass objects without navigating multiple areas of ClearPass Policy Manager.

- Supports impact analysis by identifying services, policies, enforcement profiles and roles affected by proposed configuration changes.

- Identifies unused Enforcement Profiles, Enforcement Policies, Role Mapping Policies and Roles through full dependency analysis, helping administrators find cleanup candidates.

- Provides drill-down visibility for unused Enforcement Profiles, including profile metadata and configured Enforcement Attributes.

- Includes endpoint repository analysis with matching object counts, endpoint drill-down and profiling visibility.

- Uses ClearPass REST APIs secured with OAuth 2.0 Client Credentials Grant for service, policy and enforcement data retrieval.

- Supports role-based access using RADIUS authentication against ClearPass and Aruba-User-Role based authorisation.

- Optionally accelerates endpoint profiling lookups using the built-in ClearPass PostgreSQL `appexternal` account and the `tips_endpoint_profiles` table, reducing endpoint fingerprint cache loading from approximately 74 seconds to 0.08 seconds in the reference environment.

<p align="center">
  <img src="screenshots/screenshot-8.jpg" alt="Service Dependency" width="800">
</p>

---

## Screenshots

### App Startup

<p align="center">
  <img src="screenshots/screenshot-1.jpg" alt="App Startup" width="800">
</p>

### Login Page

<p align="center">
  <img src="screenshots/screenshot-2.jpg" alt="Login RADIUS auth" width="800">
</p>

### Dashboard

<p align="center">
  <img src="screenshots/screenshot-3.jpg" alt="Dashboard" width="800">
</p>

---

### Service Dependency Graph

<p align="center">
  <img src="screenshots/screenshot-6.jpg" alt="Service Dependency" width="800">
</p>

<p align="center">
  <img src="screenshots/screenshot-8.jpg" alt="Service Dependency" width="800">
</p>

---

### Repository Search

<p align="center">
  <img src="screenshots/screenshot-7.jpg" alt="Repository search" width="800">
</p>

---

### Endpoint Details

<p align="center">
  <img src="screenshots/screenshot-9.jpg" alt="Endpoint Details" width="800">
</p>

---

### Unused Objects

<p align="center">
  <img src="screenshots/screenshot-10.jpg" alt="Unused Objects" width="800">
</p>

---

## Features

### Service Visualisation

Visualise complete service flows including:

- Authentication Sources
- Authorisation Sources
- Role Mapping Policies
- Role Mapping Rules
- Enforcement Policies
- Enforcement Profiles

---

### Interactive Policy Graph

- Zoom and pan
- Fit graph
- Centre graph
- Reset layout
- Node search
- Previous / Next search navigation
- PNG export
- JPG export

---

### Repository Search

Directly analyse Endpoint Repository conditions from Role Mapping Rules.

Features include:

- Matching endpoint counts
- Repository search
- Endpoint drill-down navigation
- Rule condition analysis

---

### Endpoint Profiling

Displays:

- Hostname
- Device Category
- Device Family
- Device Name
- Device Type
- Expanded Device Type
- MAC Vendor
- IPv4 Address

---

### Enforcement Profile Analysis

Provides detailed visibility into Enforcement Profile configuration and dependencies.

Shows:

- Services using an Enforcement Profile
- Enforcement Policy relationships
- Enforcement Profile dependencies
- Profile ID
- Profile type
- Enforcement action
- Profile description, when configured
- Enforcement Attributes including type, attribute and value

---

### Role Mapping Analysis

Provides visibility into:

- Role Mapping Rules
- Rule Conditions
- Repository usage
- Endpoint matches
- Assigned roles

---

### Unused Object Analysis

Identifies configuration objects that are no longer referenced anywhere, based on real dependency analysis rather than name matching.

Detects unused:

- Enforcement Profiles, including default enforcement profiles
- Enforcement Policies
- Role Mapping Policies
- Roles

Role usage is resolved across:

- Role Mapping Policies, including assigned roles, default roles and `Tips:Role` conditions
- Enforcement Policies using `Tips:Role` conditions
- Guest Operator Profiles via the built-in `[Guest Roles]` mapping

ClearPass built-in objects named with square brackets are automatically excluded.

Each category provides a one-click **Copy All** option for cleanup workflows.

Unused Enforcement Profiles are clickable and provide a dedicated detail view showing:

- Profile ID
- Profile type
- Enforcement action
- Description, when configured
- Enforcement Attributes
- Attribute type
- Attribute name
- Attribute value

Enforcement Profile details are retrieved through the existing ClearPass REST API integration and cached for reuse after retrieval.

---

## Architecture

```text
Browser
    │
    ▼
Flask Web Application
    │
    ├── Authentication (RADIUS)
    │
    ├── Policy Visualisation
    │
    ├── Dependency Analysis
    │
    ├── Unused Object Analysis
    │
    ├── ClearPass REST APIs
    │       ├── Services
    │       ├── Role Mapping Policies
    │       ├── Enforcement Policies
    │       ├── Enforcement Profiles
    │       ├── Roles
    │       └── Operator Profiles
    │
    └── PostgreSQL (Optional)
            └── Endpoint Profiling Cache
```
---
## Authentication and Data Sources

The application uses multiple ClearPass interfaces depending on the type of data being accessed.

### ClearPass REST APIs

Service, Role Mapping, Enforcement Policy and Enforcement Profile data is retrieved using the ClearPass REST APIs.

API authentication uses OAuth 2.0 Client Credentials Grant:

```text
grant_type=client_credentials
```

The API client requires access to:

- Services
- Authentication Sources
- Authorisation Sources
- Role Mapping Policies
- Enforcement Policies
- Enforcement Profiles
- Roles
- Guest Operator Profiles
- Endpoint Repository data

---

### User Authentication

Users authenticate directly against ClearPass using RADIUS PAP authentication.

The application supports role-based access using RADIUS reply attributes.

Supported attributes include:

```text
Aruba-User-Role
Filter-Id
Class
```

Example role mapping:

| Aruba-User-Role | Application Role |
|----------------|------------------|
| Admin | Administrator |
| ReadOnly | Read Only |

Example local ClearPass users:

| User | Role |
|------|------|
| vis-admin | Admin |
| vis-helpdesk | ReadOnly |

---

### PostgreSQL Endpoint Profiling Acceleration

Endpoint profiling information can optionally be loaded directly from the ClearPass PostgreSQL database.

The application uses the built-in ClearPass read-only PostgreSQL account:

```text
appexternal
```

to query:

```text
tips_endpoint_profiles
```

This provides endpoint profiling information including:

- Hostname
- Device Category
- Device Family
- Device Name
- Device Type
- Expanded Device Type
- MAC Vendor
- IPv4 Address

SQL acceleration is optional and can be enabled using:

```env
ENDPOINT_PROFILE_SOURCE=sql
```

If SQL access is unavailable, the application can automatically fall back to the standard REST API method.

---

### Data Source Summary

### Data Source Summary

| Function | Data Source | Authentication |
|-----------|-------------|----------------|
| User Login | ClearPass RADIUS | PAP |
| Service Discovery | ClearPass REST API | OAuth 2.0 Client Credentials |
| Role Mapping Policies | ClearPass REST API | OAuth 2.0 Client Credentials |
| Enforcement Policies | ClearPass REST API | OAuth 2.0 Client Credentials |
| Enforcement Profiles | ClearPass REST API | OAuth 2.0 Client Credentials |
| Roles | ClearPass REST API | OAuth 2.0 Client Credentials |
| Guest Operator Profiles | ClearPass REST API | OAuth 2.0 Client Credentials |
| Endpoint Repository | ClearPass REST API | OAuth 2.0 Client Credentials |
| Endpoint Profiling Cache | PostgreSQL (`tips_endpoint_profiles`) | `appexternal` |

---
## Project Structure

```text
clearpass-policy-visualiser
│
├── app.py
├── version.py
├── requirements.txt
│
├── cp_cache.py
├── cp_client.py
├── cp_endpoint.py
├── cp_endpoint_sql.py
├── cp_enforcement.py
├── cp_graph.py
├── cp_health.py
├── cp_object_graph.py
├── cp_role_mapping.py
├── cp_services.py
├── cp_unused_objects.py
│
├── auth/
│
├── sql/
│   └── endpoint_profiles.sql
│
├── templates/
│   ├── endpoint_details.html
│   ├── enforcement_profile_detail.html
│   ├── index.html
│   ├── login.html
│   ├── object_detail.html
│   ├── repository_search.html
│   ├── service.html
│   └── unused_objects.html
│
├── static/
│   └── service_graph.js
│
├── screenshots/
│
└── README.md
```
---
### Python Dependencies

```text
Flask>=3.0.3
Flask-Login>=0.6.3
Flask-Limiter>=3.8.0
python-dotenv>=1.0.1
psycopg[binary]>=3.2.0
pyyaml>=6.0
pyclearpass>=1.0.8
```

---
## Requirements

- Python 3.11 or later
- Aruba ClearPass Policy Manager
- OAuth API Client using Client Credentials Grant
- (Optional) PostgreSQL access using the built-in `appexternal` account for endpoint profiling acceleration

---

## Installation

Clone the repository:

```bash
git clone https://github.com/ariyaparsa-dev/clearpass-policy-visualiser.git

cd clearpass-policy-visualiser
```

Create a virtual environment:

```bash
python -m venv venv
```

Activate the environment.

Windows:

```bash
venv\Scripts\activate
```

Linux:

```bash
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## Configuration

Copy:

```text
.env.example
```

to:

```text
.env
```

and update as required.

Example:

```env
FLASK_SECRET_KEY=change_me

RADIUS_SERVER=clearpass.example.com
RADIUS_AUTH_PORT=1812
RADIUS_SECRET=change_me

RADIUS_NAS_IDENTIFIER=clearpass-policy-visualiser

RADIUS_TIMEOUT=5
RADIUS_RETRIES=2

RADIUS_ROLE_ATTRIBUTES=Aruba-User-Role,Filter-Id,Class

AUTH_DEFAULT_ROLE=ReadOnly

AUTH_ADMIN_RADIUS_VALUES=Admin
AUTH_READONLY_RADIUS_VALUES=ReadOnly

SESSION_COOKIE_SECURE=false
```

---

## PostgreSQL Endpoint Profiling Acceleration

For large endpoint repositories, endpoint profiling data can be loaded directly from the ClearPass PostgreSQL database.

### API Mode

```env
ENDPOINT_PROFILE_SOURCE=api
```

### SQL Mode

```env
ENDPOINT_PROFILE_SOURCE=sql
```

### Automatic Fallback

```env
ENDPOINT_SQL_FALLBACK_TO_API=true
```

If SQL connectivity fails, the application automatically falls back to the REST API method.

---

### PostgreSQL Configuration

```env
CP_SQL_HOST=
CP_SQL_PORT=5432
CP_SQL_DATABASE=tipsdb
CP_SQL_USERNAME=
CP_SQL_PASSWORD=
CP_SQL_SSLMODE=prefer

CP_SQL_QUERY_FILE=sql/endpoint_profiles.sql
```

---

## Performance Optimisation

Endpoint profiling data can be loaded directly from the ClearPass PostgreSQL database using:

```text
tips_endpoint_profiles
```

### Example Results

| Method | Time |
|----------|----------|
| REST API | ~74 seconds |
| PostgreSQL | ~0.08 seconds |

Environment:

```text
Endpoint Profiles: 376
```

Observed improvement:

```text
~74s → ~0.08s
```

---

## Typical Use Cases

### Troubleshooting Authentication Failures

Visualise the complete policy flow from service selection through role mapping and enforcement.

### Change Impact Analysis

Identify which services, policies and enforcement profiles will be affected before making configuration changes.

### ClearPass Documentation

Provide a graphical representation of ClearPass policy relationships for operational documentation.

### Configuration Reviews

Quickly understand service dependencies and enforcement profile usage without manually navigating through ClearPass.

### Configuration Cleanup

Identify unused Enforcement Profiles, Enforcement Policies, Role Mapping Policies and Roles that are candidates for removal. Copy object lists by category for review and drill into unused Enforcement Profiles to inspect their configuration before cleanup.

### Operational Troubleshooting

Search endpoint repositories, analyse rule conditions and verify profile assignments.

---

## Roadmap

Planned enhancements:

- Additional unused-object drill-down views
- Admin vs ReadOnly UI functions
- Role-based authorisation controls
- Impact analysis reporting
- Additional export options
- SVG graph export
- Standalone packaged release

---

## Changelog

### v1.1.1

- Added clickable unused Enforcement Profiles
- Added dedicated Unused Enforcement Profile detail view
- Added Enforcement Profile metadata display including ID, type, action and description
- Added detailed Enforcement Attribute visibility including attribute type, name and value
- Added Enforcement Profile caching for detail lookups
- Improved Unused Enforcement Profile layout with Profile Information and Enforcement Attributes displayed side by side
- Standardised ClearPass Policy Visualizer headers across analysis views
- Standardised page-level Back navigation on the top-right
- Updated Service Visualisation navigation and header layout for UI consistency

### v1.1.0

- Added Unused Object analysis for Enforcement Profiles, Enforcement Policies, Role Mapping Policies and Roles
- Full role dependency analysis including Guest Operator Profiles via the `[Guest Roles]` mapping
- Correct handling of default enforcement profiles in dependency analysis
- New clickable dashboard card and dedicated Unused Objects page
- Copy All per category for cleanup workflows
- Results cached at startup and refreshed on demand for fast page loads
- Reduced log verbosity

### v1.0.0

- Initial public release

---

## License

MIT License

---

## Disclaimer

This project is an independent community tool.

It is not affiliated with, endorsed by, or supported by Hewlett Packard Enterprise (HPE).

Always validate configuration changes before applying them to production environments.

---

## Acknowledgements

- Aruba ClearPass
- HPE Aruba Networking
- Flask
- Cytoscape.js
- pyclearpass

---

**ClearPass Policy Visualiser v1.1.1**

Visualise. Analyse. Troubleshoot.