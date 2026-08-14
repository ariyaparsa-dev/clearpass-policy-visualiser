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

ClearPass Policy Visualiser is a Flask-based visualisation and analysis platform for Aruba ClearPass Policy Manager.

It provides graphical visibility into the complete authentication and authorisation workflow, including:

- Services
- Authentication Sources
- Authorisation Sources
- Role Mapping Policies
- Role Mapping Rules
- Enforcement Policies
- Enforcement Profiles
- Enforcement Attributes
- Roles
- Endpoint Repository conditions

The Visualiser consolidates policy relationships, dependencies and enforcement actions into an interactive interface, allowing administrators to understand ClearPass configuration without navigating multiple areas of Policy Manager.

Additional capabilities include:

- Dependency analysis across ClearPass policy objects
- Unused object detection
- Enforcement Profile inspection
- Role Mapping and Enforcement Policy graph visualisation
- Endpoint Repository analysis
- Endpoint profiling visibility
- RADIUS-based user authentication
- Role-based application access
- Browser-based initial configuration
- Configuration and connectivity validation
- Optional PostgreSQL endpoint profiling acceleration

The application uses ClearPass REST APIs secured with OAuth 2.0 Client Credentials Grant for policy and configuration data retrieval.

Users authenticate against ClearPass using RADIUS, with application permissions derived from returned role attributes such as `Aruba-User-Role`.

Endpoint profiling data can optionally be loaded from the ClearPass PostgreSQL database using the built-in `appexternal` account and the `tips_endpoint_profiles` table.

In the reference environment, PostgreSQL reduced endpoint fingerprint cache loading from approximately 74 seconds using the REST API to approximately 0.08 seconds.

<p align="center">
  <img src="screenshots/screenshot-8.jpg" alt="Service Dependency" width="800">
</p>

---

## Screenshots

### Setup Validation

Before configuration is saved, the Visualiser validates connectivity to the configured services.

<p align="center">
  <img src="screenshots/screenshot-1a.jpg" alt="App Startup" width="800">
</p>

<p align="center">
  <img src="screenshots/screenshot-1b.jpg" alt="App Startup" width="800">
</p>

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

### First-Run Initial Setup

ClearPass Policy Visualiser v1.2.0 includes a browser-based Initial Setup workflow.

When the application is started without an existing Visualiser configuration, Flask starts without initialising the ClearPass caches and redirects the administrator to Initial Setup.

The setup workflow configures:

- ClearPass REST API
- ClearPass REST API SSL certificate verification
- RADIUS authentication
- RADIUS shared secret
- NAS identifier
- Endpoint profiling source
- Optional ClearPass PostgreSQL endpoint profiling

Sensitive fields require confirmation before validation.

Configuration is validated before being persisted.

---

### Setup Connectivity Validation

Initial Setup performs connectivity validation before configuration is saved.

Validation includes:

- ClearPass server connectivity
- ClearPass REST API authentication
- PostgreSQL connectivity when PostgreSQL endpoint profiling is selected

If the ClearPass server cannot be reached, the REST API authentication test is skipped rather than incorrectly reported as an authentication failure.

Validation results are displayed individually so administrators can distinguish between:

- Successful tests
- Failed tests
- Tests that were skipped because a prerequisite failed

Configuration is saved only after required validation succeeds.

Failed setup attempts remain on the Initial Setup page and do not create a completed Visualiser configuration.

---

### Configuration Management

Visualiser configuration created by Initial Setup is stored locally in:

```text
.visualiser.env
```

The application explicitly loads this file during startup.

The legacy `config.yaml` configuration path has been removed.

The application also no longer performs implicit loading of a conventional `.env` file during startup.

This provides a single Visualiser-managed configuration source:

```text
Fresh Installation
        │
        ▼
Initial Setup
        │
        ▼
Configuration Validation
        │
        ▼
.visualiser.env
        │
        ▼
Start Visualiser
        │
        ▼
Login
```

The `.visualiser.env` file contains sensitive configuration and is excluded from Git.

---

### Service Visualisation

Visualise complete ClearPass service flows including:

- Authentication Sources
- Authorisation Sources
- Role Mapping Policies
- Role Mapping Rules
- Enforcement Policies
- Enforcement Profiles

---

### Interactive Policy Graph

Interactive graph features include:

- Zoom and pan
- Fit graph
- Centre graph
- Reset layout
- Node search
- Previous / Next search navigation
- PNG export
- JPG export

Unused Enforcement Policies and Role Mapping Policies can also be opened directly from the Unused Objects view and displayed using the policy graph.

---

### Repository Search

Directly analyse Endpoint Repository conditions referenced by Role Mapping Rules.

Features include:

- Matching endpoint counts
- Repository search
- Endpoint drill-down navigation
- Rule condition analysis

---

### Endpoint Profiling

Endpoint profiling can display:

- Hostname
- Device Category
- Device Family
- Device Name
- Device Type
- Expanded Device Type
- MAC Vendor
- IPv4 Address

Endpoint profiling can use either the ClearPass REST API or, optionally, direct PostgreSQL access for accelerated cache loading.

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
- Enforcement Attributes
- Attribute type
- Attribute name
- Attribute value

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

Identifies ClearPass configuration objects that are no longer referenced, based on dependency analysis rather than name matching.

Detects unused:

- Enforcement Profiles, including default enforcement profiles
- Enforcement Policies
- Role Mapping Policies
- Roles

Role usage is resolved across:

- Role Mapping Policies
- Assigned roles
- Default roles
- `Tips:Role` conditions
- Enforcement Policies using `Tips:Role` conditions
- Guest Operator Profiles through the built-in `[Guest Roles]` mapping

ClearPass built-in objects named with square brackets are automatically excluded.

Each unused-object category provides a one-click **Copy All** option for cleanup and review workflows.

Unused Enforcement Profiles are clickable and provide a dedicated detail view showing:

- Profile ID
- Profile type
- Enforcement action
- Description, when configured
- Enforcement Attributes
- Attribute type
- Attribute name
- Attribute value

Unused Enforcement Policies and Role Mapping Policies are also clickable and can be inspected using their dependency graph.

Enforcement Profile details are retrieved through the existing ClearPass REST API integration and cached for reuse after retrieval.

---

## Architecture

```text
Browser
    │
    ▼
Flask Web Application
    │
    ├── Initial Setup
    │       ├── Configuration Validation
    │       └── .visualiser.env
    │
    ├── Authentication
    │       └── ClearPass RADIUS
    │
    ├── Policy Visualisation
    │
    ├── Dependency Analysis
    │
    ├── Unused Object Analysis
    │
    ├── ClearPass REST APIs
    │       ├── Services
    │       ├── Authentication Sources
    │       ├── Authorisation Sources
    │       ├── Role Mapping Policies
    │       ├── Enforcement Policies
    │       ├── Enforcement Profiles
    │       ├── Roles
    │       ├── Operator Profiles
    │       └── Endpoint Repository
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

## User Authentication

Users authenticate against ClearPass using RADIUS PAP authentication.

The application supports role-based access using RADIUS reply attributes.

Supported role attributes include:

```text
Aruba-User-Role
Filter-Id
Class
```

Example role mapping:

| Aruba-User-Role | Application Role |
|-----------------|------------------|
| Admin | Administrator |
| ReadOnly | Read Only |

### ClearPass Authentication Prerequisite

Before users can log in to the Visualiser, ClearPass must be configured to authenticate those users through a service available to the Visualiser.

For example, local ClearPass users can be created as:

| User | Returned Role |
|------|---------------|
| `vis-admin` | `Admin` |
| `vis-helpdesk` | `ReadOnly` |

The ClearPass service and enforcement configuration should return the appropriate role to the Visualiser.

For example:

```text
Aruba-User-Role = Admin
```

for administrative access, or:

```text
Aruba-User-Role = ReadOnly
```

for read-only access.

The required RADIUS server, port, shared secret and NAS identifier are configured through Initial Setup.

---

## PostgreSQL Endpoint Profiling Acceleration

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

The endpoint profiling source is selected during Initial Setup.

### API Mode

API mode retrieves endpoint profiling information using the ClearPass REST API.

```text
Endpoint Profiling Source: REST API
```

### PostgreSQL Mode

PostgreSQL mode loads endpoint profiling data directly from the ClearPass PostgreSQL database.

```text
Endpoint Profiling Source: PostgreSQL
```

When PostgreSQL mode is selected, Initial Setup requests:

- PostgreSQL Host
- PostgreSQL Port
- Database
- Username
- Password
- Password confirmation

The PostgreSQL connection is validated before setup can complete.

---

## Data Source Summary

| Function | Data Source | Authentication |
|----------|-------------|----------------|
| User Login | ClearPass RADIUS | PAP |
| Service Discovery | ClearPass REST API | OAuth 2.0 Client Credentials |
| Authentication Sources | ClearPass REST API | OAuth 2.0 Client Credentials |
| Authorisation Sources | ClearPass REST API | OAuth 2.0 Client Credentials |
| Role Mapping Policies | ClearPass REST API | OAuth 2.0 Client Credentials |
| Enforcement Policies | ClearPass REST API | OAuth 2.0 Client Credentials |
| Enforcement Profiles | ClearPass REST API | OAuth 2.0 Client Credentials |
| Roles | ClearPass REST API | OAuth 2.0 Client Credentials |
| Guest Operator Profiles | ClearPass REST API | OAuth 2.0 Client Credentials |
| Endpoint Repository | ClearPass REST API | OAuth 2.0 Client Credentials |
| Endpoint Profiling Cache | REST API or PostgreSQL | OAuth 2.0 / `appexternal` |

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
├── cp_setup.py
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
│   ├── setup.html
│   ├── setup_complete.html
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

## Python Dependencies

The Visualiser uses the following direct Python dependencies:

```text
Flask>=3.0.3
Flask-Login>=0.6.3
Flask-Limiter>=3.8.0
python-dotenv>=1.0.1
psycopg[binary]>=3.2.0
pyclearpass>=1.0.8
```

PyYAML is no longer a direct dependency because the legacy YAML configuration path has been removed.

---
## Requirements

- Python 3.11 or later
- Aruba ClearPass Policy Manager
- ClearPass REST API Client using OAuth 2.0 Client Credentials Grant
- Network connectivity from the Visualiser host to ClearPass
- RADIUS configuration in ClearPass for Visualiser user authentication
- Appropriate ClearPass service and enforcement configuration to return Visualiser user roles
- PostgreSQL access using the built-in `appexternal` account when PostgreSQL endpoint profiling is selected

---

## Installation

Clone the repository:

```bash
git clone <REPOSITORY-URL>
cd clearpass-policy-visualiser
```

Create a virtual environment:

```bash
python -m venv venv
```

Activate the environment.

### Windows

```bash
venv\Scripts\activate
```

### Linux

```bash
source venv/bin/activate
```

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

Start the Visualiser:

```bash
python app.py
```

On a new installation, the application will start without initialising the ClearPass caches and will present the Initial Setup page.

Open the address displayed by Flask in a browser and complete Initial Setup.

---

## Initial Setup

The Initial Setup wizard replaces the previous manual `.env` configuration process.

There is no requirement to copy or manually edit an `.env` or `config.yaml` file.

Initial Setup is divided into the following configuration areas.

### RADIUS Authentication

Configure:

- RADIUS Server
- RADIUS Port
- RADIUS Shared Secret
- Confirm RADIUS Shared Secret
- NAS Identifier

The page also describes the ClearPass-side user and role configuration required for Visualiser authentication.

---

### ClearPass REST API

Configure:

- ClearPass API URL
- Client ID
- Client Secret
- Confirm Client Secret
- SSL certificate verification preference

The REST API uses OAuth 2.0 Client Credentials Grant.

---

### Endpoint Profiling

Select the source used for endpoint profiling:

- REST API
- PostgreSQL

When PostgreSQL is selected, configure:

- PostgreSQL Host
- PostgreSQL Port
- Database
- Username
- Password
- Confirm Password

---

## Initial Setup Validation

After the form is submitted, the Visualiser validates the configuration before saving it.

A successful validation can include:

```text
ClearPass Server       Successful
ClearPass REST API     Successful
PostgreSQL             Successful
```

If a prerequisite test fails, dependent tests can be skipped.

For example:

```text
ClearPass Server       Failed
ClearPass REST API     Skipped
PostgreSQL             Tested independently
```

If validation fails:

```text
Initial Setup
      │
      ▼
Display Validation Results
      │
      ▼
Remain on Setup Page
      │
      ▼
Configuration Not Saved
```

If validation succeeds:

```text
Initial Setup
      │
      ▼
Validate Connectivity
      │
      ▼
Save .visualiser.env
      │
      ▼
Setup Complete
      │
      ▼
Start Visualiser
      │
      ▼
Initialise Caches
      │
      ▼
Login
```

---

## Configuration Files and Secrets

### `.visualiser.env`

Initial Setup creates:

```text
.visualiser.env
```

This contains the active Visualiser configuration.

It may contain sensitive information including:

- ClearPass API Client Secret
- RADIUS Shared Secret
- PostgreSQL password

Do not commit this file to source control.

The supplied `.gitignore` excludes `.visualiser.env`.

---

### `.flask_secret`

If `FLASK_SECRET_KEY` is not explicitly configured, the application generates a persistent Flask session secret and stores it in:

```text
.flask_secret
```

This file is also excluded from Git.

---

## Starting the Visualiser

For an existing configured installation:

```bash
python app.py
```

The Visualiser loads `.visualiser.env` and initialises the required caches.

Startup includes:

- ClearPass service discovery
- ClearPass health check
- Endpoint profiling cache
- Role cache
- Enforcement Profile reference cache
- Role Mapping reference cache
- Unused Object cache

After startup, users authenticate through the login page using ClearPass RADIUS.

---

## Refreshing Cached Data

The dashboard provides a cache refresh operation which rebuilds Visualiser data from ClearPass, including:

- Health status
- Services
- Roles
- Enforcement Profile references
- Role Mapping references
- Unused Object analysis

This allows the Visualiser to reflect ClearPass configuration changes without requiring a complete application reinstall.

---

## PostgreSQL Endpoint Profiling Performance

For large endpoint repositories, endpoint profiling data can be loaded directly from the ClearPass PostgreSQL database using:

```text
tips_endpoint_profiles
```

### Reference Results

| Method | Time |
|--------|------|
| REST API | ~74 seconds |
| PostgreSQL | ~0.08 seconds |

Reference environment:

```text
Endpoint Profiles: 376
```

Observed improvement:

```text
~74s → ~0.08s
```

These figures are observations from the reference environment and should not be interpreted as guaranteed performance in other ClearPass deployments.

---

## Typical Use Cases

### Troubleshooting Authentication Failures

Visualise the complete policy flow from service selection through role mapping and enforcement.

### Change Impact Analysis

Identify which services, policies and enforcement profiles may be affected before making configuration changes.

### ClearPass Documentation

Provide a graphical representation of ClearPass policy relationships for operational documentation.

### Configuration Reviews

Quickly understand service dependencies and enforcement profile usage without manually navigating through multiple areas of ClearPass.

### Configuration Cleanup

Identify unused Enforcement Profiles, Enforcement Policies, Role Mapping Policies and Roles that are candidates for review.

Copy unused object lists by category and drill into individual objects to inspect their configuration and relationships before making changes.

### Operational Troubleshooting

Search endpoint repositories, analyse rule conditions and verify profile assignments.

---

## Roadmap

Planned enhancements include:

### ClearPass Assisted Setup

Future setup improvements are planned to optionally automate selected ClearPass-side prerequisites using the ClearPass REST API.

The proposed workflow will remain opt-in and is intended to build on the v1.2.0 Initial Setup framework.

Potential phases include:

1. Optional provisioning of Visualiser local users
2. Optional provisioning of Visualiser role/enforcement configuration
3. Optional provisioning of the Visualiser RADIUS service

Existing ClearPass objects should be detected and validated rather than blindly duplicated or overwritten.

### Additional Enhancements

- Additional unused-object drill-down views
- Enhanced role-based authorisation controls
- Impact analysis reporting
- Additional export options
- SVG graph export
- Standalone packaged release
- Multi-server ClearPass support

---

## Changelog

### v1.2.0

#### Initial Setup

- Added browser-based first-run Initial Setup workflow
- Added ClearPass REST API configuration
- Added RADIUS authentication configuration
- Added endpoint profiling source selection
- Added optional PostgreSQL endpoint profiling configuration
- Added confirmation fields for sensitive credentials
- Added dedicated Setup Complete workflow
- Added Start Visualiser operation after successful setup

#### Configuration Validation

- Added ClearPass server connectivity validation
- Added ClearPass REST API authentication validation
- Added PostgreSQL connectivity validation when PostgreSQL profiling is selected
- Added independent validation result reporting
- Added skipped REST API status when the ClearPass server cannot be reached
- Prevented failed setup validation from creating a completed configuration

#### Configuration Management

- Added `.visualiser.env` as the Visualiser-managed runtime configuration
- Added explicit `.visualiser.env` loading at application startup
- Added configuration reload after successful Initial Setup
- Added clearing of existing user sessions after initial configuration changes
- Removed implicit `.env` loading
- Removed the legacy `config.yaml` runtime configuration path
- Removed the direct PyYAML dependency

#### Authentication

- Added Initial Setup guidance for ClearPass RADIUS authentication prerequisites
- Documented example `Admin` and `ReadOnly` Visualiser roles
- Documented example `vis-admin` and `vis-helpdesk` ClearPass users
- Documented `Aruba-User-Role` role mapping requirements

#### Health and Startup

- Migrated ClearPass health checking away from `config.yaml`
- Added clean startup behaviour when Initial Setup is incomplete
- Added Visualiser cache initialisation after successful setup
- Improved setup and startup logging

#### User Interface

- Standardised ClearPass Policy Visualiser branding across object analysis views
- Standardised Back navigation placement on the top-right
- Added consistent headers for Enforcement Policy and Role Mapping Policy detail views
- Improved responsive behaviour for object detail page headers

---

### v1.1.1

- Added clickable unused Enforcement Profiles
- Added dedicated Unused Enforcement Profile detail view
- Added Enforcement Profile metadata display including ID, type, action and description
- Added detailed Enforcement Attribute visibility including attribute type, name and value
- Added Enforcement Profile caching for detail lookups
- Improved Unused Enforcement Profile layout with Profile Information and Enforcement Attributes displayed side by side
- Standardised ClearPass Policy Visualiser headers across analysis views
- Standardised page-level Back navigation on the top-right
- Updated Service Visualisation navigation and header layout for UI consistency

---

### v1.1.0

- Added Unused Object analysis for Enforcement Profiles, Enforcement Policies, Role Mapping Policies and Roles
- Added full role dependency analysis including Guest Operator Profiles through the `[Guest Roles]` mapping
- Added correct handling of default Enforcement Profiles during dependency analysis
- Added clickable dashboard card and dedicated Unused Objects page
- Added Copy All per category for cleanup workflows
- Added startup and refresh caching for Unused Object results
- Reduced log verbosity

---

### v1.0.0

- Initial public release

---

## Security Considerations

The Visualiser handles credentials used to communicate with ClearPass and, when enabled, PostgreSQL.

Files containing local secrets are excluded from Git by the supplied `.gitignore`, including:

```text
.visualiser.env
.flask_secret
cert.pem
key.pem
```

Administrators should:

- Protect access to the Visualiser host
- Use appropriately scoped ClearPass API credentials
- Protect the RADIUS shared secret
- Protect PostgreSQL credentials
- Use appropriate TLS and certificate verification settings for the deployment
- Review ClearPass configuration before making production changes
- Never commit `.visualiser.env` or `.flask_secret` to source control

---

## License

MIT License

---

## Disclaimer

This project is an independent community tool.

It is not affiliated with, endorsed by, or supported by Hewlett Packard Enterprise (HPE).

Always validate configuration changes before applying them to production environments.

Unused Object results should be treated as analysis and review candidates. Confirm that an object is no longer required before removing it from ClearPass.

---

## Acknowledgements

- Aruba ClearPass
- HPE Aruba Networking
- Flask
- Cytoscape.js
- pyclearpass

---

**ClearPass Policy Visualiser v1.2.0**

Visualise. Analyse. Troubleshoot.