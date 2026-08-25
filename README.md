# Hybrid Web Application Firewall (WAF)

A hybrid **Web Application Firewall (WAF)** built with **FastAPI** that combines rule-based security detection with **Machine Learning** to inspect, classify, and block malicious HTTP requests before they reach a protected web application.

The system operates as a reverse proxy between the client and the protected application, providing multiple security layers including attack-signature detection, ML-based classification, IP access control, rate limiting, request validation, logging, and a real-time monitoring dashboard.

---

## Overview

Traditional Web Application Firewalls primarily rely on predefined attack signatures. While effective against known attack patterns, signature-based detection alone may fail to identify malicious requests that do not exactly match existing rules.

This project implements a **hybrid detection approach** combining:

- Rule-based attack detection
- Machine Learning classification
- IP blacklist and whitelist management
- Rate limiting
- Request size validation
- HTTP request logging
- Attack classification
- Real-time monitoring dashboard
- Reverse proxy protection

The Machine Learning component was developed using the **CSIC 2010 HTTP dataset** to classify HTTP requests as either normal or malicious.

---

## Key Features

- Hybrid rule-based and Machine Learning detection
- SQL Injection detection
- Cross-Site Scripting (XSS) detection
- Path Traversal detection
- Command Injection detection
- Rate limiting
- IP blacklist and whitelist management
- HTTP request size validation
- ML-based malicious request detection
- Request and attack logging
- Real-time monitoring dashboard
- Reverse proxy architecture
- REST API for WAF management
- Automated tests for middleware, detection engine, and security rules

---

## Architecture

The WAF operates between the client and the protected web application.

```text
                         ┌─────────────────────┐
                         │       Client        │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │ FastAPI / Uvicorn   │
                         └──────────┬──────────┘
                                    │
                                    ▼
                      ┌──────────────────────────┐
                      │      WAF Middleware      │
                      └─────────────┬────────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    │               │               │
                    ▼               ▼               ▼
              Request Size       IP Rules       Body Parsing
                 Check             Check
                    │               │
                    └───────────────┼───────────────┐
                                    ▼               │
                         ┌─────────────────────┐     │
                         │  Detection Engine   │     │
                         └──────────┬──────────┘     │
                                    │
                    ┌───────────────┴───────────────┐
                    │                               │
                    ▼                               ▼
          ┌────────────────────┐          ┌────────────────────┐
          │ Rule-Based Engine  │          │ Machine Learning   │
          │                    │          │     Detector       │
          └──────────┬─────────┘          └──────────┬─────────┘
                     │                               │
                     └───────────────┬───────────────┘
                                     ▼
                           ┌───────────────────┐
                           │ Security Decision │
                           │   Allow / Block   │
                           └─────────┬─────────┘
                                     │
                           ┌─────────┴─────────┐
                           │                   │
                           ▼                   ▼
                   Request Logging       Dashboard
                           │
                           ▼
                  Protected Application
                         (DVWA)
```

---

## Detection Pipeline

Every incoming HTTP request passes through multiple security layers before being forwarded to the protected application.

### 1. Path Filtering

Internal WAF routes are excluded from normal security inspection.

Examples include:

```text
/dashboard
/static
/.well-known
```

This prevents the firewall from unnecessarily inspecting its own internal resources.

### 2. Request Size Validation

The middleware validates the size of incoming requests before performing deeper inspection.

Different limits can be applied depending on the request content type. Requests exceeding the configured limits are rejected before reaching the protected application.

### 3. IP Access Control

The source IP address is checked against the configured IP rules.

```text
              Incoming IP
                   │
                   ▼
             Check IP Rules
              /         \
       Blacklist       Whitelist
           │               │
         BLOCK           ALLOW
                           │
                      Otherwise
                           │
                           ▼
                 Continue Inspection
```

This allows administrators to explicitly block or trust specific IP addresses.

### 4. Rate Limiting

The system monitors request frequency to reduce abusive or high-frequency traffic.

Clients exceeding the configured request threshold can be blocked by the WAF.

### 5. Rule-Based Detection

The request is inspected for known attack patterns such as:

- SQL Injection
- Cross-Site Scripting (XSS)
- Path Traversal
- Command Injection

### 6. Machine Learning Detection

The Machine Learning model provides an additional detection layer for malicious requests that may not exactly match predefined attack signatures.

### 7. Logging and Monitoring

Detection results and request information are stored and exposed through the monitoring dashboard.

---

## Rule-Based Detection

The detection engine contains dedicated rules for several common web attacks.

### SQL Injection


### Cross-Site Scripting (XSS)
### Path Traversal
### Command Injection
### Rate Limiting
## Machine Learning Detection
Rule-based detection is complemented by a Machine Learning classifier.
The ML pipeline analyzes characteristics extracted from incoming HTTP requests and produces a binary classification:

```text
HTTP Request
     │
     ▼
Feature Extraction
     │
     ▼
Preprocessing
     │
     ▼
Machine Learning Model
     │
     ▼
Normal / Attack
```

The current ML component performs:

```text
Normal
   vs
Attack
```

This provides an additional detection mechanism beyond predefined attack signatures.

---

## Hybrid Detection Strategy

The core idea of the project is to combine deterministic security rules with Machine Learning.

```text
                  Incoming Request
                         │
                         ▼
                    Rate Limit
                         │
                         ▼
                Rule-Based Detection
                    /           \
                 Match         No Match
                   │              │
                   ▼              ▼
                 BLOCK       ML Detection
                               /       \
                           Attack      Normal
                              │           │
                              ▼           ▼
                            BLOCK        ALLOW
```

Rule-based detection provides reliable detection of known attack patterns, while the Machine Learning model adds another layer for suspicious requests that may not exactly match existing signatures.

---

## Machine Learning Pipeline

The Machine Learning component was developed using the **CSIC 2010 HTTP dataset**.

The dataset contains both legitimate and malicious HTTP requests and was used to train and evaluate the classification models.

### Input Data

The primary HTTP information used during model development includes:

```text
Method
URL
Content
Content-Length
```

Environment-specific and highly constant HTTP headers were removed during preprocessing to reduce dataset-specific bias and improve model generalization.

---

## Feature Engineering

Instead of relying only on raw HTTP strings, structural characteristics are extracted from URLs and request content.

Examples include:

| Feature | Description |
|---|---|
| URL Length | Total number of characters in the URL |
| Path Length | Length of the URL path |
| Path Depth | Number of path levels |
| Query Length | Length of the query string |
| Parameters | Number of URL parameters |
| Digits | Number of numeric characters |
| Letters | Number of alphabetic characters |
| Special Characters | Number of special characters |
| Encoded Characters | Detects encoded URL content |
| Unusual Character Ratio | Ratio of unusual characters |
| Hostname Length | Length of the hostname |
| File Extension | Detects file extensions |
| Content Length | Length of request content |

The HTTP method is handled as a categorical feature during preprocessing.

---

## Models Evaluated

Several Machine Learning algorithms were evaluated during model development:

| Model | Purpose |
|---|---|
| Logistic Regression | Linear probabilistic classifier |
| Random Forest | Tree-based ensemble classifier |
| Linear SVM | Linear maximum-margin classifier |
| SGD Classifier | Efficient linear classifier trained using SGD |

The final model was selected based not only on training performance but also on its ability to **generalize to previously unseen HTTP requests**.

---

## Model Evaluation

The models were evaluated using several classification metrics:

- Accuracy
- Precision
- Recall
- F1-score
- Confusion Matrix
- ROC Curve
- ROC-AUC

Using multiple metrics provides a more complete understanding of model behavior than relying on accuracy alone.

---

## Reverse Proxy

The WAF operates as a reverse proxy in front of the protected web application.

The current development environment uses **DVWA (Damn Vulnerable Web Application)** as the protected target.

```text
Client
   │
   ▼
WAF
   │
   ├── Malicious → Block
   │
   └── Safe
        │
        ▼
       DVWA
```

The current development target runs at:

```text
http://127.0.0.1:8080
```

Requests are inspected by the WAF before accepted traffic is forwarded to the target application.

---

## Project Structure

```text
WAF-Based-on-ML/
│
├── app/
│   ├── api/
│   ├── core/
│   ├── dashboard/
│   ├── database/
│   │
│   ├── detection/
│   │   ├── ml/
│   │   ├── rules/
│   │   └── engine.py
│   │
│   ├── middleware/
│   │   └── waf_middleware.py
│   │
│   ├── models/
│   ├── schemas/
│   └── main.py
│
├── migrations/
│
├── ml_models/
│   ├── Features.py
│   ├── Model.py
│   ├── Model_V1.1.py
│   └── test_model.py
│
├── tests/
│   ├── test_engine.py
│   ├── test_middleware.py
│   └── test_rules.py
│
├── Model.ipynb
├── .env.example
├── .gitignore
├── alembic.ini
├── requirements.txt
└── README.md
```

---

## Technology Stack

### Backend

![Python](https://img.shields.io/badge/Python-3.x-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-Framework-green)

- Python
- FastAPI
- Uvicorn
- HTTPX

### Machine Learning

- Scikit-learn
- Pandas
- NumPy
- Joblib

### Database

- SQLAlchemy
- Alembic
- SQLite

### Dashboard

- HTML
- CSS
- JavaScript

### Testing

- Pytest

---

## Getting Started

### Prerequisites

Make sure the following are installed:

- Python 3.x
- pip
- Git

A running protected application such as DVWA is required if you want to test the reverse proxy functionality.

---

### 1. Clone the Repository

```bash
git clone https://github.com/AmrKallab/WAF-Based-on-ML.git
cd WAF-Based-on-ML
```

### 2. Create a Virtual Environment

#### Windows

```bash
python -m venv .venv
.venv\Scripts\activate
```

#### Linux / macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables

Create a `.env` file using `.env.example` as a reference.

```bash
cp .env.example .env
```

On Windows:

```bash
copy .env.example .env
```

Configure the required application, database, ML, dashboard, and security settings.

> Never commit real credentials or secret keys to the repository.

### 5. Run the WAF

From the project root:

```bash
uvicorn app.main:app --reload
```

The WAF will start receiving HTTP requests and inspect them before forwarding accepted traffic to the protected application.

---

## Testing

The project includes automated tests for the main WAF components.

Run the complete test suite using:

```bash
pytest
```

The tests cover core components including:

```text
Detection Engine
WAF Middleware
Security Rules
```

---

## Request Processing Example

### Normal Request

```text
Client
  │
  ▼
WAF Middleware
  │
  ├── Request Size ✓
  ├── IP Rules ✓
  ├── Rate Limit ✓
  ├── Security Rules ✓
  └── ML Detection → Normal
  │
  ▼
Reverse Proxy
  │
  ▼
Protected Application
```

### Malicious Request

```text
Client
  │
  ▼
WAF Middleware
  │
  ▼
Detection Engine
  │
  ▼
Attack Detected
  │
  ├── Log Request
  ├── Update Dashboard
  │
  ▼
403 Forbidden
```

---

## Project Summary

**WAF Based on ML** is a hybrid Web Application Firewall that combines **rule-based detection** with **Machine Learning** to analyze and filter malicious HTTP traffic before it reaches a protected web application.

The system integrates multiple security layers, including attack detection, ML-based request classification, IP access control, rate limiting, request logging, and real-time monitoring through a web dashboard.

This project demonstrates the practical integration of **Web Security, Backend Engineering, Machine Learning, and Database Management** into a unified security system.
