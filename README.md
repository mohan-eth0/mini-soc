# Mini SOC Detection Engine

A lightweight SOC-style detection and response engine written in Python.
Designed to detect SSH-based attacks using log analysis and rule-based logic.

## Features
- SSH log collection (auth.log, journalctl)
- Rule-based detection engine
- Alert generation
- Automated response hook
- Pytest-based detection validation

## Project Structure
collectors/     → Log ingestion  
engine/         → Detection & alert logic  
rules/          → Detection rules  
response/       → Automated response scripts  
reports/        → SOC outputs  
tests/          → Pytest validation  

## How It Works
1. Collects SSH authentication logs
2. Applies detection rules
3. Generates alerts
4. Triggers response actions (optional)

## Run
```bash
python main.py
