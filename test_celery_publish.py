"""Test script to diagnose Celery task publishing"""
import os
import sys

# Set up path
os.chdir(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

print("=== CELERY TASK PUBLISH TEST ===")
print()

# Step 1: Check broker config
print("1. Checking broker config...")
from celery_config import CELERY_CONFIG
print(f"   broker_url: {CELERY_CONFIG['broker_url']}")
print(f"   task_default_queue: {CELERY_CONFIG['task_default_queue']}")
print()

# Step 2: Import the Celery app
print("2. Importing Celery app from tasks.py...")
from tasks import app as celery_app
print(f"   app.main: {celery_app.main}")
print(f"   app.conf.broker_url: {celery_app.conf.broker_url}")
print()

# Step 3: Check registered tasks
print("3. Checking registered tasks...")
task_names = [t for t in celery_app.tasks.keys() if 'ananta' in t]
for t in task_names[:5]:
    print(f"   - {t}")
print()

# Step 4: Import a specific task
print("4. Importing scan_osint_layer1_task...")
from tasks import scan_osint_layer1_task
print(f"   task name: {scan_osint_layer1_task.name}")
print(f"   task app: {scan_osint_layer1_task.app.main}")
print()

# Step 5: Try to publish
print("5. Publishing task with delay()...")
import time
start = time.time()
try:
    result = scan_osint_layer1_task.delay("test-publish.example.com", None)
    elapsed = time.time() - start
    print(f"   SUCCESS in {elapsed:.2f}s")
    print(f"   Task ID: {result.id}")
    print(f"   Task state: {result.state}")
except Exception as e:
    elapsed = time.time() - start
    print(f"   FAILED after {elapsed:.2f}s: {e}")
print()

# Step 6: Check Redis queues
print("6. Checking Redis queues...")
import redis
r = redis.from_url('redis://localhost:6379/0')
for q in ['celery', 'default', 'osint_fast', 'osint_medium', 'osint_critical']:
    length = r.llen(q)
    if length > 0:
        print(f"   {q}: {length} items")
    else:
        print(f"   {q}: empty")

print()
print("=== TEST COMPLETE ===")
