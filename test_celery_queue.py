"""Test Celery queue routing"""
import os, sys
os.chdir(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

print("Loading Celery...")
from tasks import app as celery_app, scan_osint_layer1_task

import redis
r = redis.from_url('redis://localhost:6379/0')

print()
print("Test 1: delay() - should use routing")
result1 = scan_osint_layer1_task.delay("test1.example.com", None)
print(f"  Task ID: {result1.id}")
print(f"  osint_fast queue: {r.llen('osint_fast')}")
print(f"  celery queue: {r.llen('celery')}")

print()
print("Test 2: apply_async with explicit queue")
result2 = scan_osint_layer1_task.apply_async(args=["test2.example.com", None], queue='osint_fast')
print(f"  Task ID: {result2.id}")
print(f"  osint_fast queue: {r.llen('osint_fast')}")
print(f"  celery queue: {r.llen('celery')}")

print()
print("=== QUEUES STATUS ===")
for q in ['celery', 'default', 'osint_fast', 'osint_medium']:
    print(f"  {q}: {r.llen(q)}")
