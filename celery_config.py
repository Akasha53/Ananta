"""
Configuration avancée de Celery pour Ananta - Architecture Multi-Workers

Ce fichier définit:
1. Plusieurs queues spécialisées par type de tâche
2. Routage automatique des tâches vers les bonnes queues
3. Priorités pour les tâches critiques
4. Configuration optimisée par type de worker
"""

import os
from kombu import Queue, Exchange

# URL Redis
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

# ==================== QUEUES DÉFINITION ====================

# Exchange principal (direct routing)
default_exchange = Exchange('ananta', type='direct')

# Définition des queues avec leurs priorités
CELERY_QUEUES = (
    # Queue haute priorité pour scans urgents
    Queue('priority',
          exchange=default_exchange,
          routing_key='priority',
          priority=10),

    # Queue pour scans Layer 1 (rapides, passifs)
    Queue('osint_fast',
          exchange=default_exchange,
          routing_key='osint.fast',
          priority=7),

    # Queue pour scans Layer 2 (moyens, conditionnels)
    Queue('osint_medium',
          exchange=default_exchange,
          routing_key='osint.medium',
          priority=5),

    # Queue pour scans Layer 3 (lents, nécessitent approbation)
    Queue('osint_critical',
          exchange=default_exchange,
          routing_key='osint.critical',
          priority=3),

    # Queue pour tâches de maintenance et nettoyage
    Queue('maintenance',
          exchange=default_exchange,
          routing_key='maintenance',
          priority=1),

    # Queue par défaut (fallback)
    Queue('default',
          exchange=default_exchange,
          routing_key='default',
          priority=5),
)

# ==================== ROUTING ====================

# Règles de routage automatique des tâches vers les queues
CELERY_ROUTES = {
    # Scans OSINT par layer
    'ananta.scan_osint_layer1': {
        'queue': 'osint_fast',
        'routing_key': 'osint.fast',
    },
    'ananta.scan_osint_layer2': {
        'queue': 'osint_medium',
        'routing_key': 'osint.medium',
    },
    'ananta.scan_osint_layer3': {
        'queue': 'osint_critical',
        'routing_key': 'osint.critical',
    },

    # Scan générique (ancien comportement, utilise routing dynamique)
    'ananta.scan_osint': {
        'queue': 'osint_medium',  # Par défaut en medium
        'routing_key': 'osint.medium',
    },

    # Tâches de maintenance
    'ananta.cleanup_old_jobs': {
        'queue': 'maintenance',
        'routing_key': 'maintenance',
    },
    'ananta.cleanup_cache': {
        'queue': 'maintenance',
        'routing_key': 'maintenance',
    },

    # Tâches prioritaires
    'ananta.priority_scan': {
        'queue': 'priority',
        'routing_key': 'priority',
    },

    # Tâches parallèles (architecture chord)
    'ananta.execute_layer1_tools': {
        'queue': 'osint_fast',
        'routing_key': 'osint.fast',
    },
    'ananta.execute_layer2_tools': {
        'queue': 'osint_medium',
        'routing_key': 'osint.medium',
    },
    'ananta.aggregate_parallel_results': {
        'queue': 'default',
        'routing_key': 'default',
    },
    'ananta.scan_parallel': {
        'queue': 'default',
        'routing_key': 'default',
    },
}

# ==================== CONFIGURATION CELERY ====================

CELERY_CONFIG = {
    # Broker & Backend
    'broker_url': REDIS_URL,
    'result_backend': REDIS_URL,

    # Serialization
    'task_serializer': 'json',
    'accept_content': ['json'],
    'result_serializer': 'json',

    # Timezone
    'timezone': 'UTC',
    'enable_utc': True,

    # Task tracking
    'task_track_started': True,
    'task_send_sent_event': True,
    'task_store_eager_result': True,

    # Timeouts (par défaut, peuvent être overridés par queue)
    'task_time_limit': 300,  # 5 minutes hard limit
    'task_soft_time_limit': 270,  # 4.5 minutes soft limit

    # Worker configuration
    'worker_prefetch_multiplier': 1,  # Une tâche à la fois
    'worker_max_tasks_per_child': 100,  # Redémarrer après 100 tâches
    'worker_disable_rate_limits': False,

    # Queues & Routes
    'task_queues': CELERY_QUEUES,
    'task_routes': CELERY_ROUTES,
    'task_default_queue': 'default',
    'task_default_exchange': 'ananta',
    'task_default_routing_key': 'default',

    # Result backend configuration
    'result_expires': 3600,  # Résultats expirent après 1h
    'result_extended': True,

    # Retry policy
    'task_acks_late': True,  # Acknowledge après exécution
    'task_reject_on_worker_lost': True,

    # Redis specific
    'broker_connection_retry': True,
    'broker_connection_retry_on_startup': True,
    'broker_connection_max_retries': 10,
}

# ==================== WORKER PROFILES ====================

WORKER_PROFILES = {
    'fast': {
        'description': 'Worker optimisé pour scans rapides (Layer 1)',
        'queues': ['osint_fast', 'priority'],
        'concurrency': 4,  # Peut gérer 4 scans en parallèle
        'max_tasks_per_child': 200,
        'time_limit': 60,  # 1 minute max
        'soft_time_limit': 50,
    },

    'medium': {
        'description': 'Worker pour scans moyens (Layer 2)',
        'queues': ['osint_medium', 'priority', 'default'],
        'concurrency': 2,  # 2 scans en parallèle
        'max_tasks_per_child': 100,
        'time_limit': 300,  # 5 minutes max
        'soft_time_limit': 270,
    },

    'critical': {
        'description': 'Worker pour scans critiques (Layer 3)',
        'queues': ['osint_critical', 'priority'],
        'concurrency': 1,  # Un seul scan à la fois
        'max_tasks_per_child': 50,
        'time_limit': 600,  # 10 minutes max
        'soft_time_limit': 540,
    },

    'maintenance': {
        'description': 'Worker pour tâches de maintenance',
        'queues': ['maintenance'],
        'concurrency': 1,
        'max_tasks_per_child': 20,
        'time_limit': 1800,  # 30 minutes max
        'soft_time_limit': 1740,
    },

    'general': {
        'description': 'Worker généraliste (tous types de tâches)',
        'queues': ['osint_fast', 'osint_medium', 'osint_critical', 'maintenance', 'priority', 'default'],
        'concurrency': 2,
        'max_tasks_per_child': 100,
        'time_limit': 300,
        'soft_time_limit': 270,
    }
}

# ==================== HELPERS ====================

def get_worker_command(profile_name: str) -> str:
    """
    Génère la commande Celery pour lancer un worker avec le profil spécifié.

    Args:
        profile_name: Nom du profil ('fast', 'medium', 'critical', 'maintenance', 'general')

    Returns:
        Commande shell complète pour lancer le worker

    Example:
        >>> get_worker_command('fast')
        'celery -A tasks worker -Q osint_fast,priority -c 4 --max-tasks-per-child=200 --time-limit=60 -n fast@%h --loglevel=info'
    """
    if profile_name not in WORKER_PROFILES:
        raise ValueError(f"Profil '{profile_name}' inconnu. Profils disponibles: {list(WORKER_PROFILES.keys())}")

    profile = WORKER_PROFILES[profile_name]
    queues = ','.join(profile['queues'])

    cmd = (
        f"celery -A tasks worker "
        f"-Q {queues} "
        f"-c {profile['concurrency']} "
        f"--max-tasks-per-child={profile['max_tasks_per_child']} "
        f"--time-limit={profile['time_limit']} "
        f"-n {profile_name}@%h "
        f"--loglevel=info"
    )

    # Ajouter --pool=solo pour Windows
    import platform
    if platform.system() == 'Windows':
        cmd += " --pool=solo"

    return cmd


def print_worker_commands():
    """Affiche toutes les commandes pour lancer les workers."""
    print("=" * 80)
    print("ANANTA - Commandes Workers Spécialisés")
    print("=" * 80)

    for profile_name, profile in WORKER_PROFILES.items():
        print(f"\n📊 {profile_name.upper()} Worker")
        print(f"   Description: {profile['description']}")
        print(f"   Queues: {', '.join(profile['queues'])}")
        print(f"   Concurrency: {profile['concurrency']}")
        print(f"\n   Commande:")
        print(f"   {get_worker_command(profile_name)}")
        print()

    print("=" * 80)


if __name__ == "__main__":
    print_worker_commands()
