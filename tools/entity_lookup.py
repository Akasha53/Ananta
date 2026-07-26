"""
CLI de recherche d'entité.

Utile pour tester le moteur sans lancer l'API, ou pour l'intégrer dans un
script d'analyse.

Exemples:
    python -m tools.entity_lookup "ACME INDUSTRIES SAS"
    python -m tools.entity_lookup "552 100 554" --mode passive --format json
    python -m tools.entity_lookup "contact@acme.fr" --purpose kyc_aml --save
    python -m tools.entity_lookup --preview "Jean Dupont +33 6 12 34 56 78"
    python -m tools.entity_lookup --sources
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Optional


def _print_progress(percent: int, message: str) -> None:
    sys.stderr.write(f"\r[{percent:3d}%] {message[:70]:<70}")
    sys.stderr.flush()


def cmd_sources() -> int:
    from entity_research import describe_sources

    sources = describe_sources()
    available = sum(1 for s in sources if s["available"])
    print(f"{len(sources)} sources ({available} disponibles sans configuration supplémentaire)\n")

    for layer in (1, 2, 3):
        layer_sources = [s for s in sources if s["layer"] == layer]
        if not layer_sources:
            continue
        print(f"── Couche {layer} " + "─" * 50)
        for source in layer_sources:
            mark = "✓" if source["available"] else "○"
            key_note = "" if source["available"] else f"  (clé: {', '.join(source['api_key_env'])})"
            print(f" {mark} {source['id']:<18} {source['coverage']:<7} {source['name']}{key_note}")
            print(f"   {source['description'][:100]}")
            print(f"   accepte: {', '.join(source['accepts'])}")
        print()
    return 0


def cmd_preview(query: str, entity_kind: Optional[str], region: str) -> int:
    from entity_research import preview_selectors

    preview = preview_selectors(query, entity_kind=entity_kind, default_region=region)

    print(f"Requête      : {preview['query']}")
    print(f"Nature       : {preview['entity_kind']} ({preview['kind_confidence']:.0%})")
    print(f"Libellé      : {preview['label']}")
    print(f"Données perso: {'oui' if preview['personal_data_involved'] else 'non'}\n")

    print("Sélecteurs reconnus:")
    for selector in preview["selectors"]:
        sources = preview["planned_sources"].get(
            f"{selector['type']}:{str(selector['value']).lower()}", []
        )
        flag = " [perso]" if selector["personal_data"] else ""
        print(f"  {selector['type']:<16} {selector['value']:<40} {selector['confidence']:.0%}{flag}")
        if sources:
            print(f"  {'':<16} → {', '.join(sources)}")
    return 0


def cmd_research(args: argparse.Namespace) -> int:
    from entity_research import research_entity

    dossier = research_entity(
        args.query,
        mode=args.mode,
        purpose=args.purpose,
        entity_kind=args.kind,
        language=args.language,
        template=args.template,
        allow_account_enumeration=args.allow_enumeration,
        allow_breach_data=args.allow_breach,
        authorized_investigation_acknowledged=args.acknowledge_authorization,
        redact_personal_data=args.redact,
        use_llm=not args.no_llm,
        only_sources=args.only.split(",") if args.only else None,
        exclude_sources=args.exclude.split(",") if args.exclude else None,
        default_region=args.region,
        progress=None if args.quiet else _print_progress,
    )

    if not args.quiet:
        sys.stderr.write("\n\n")

    if args.format == "json":
        print(json.dumps(dossier.to_dict(), ensure_ascii=False, indent=2))
    elif args.format == "graph":
        print(json.dumps(dossier.graph(), ensure_ascii=False, indent=2))
    else:
        print(dossier.report_markdown)

    if args.save:
        from database import SessionLocal
        from entity_research.storage import persist_dossier

        session = SessionLocal()
        try:
            run = persist_dossier(
                session,
                dossier,
                mode=args.mode,
                purpose=args.purpose,
                language=args.language,
                report_template=args.template,
            )
            sys.stderr.write(f"Dossier enregistré : run_id={run.run_id}\n")
        finally:
            session.close()

    return 0 if dossier.entities else 1


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="entity_lookup",
        description="Recherche d'entité Ananta : d'un simple indice au dossier complet",
    )
    parser.add_argument("query", nargs="?", help="Nom, email, téléphone, domaine, SIREN, LEI...")
    parser.add_argument("--preview", action="store_true", help="Analyse la requête sans rien interroger")
    parser.add_argument("--sources", action="store_true", help="Liste le catalogue des sources")

    parser.add_argument("--mode", default="standard", choices=["passive", "standard", "deep"])
    parser.add_argument("--kind", default=None, choices=["person", "organization"])
    parser.add_argument(
        "--purpose",
        default="due_diligence",
        choices=[
            "due_diligence", "kyc_aml", "fraud_investigation", "security_assessment",
            "journalism", "recruitment", "legal_proceedings", "self_check", "research",
            "authorized_investigation",
        ],
        help="Finalité déclarée (base légale RGPD)",
    )
    parser.add_argument("--language", default="fr", choices=["fr", "en", "es", "de"])
    parser.add_argument(
        "--template", default="detailed", choices=["detailed", "executive", "technical", "minimal"]
    )
    parser.add_argument("--region", default="FR", help="Région par défaut pour les téléphones")
    parser.add_argument("--format", default="markdown", choices=["markdown", "json", "graph"])
    parser.add_argument("--only", help="Restreindre à ces sources (séparées par des virgules)")
    parser.add_argument("--exclude", help="Exclure ces sources (séparées par des virgules)")
    parser.add_argument("--allow-enumeration", action="store_true", help="Autorise la recherche de pseudonyme")
    parser.add_argument("--allow-breach", action="store_true", help="Autorise les bases de fuites")
    parser.add_argument(
        "--acknowledge-authorization",
        action="store_true",
        help="Atteste le mandat explicite requis par authorized_investigation",
    )
    parser.add_argument("--redact", action="store_true", help="Masque les données personnelles")
    parser.add_argument("--no-llm", action="store_true", help="Désactive la synthèse LLM")
    parser.add_argument("--save", action="store_true", help="Enregistre le dossier en base")
    parser.add_argument("--quiet", action="store_true", help="Sans barre de progression")

    args = parser.parse_args(argv)

    if args.sources:
        return cmd_sources()

    if not args.query:
        parser.error("une requête est requise (ou utilisez --sources)")

    if args.preview:
        return cmd_preview(args.query, args.kind, args.region)

    return cmd_research(args)


if __name__ == "__main__":
    raise SystemExit(main())
