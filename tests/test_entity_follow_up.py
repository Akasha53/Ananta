from entity_research.follow_up import (
    automatic_follow_up_options,
    dossier_follow_up_facts,
)
from entity_research.identifiers import EntityKind, SelectorType, make_selector
from entity_research.schema import Dossier, EntityNode


def _person_dossier() -> Dossier:
    person = EntityNode(
        kind=EntityKind.PERSON,
        label="Alexandra Latouche",
        selectors=[
            make_selector(SelectorType.PERSON_NAME, "Alexandra Latouche"),
        ],
        confidence=0.9,
        is_root=True,
    )
    company = EntityNode(
        kind=EntityKind.ORGANIZATION,
        label="SCI MARGOT",
        selectors=[
            make_selector(SelectorType.ORG_NAME, "SCI MARGOT"),
            make_selector(SelectorType.SIREN, "123456789"),
        ],
        confidence=0.72,
    )
    return Dossier(
        run_id="pass-1",
        query="Alexandra Latouche",
        kind=EntityKind.PERSON,
        label="Alexandra Latouche",
        root_key=person.key,
        entities=[person, company],
    )


def test_follow_up_reinjects_linked_entities_without_misassigning_their_ids():
    facts = dossier_follow_up_facts(_person_dossier())

    assert {
        "label": "Société liée",
        "value": "SCI MARGOT",
        "confidence": 0.72,
    } in facts
    assert not any(fact["value"] == "123456789" for fact in facts)


def test_follow_up_does_not_flatten_same_name_homonym_into_the_root():
    dossier = _person_dossier()
    dossier.entities.append(
        EntityNode(
            kind=EntityKind.PERSON,
            label="ALEXANDRA LATOUCHE",
            key="person:alexandra latouche~homonym",
            confidence=0.85,
        )
    )

    facts = dossier_follow_up_facts(dossier)

    assert not any(
        fact["label"] == "Personne liée"
        and fact["value"].casefold() == "alexandra latouche"
        for fact in facts
    )


def test_automatic_follow_up_is_explicit_and_uses_tool_provenance():
    options = automatic_follow_up_options(
        _person_dossier(),
        {
            "mode": "standard",
            "briefing_text": "Information initiale.",
            "briefing_facts": [],
        },
    )

    assert options["mode"] == "standard"
    assert options["briefing_origin"] == "tool"
    assert "ses entreprises, mandats actuels et passés" in options["briefing_text"]
    assert "liens familiaux explicitement documentés" in options["briefing_text"]
    assert "Ne fusionner aucun homonyme" in options["briefing_text"]
    assert "ni document d'identité, ni visa" in options["briefing_text"]
    assert any(fact["value"] == "SCI MARGOT" for fact in options["briefing_facts"])


def test_worker_schedules_pass_two_after_persisting_pass_one(
    monkeypatch,
    db_session,
):
    import entity_research
    import tasks
    from database import EntityResearchRun
    from entity_research.storage import create_run
    from tests.conftest import TestingSessionLocal

    run_id = "automatic-pass-1"
    create_run(
        db_session,
        run_id=run_id,
        query="Alexandra Latouche",
        job_id=run_id,
        mode="standard",
        created_by="local",
        active_owner="local",
    )

    def fake_research(query, **kwargs):
        dossier = _person_dossier()
        dossier.run_id = kwargs["run_id"]
        dossier.query = query
        return dossier

    scheduled = []

    def fake_apply_async(*, args, task_id):
        scheduled.append({"args": args, "task_id": task_id})

    monkeypatch.setattr(entity_research, "research_entity", fake_research)
    monkeypatch.setattr(tasks, "SessionLocal", TestingSessionLocal)
    monkeypatch.setattr(tasks.entity_research_task, "apply_async", fake_apply_async)

    result = tasks.entity_research_task.apply(
        args=[
            "Alexandra Latouche",
            {
                "mode": "standard",
                "_created_by": "local",
                "_pass_number": 1,
            },
        ],
        task_id=run_id,
        throw=True,
    ).get()

    assert result["follow_up_run_id"] == scheduled[0]["task_id"]
    child = (
        db_session.query(EntityResearchRun)
        .filter(EntityResearchRun.parent_run_id == run_id)
        .one()
    )
    assert child.pass_number == 2
    assert child.status == "PENDING"
    assert scheduled[0]["args"][1]["_pass_number"] == 2
    assert scheduled[0]["args"][1]["briefing_origin"] == "tool"
