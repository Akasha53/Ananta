# Recherche comparative — résolution d'entités

Cette note documente les concepts étudiés avant le durcissement du moteur.
L'implémentation Ananta est originale : aucun code tiers n'a été copié.

## Projets étudiés

| Projet | Licence | Concept retenu dans Ananta |
|---|---|---|
| [Splink](https://github.com/moj-analytical-services/splink) | MIT | Pondérer les preuves rares et stables plus fortement que les noms communs ; rendre le score explicable. |
| [Python Record Linkage Toolkit](https://github.com/J535D165/recordlinkage) | BSD-3-Clause | Séparer génération de candidats, comparaison champ par champ et décision finale. |
| [SpiderFoot](https://github.com/smicallef/spiderfoot) | MIT | Corrélations explicables, seuils, filtrage et conservation des candidats rejetés. |
| [OpenCTI](https://github.com/OpenCTI-Platform/opencti) | Apache-2.0 pour l'édition communautaire | Porter confiance, provenance et temporalité au niveau des relations. |
| [IntelOwl](https://github.com/intelowlproject/IntelOwl) | AGPL-3.0 | Idée de playbooks et de pivots contrôlés uniquement ; aucun code repris afin de préserver la licence MIT d'Ananta. |
| [OCCRP Aleph](https://docs.aleph.occrp.org/about/) | Projet open source, composants sous licences déclarées par le dépôt | Garder l'analyste dans la boucle pour les candidats ambigus et faciliter la navigation dans le graphe. |

## Adaptation réalisée

- trois profils de rapprochement : `strict`, `balanced`, `exploratory` ;
- score multi-preuves avec veto sur les identifiants stables contradictoires ;
- homonymes conservés sous des clés distinctes au lieu d'une fusion nominale ;
- seuils de pivot par type de sélecteur et quarantaine des pistes faibles ;
- journal `resolution` sérialisé et onglet d'explication dans l'interface ;
- résultats web et profils sociaux classés comme candidats avant confirmation ;
- sanctions nominales soumises à revue manuelle, confirmation par identifiant ;
- tests adversariaux déterministes sur noms, sigles, personnes, registres,
  domaines, sanctions et parcours du graphe.
- file de revue persistante pour confirmer, rejeter ou documenter un candidat ;
- faux positifs exclus logiquement sans suppression de la trace d'audit ;
- historique `first_seen` / `last_seen` des entités et relations récurrentes ;
- corrélations YAML sans `eval`, avec métriques et opérateurs en liste blanche.

## Pistes suivantes

- apprendre les pondérations sur un jeu de paires annotées, sans remplacer les
  veto déterministes ;
- mesurer précision, rappel et taux de faux positifs sur un corpus versionné ;
- exporter/importer un corpus de décisions analyste anonymisé pour cette mesure.

Le moteur de règles utilise `yaml.safe_load` de PyYAML, déjà présent dans le
projet. Aucun code de SpiderFoot, OpenCTI ou Aleph n'a été copié. Les playbooks
Enterprise d'OpenCTI ne sont ni importés ni reproduits.
