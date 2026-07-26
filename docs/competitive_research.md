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

## Pistes suivantes

- apprendre les pondérations sur un jeu de paires annotées, sans remplacer les
  veto déterministes ;
- afficher une file de revue humaine permettant d'accepter ou rejeter un
  candidat et de conserver la justification de l'opérateur ;
- mesurer précision, rappel et taux de faux positifs sur un corpus versionné ;
- ajouter `first_seen` / `last_seen` aux relations pour mieux distinguer une
  identité actuelle d'une ancienne observation.
