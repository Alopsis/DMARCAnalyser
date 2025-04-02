# Description

Cet outil a été créé pour faire un monitoring des enregistrements DMARC des domaines. 

# Fonctionnement 

Ce programme prend en compte une liste de domaine persistante afin d'effectuer differentes actions pour le monitoring de ces dernier dans le but de trouver les misconfigurations DMARC. 

Voici les differentes fonctionnalitées du programme : 
- Analyse des misconfigurations DMARC 
- Analyse des changements de configuration DNS des domaines 
- Récuperation des records DNS 

# Installation 
```
- python3 -m venv dep
- source ./dep/bin/activate
- pip install -r requirements.txt
```

# Utilisation 

```
- python3 script.py
> addConfig 
> google.com
> checkConfig
> quit
```

## Help
[analyseMisconfig]
- Permet d'analyser l'enregistrement DMARC d'un domaine dans le but de trouver les misconfigurations.

[checkConfig]
- Permet de regarder tous les domaines actuellement monitorés.

[addConfig]
- Permet d'ajouter un domaine a monitorer.

[getChangement]
- Permet de voir les changements avec les anciennes informations pour voir les ajouts et les suppressions. 

[getDNSRecord]

- Permet d'afficher les champs DNS d'un domaine 

[quit]
- Permet de quitter le programme 