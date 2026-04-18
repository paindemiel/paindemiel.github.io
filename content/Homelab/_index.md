---
toc: false
---

Dans cette section du site je vais aborder la construction de mon homelab avec les services que j'auto héberge.

L'objectif est de tout gérer avec une approche Devops, donc automatiser la création de l'infra, la récupération des données applicatives depuis un backup ainsi que la destruction de l'infra ou d'une partie de cette dernière.

J'essaye au maximum d'utiliser des outils et technologies libre et open source, de plus dans cette série à part l'achat de dns je n'utiliserais rien de payant. Cependant l'usage étant non-commercial l'utilisation de certains outils ou technologies pourrais devenir payant dans le cadre d'une utilisation commercial.

Voici un schéma qui présente de manière grossière l'infrastructure que j'essaye de mettre en place :
```mermaid
flowchart TB;
    V[Internet] --> Z;
    W[Ludus] --> Z;
    X[Razer] --> Z;
    Y[Tower] --> Z;
    Z[Box Wifi] --> FW[Firewall - Router];
    FW --> Securité;
    FW --> VPN;
    FW --> Infra;
    FW --> Applications;
subgraph Proxmox;
    subgraph Securité;
        SIEM;
        Crowdsec;
    end;
    subgraph VPN;
        Headscale;
        Vma[VM - advertising routes];
    end;
    subgraph Infra;
        Openbao;
        Caddy;
        Blocky;
    end;
    subgraph Applications;
        Forgejo;
        Docmost;
        Memos;
        Immich;
        Share;
    end;
    FW --> PBS;
end;
```
