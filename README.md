[README.md](https://github.com/user-attachments/files/28327472/README.md)
# ShopOSINT - OSINT sur liens de paiement

```
███████╗██╗  ██╗ ██████╗ ██████╗  ██████╗ ███████╗██╗███╗   ██╗████████╗
██╔════╝██║  ██║██╔═══██╗██╔══██╗██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝
███████╗███████║██║   ██║██████╔╝██║   ██║███████╗██║██╔██╗ ██║   ██║
╚════██║██╔══██║██║   ██║██╔═══╝ ██║   ██║╚════██║██║██║╚██╗██║   ██║
███████║██║  ██║╚██████╔╝██║     ╚██████╔╝███████║██║██║ ╚████║   ██║
╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝      ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝
            Payment Link OSINT · Stripe · SumUp · Revolut · Lydia
```

**ShopOSINT** est un outil d'OSINT qui résout silencieusement un lien de paiement ou un profil
(Stripe, SumUp, Revolut, Lydia) en informations marchand & identité, sans payer, sans carte,
sans déclencher de transaction. Idéal pour pivoter sur une boutique ou un compte frauduleux.

Version CLI du module [roso.info/shoposint](https://roso.info/shoposint/).

## Fonctionnalités

- **Stripe** — décode le fragment `#fid` d'un lien checkout (URL-decode → base64 → XOR-5 → JSON)
  pour la clé publishable, puis rejoue le `POST /init` que le navigateur émet de toute façon.
  Récupère : nom marchand, email/téléphone support, site, libellé bancaire, produit, devise, pays.
  100% silencieux et répétable.
- **SumUp** — lit le `checkout_id` de la page `b2c` puis interroge l'API checkout pour révéler
  l'email du marchand (`pay_to_email`), le nom, le montant. ⚠ Crée une tentative de paiement en
  **échec** (sans débit), à usage unique par lien.
- **Revolut** — profil public `revolut.me/<revtag>` : nom, pays, revtag, moyens de paiement.
- **Lydia** — cagnotte `pots.lydia.me/collect/<slug>` (API anonyme) : nom de l'organisateur,
  IBAN/BIC bénéficiaire, titre, montant collecté.
- Export des résultats en JSON

## Dépendances

- Python 3.8+

```
curl_cffi>=0.7.0
```

> `curl_cffi` (impersonation TLS Chrome) est requis : les API Stripe/SumUp filtrent les clients
> HTTP au fingerprint JA3. Les requêtes `requests` standard sont bloquées.

## Installation

```bash
git clone https://github.com/redsecurityfr/ShopOSINT.git
cd ShopOSINT
pip install -r requirements.txt
```

## Utilisation

```bash
# Mode interactif
python shoposint.py

# Résolution directe
python shoposint.py pay.sumup.com/b2c/ABCD1234
python shoposint.py revolut.me/johndoe
python shoposint.py "checkout.stripe.com/c/pay/cs_live_...#fid..."
python shoposint.py pots.lydia.me/collect/ma-cagnotte

# Mode verbeux + export JSON
python shoposint.py revolut.me/johndoe -v --export

# Sortie JSON brute (scripting)
python shoposint.py revolut.me/johndoe --json
```

## Options

| Option | Description |
|--------|-------------|
| `url` | Lien de paiement / profil à résoudre |
| `-v, --verbose` | Mode verbeux (détaille les étapes) |
| `--export` | Exporter les résultats en JSON |
| `--json` | Sortie JSON brute sur stdout (sans bannière ni couleurs) |

## Liens supportés

| Fournisseur | Format de lien | Données récupérées |
|-------------|----------------|--------------------|
| **Stripe** | `checkout.stripe.com/c/pay/cs_...#fid...` · `buy.stripe.com/...` | nom, email, téléphone, site, libellé bancaire, produit, pays |
| **SumUp** | `pay.sumup.com/b2c/CODE` | nom, email marchand, montant, pays |
| **Revolut** | `revolut.me/<revtag>` | nom, revtag, pays, moyens de paiement |
| **Lydia** | `pots.lydia.me/collect/<slug>` | organisateur, IBAN, BIC, montant collecté |

## Auteur

[@RedSecurityfr](https://x.com/RedSecurityfr) - [red-security.fr](https://red-security.fr) - [osint-opsec.fr](https://osint-opsec.fr) - [roso.info](https://roso.info)

## Communauté

Rejoignez la communauté OSINT sur Discord : [https://discord.com/invite/rPkY5jaTfF](https://discord.com/invite/rPkY5jaTfF)
