# pages

Soukromé stránky na GitHub Pages. Obsah je zašifrovaný jedním heslem; v repozitáři je čitelný jen obecný zavaděč a nástroj, tedy jak trezor funguje, ne co je v něm.

## Jak to funguje

- `index.html` a `loader.js` ukážou zámek. Z hesla se přes PBKDF2-SHA256 (600 000 iterací, náhodná sůl) odvodí klíč, který z `vault/locks.json` rozbalí datový klíč (AES-256-GCM). Ten se uloží do IndexedDB prohlížeče jako nepřenositelný klíč WebCrypto, takže ho nevyčte ani skript, a platí do zamknutí.
- `sw.js` (Service Worker) zachytí žádost o soubor stránky, najde ho v zašifrovaném seznamu `vault/contents.bin`, stáhne jeho blok z `vault/blocks/`, dešifruje a vrátí. Do Cache Storage ukládá jen šifrované bloky.
- `404.html` je kopie zavaděče: na zařízení, kde Service Worker ještě neběží, se postará o přímou adresu podstránky.
- `cipher.js` obsahuje společné šifrovací funkce pro zavaděč, Service Worker, stránky i nástroj.
- Druhý zámek ke stejnému datovému klíči je záchranný klíč `ZK-…` (256 bitů) pro případ zapomenutého hesla.

Formát bloku: 12 B IV a pak AES-256-GCM s tagem 16 B; obsah je doplněný nulami na násobek 4 KiB a jako doplňková data se ověřuje id bloku. Názvy bloků jsou náhodné.

Zavaděč počítá s tím, že web běží na cestě `/pages/` (značka `<base>` v `index.html` a `404.html`).

## Nástroj

`tools/vault.mjs` (Node 20+, bez závislostí) čte heslo z proměnné `VAULT_PASSWORD`; čitelné soubory vznikají jen ve složce `src/`, která se nikdy necommituje.

```sh
VAULT_PASSWORD=… node tools/vault.mjs init       # nový trezor, vypíše jednou záchranný klíč
VAULT_PASSWORD=… node tools/vault.mjs open       # vault/ → src/
VAULT_PASSWORD=… node tools/vault.mjs seal       # src/ → vault/ (nezměněné soubory si nechají blok)
VAULT_PASSWORD=… VAULT_NEW_PASSWORD=… node tools/vault.mjs password
VAULT_PASSWORD=… node tools/vault.mjs rotate     # nový datový klíč a nové zašifrování všeho
VAULT_PASSWORD=… node tools/vault.mjs check      # spouští se i jako git hook pre-commit
```

## Co šifrování nechrání

Kdokoli vidí, že repozitář a web existují, obecný kód, počet a přibližnou velikost šifrovaných bloků a časy commitů. Kdo repozitář stáhne, může hesla zkoušet bez omezení, proto je potřeba dlouhé náhodné heslo. Rotace klíče chrání jen nový obsah; staré verze v historii gitu zůstávají čitelné starým heslem.
