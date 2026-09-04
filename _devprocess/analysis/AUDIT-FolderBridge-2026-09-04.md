---
id: AUDIT-FolderBridge-2026-09-04
title: Security Audit FolderBridge 2.15.3
date: 2026-09-04
---

# Security Audit Report

| Feld | Wert |
|------|------|
| Projekt | FolderBridge (obsidian-multifolder) |
| Version | 2.15.3 |
| Datum | 2026-09-04 |
| Branch | feature/audit-2026-09-04 (HEAD 6973ead) |
| Scan-Scope | full, 108 Dateien im Scope |
| Risikobewertung bei Erstprüfung | **Hoch** |
| Risikobewertung nach Fix-Loop | **Niedrig** |

---

## Zusammenfassung

FolderBridge hängt externe Verzeichnisse und Remote-Speicher (WebDAV, S3, SFTP) als virtuelle Ordner in einen Obsidian-Vault. Das Plugin trägt damit eine Sicherheitsgrenze, die es selbst durchsetzen muss, und es hat dafür bewusst Komponenten gebaut: einen `SecurityManager` mit Allowlist, einen `CredentialStore` auf Basis der OS-Keychain und einen tokengeschützten lokalen Dateiserver. Diese Grundstruktur ist durchdacht.

Die Prüfung findet zwei Klassen von Problemen. Erstens hält die Allowlist ihr eigenes Versprechen nicht: Sie vergleicht Pfade rein textuell und löst keine Symlinks auf, wodurch ein Symlink innerhalb eines gemounteten Ordners lesend und schreibend aus der erlaubten Zone herausführt. Zweitens fehlt den SFTP-Verbindungen die Host-Key-Verifikation vollständig, womit die Authentizität des Servers nie geprüft wird und ein Angreifer in Netzwerkposition Zugangsdaten und Inhalte abgreifen kann. Dazu kommt eine Kette von Lieferketten-Schwächen im Release-Workflow.

Kein Befund ist kritisch im Sinne einer aus der Ferne und ohne Vorbedingung ausnutzbaren Lücke. Die beiden hoch bewerteten Code-Befunde untergraben aber genau die Zusagen, die der Code an prominenter Stelle dokumentiert. Empfehlung: kein Release, bis H-1 und H-2 behoben sind.

| Analysebereich | Kritisch | Hoch | Mittel | Niedrig | Info |
|-----------------|----------|------|--------|-----|------|
| Code (SAST, OWASP, Zero Trust, Qualität) | 0 | 2 | 3 | 1 | 7 |
| SCA (Abhängigkeiten) | 0 | 0 | 2 | 2 | 0 |
| Lieferkette (Provenance, Build-Integrität) | 0 | 3 | 5 | 0 | 5 |
| Lizenz-Compliance | 0 | 0 | 0 | 0 | 0 |
| **Gesamt** | **0** | **5** | **10** | **3** | **12** |

---

## P1: Must Fix (Hoch)

### H-1: SFTP-Verbindungen ohne Host-Key-Verifikation

- **Severity:** Hoch
- **CWE-ID:** CWE-322 (Key Exchange without Entity Authentication), verwandt CWE-295
- **CVSS:** CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N = 7.4
- **Location:** [src/SFTPAdapter.ts:172-187](src/SFTPAdapter.ts#L172-L187)
- **FP:** A2-sftp-hostkey
- **Status:** Confirmed
- **Evidence:** `connectOptions` wird aus genau vier Feldern gebaut (`host`, `port`, `username`, dazu `password` oder `privateKey`). Ein `hostVerifier` wird nicht gesetzt. Ein projektweiter grep über `hostVerifier|hostHash|algorithms|checkServerIdentity` liefert null Treffer. Die ssh2-Dokumentation zu `hostVerifier` lautet: "Default: (auto-accept if `hostVerifier` is not set)". Die Verbindung akzeptiert damit jeden präsentierten Host-Key.
- **Risk:** Ein Angreifer in Netzwerkposition (kompromittiertes WLAN, DNS-Spoofing, bösartiger Exit-Node) gibt sich als der SFTP-Server aus, erhält im Passwort-Modus die Zugangsdaten im Klartext und liefert manipulierte Dateiinhalte in den Vault zurück.
- **Remediation:** In `_doConnect()` einen `hostVerifier` setzen, der den Fingerprint gegen einen beim ersten Verbinden bestätigten und in der Mount-Konfiguration abgelegten Wert prüft (Trust-on-first-use mit sichtbarer Bestätigung durch den Nutzer und harter Warnung bei Abweichung).
- **Effort:** M

### H-2: Allowlist lässt sich per Symlink verlassen

- **Severity:** Hoch
- **CWE-ID:** CWE-59 (Improper Link Resolution Before File Access)
- **CVSS:** CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H = 7.2
- **Location:** [src/SecurityManager.ts:34-47](src/SecurityManager.ts#L34-L47), [src/OSHelpers.ts:313-319](src/OSHelpers.ts#L313-L319)
- **FP:** A3-symlink-escape
- **Status:** Confirmed
- **Evidence:** `normalizeForComparison()` ruft `path.normalize()` auf, das `..` rein lexikalisch auflöst, aber keine Symlinks. `isAllowed()` vergleicht anschließend nur Präfixe. Ein PoC in isolierter Sandbox belegt die Folge:

  ```
  Angefragter Pfad : <mount>/harmlos/private.txt
  Guard isAllowed  : ERLAUBT
  fs.realpathSync  : <außerhalb>/secret/private.txt
  Liegt im Mount   : false
  Gelesener Inhalt : "TOP SECRET - außerhalb des Mounts"
  ```

  Verschärfend löst [src/VirtualAdapter.ts:523-537](src/VirtualAdapter.ts#L523-L537) Symlinks aktiv per `fs.promises.stat` auf und zeigt das Ziel als regulären Ordner im Vault an. Der Zugriff bleibt nicht lesend: Hinter demselben Guard liegen `writeFile` ([Z.677](src/VirtualAdapter.ts#L677)) und `rm(..., { recursive: true, force: true })` ([Z.962](src/VirtualAdapter.ts#L962)).
- **Risk:** Wer in einen gemounteten Ordner schreiben kann (geteiltes Laufwerk, Cloud-Sync-Ordner, geklontes Repository, entpacktes Archiv), platziert dort einen Symlink und erhält über den Vault Lese-, Schreib- und Löschzugriff auf beliebige Pfade mit den Rechten des Obsidian-Prozesses.
- **Remediation:** In `isAllowed()` den Pfad vor dem Präfixvergleich über `fs.realpathSync` auflösen (für noch nicht existierende Zielpfade das nächste vorhandene Elternverzeichnis auflösen) und Einträge, deren aufgelöster Pfad die Allowlist verlässt, in `listRealDirectory` überspringen.
- **Effort:** M

### H-3 bis H-5: GitHub-Actions im Release-Workflow auf verschiebbare Tags gepinnt

- **Severity:** Hoch
- **CWE-ID:** CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)
- **CVSS:** CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H = 8.0
- **Location:** [.github/workflows/release.yml:15](.github/workflows/release.yml#L15) (`actions/checkout@v4`), [:18](.github/workflows/release.yml#L18) (`actions/setup-node@v4`), [:57](.github/workflows/release.yml#L57) (`softprops/action-gh-release@v2`)
- **FP:** c6e9c372, 3b708fc6, 59f1959c
- **Status:** Confirmed
- **Evidence:** Alle drei Actions referenzieren einen beweglichen Major-Tag. Ein Tag lässt sich im Quell-Repository auf einen anderen Commit umhängen; der Workflow zieht dann ohne jede Änderung am eigenen Repo neuen fremden Code. Der Workflow läuft mit `permissions: contents: write` und veröffentlicht die Release-Artefakte, die Nutzer als Plugin installieren.
- **Risk:** Eine Kompromittierung eines der drei Action-Repositories führt direkt zu manipulierten Release-Assets, also zu einer Verteilung von Schadcode an alle Plugin-Nutzer über den offiziellen Kanal.
- **Remediation:** Jede Action auf den vollen Commit-SHA pinnen und den Versionstag als Kommentar dahinter setzen (`uses: actions/checkout@<sha> # v4.2.2`), Aktualisierung per Dependabot.
- **Effort:** S

---

## P2: Should Fix (Mittel)

### M-1: Alle Zugangsdaten liegen zur Laufzeit im Klartext in sessionStorage

- **Severity:** Mittel
- **CWE-ID:** CWE-522 (Insufficiently Protected Credentials), CWE-312
- **CVSS:** CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N = 5.4
- **Location:** [main.ts:744-767](main.ts#L744-L767), [src/CredentialStore.ts:132-136](src/CredentialStore.ts#L132-L136)
- **FP:** A4-cred-session
- **Status:** Confirmed
- **Evidence:** Beim Layout-Ready entschlüsselt das Plugin jedes gespeicherte Secret und legt es unmittelbar unverschlüsselt ab: `decryptCredential(mount.encryptedWebdavPassword)` gefolgt von `saveWebDAVPassword(mount.id, plain)`, analog für S3-Secret-Key, SFTP-Passwort und SFTP-Passphrase. `saveSessionCredential` schreibt per `sessionStorage.setItem` im Klartext. Der Pfad ist nicht an `isEncryptionAvailable()` gekoppelt, greift also auch dort, wo die OS-Keychain verfügbar ist.
- **Risk:** Der Keychain-Schutz wirkt nur im Ruhezustand. Zur Laufzeit liest jedes andere Plugin im selben Renderer die Secrets mit einem `sessionStorage.getItem` aus, ebenso jeder Prozess mit Lesezugriff auf die Session-Storage-Dateien des Profils.
- **Remediation:** Entschlüsselte Secrets nur in einer prozessinternen Map halten, die der Adapter direkt konsumiert, und `sessionStorage` ausschließlich dort verwenden, wo `isEncryptionAvailable()` false liefert (Mobile).
- **Effort:** M

### M-2: Path Traversal im lokalen Dateiserver

- **Severity:** Mittel
- **CWE-ID:** CWE-22 (Path Traversal)
- **CVSS:** CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N = 5.1
- **Location:** [src/FileServer.ts:263-270](src/FileServer.ts#L263-L270), Eingang [src/FileServer.ts:167](src/FileServer.ts#L167)
- **FP:** A1-fsrv-trav
- **Status:** Confirmed
- **Evidence:** `handleRequest` bildet den Dateipfad als `decodeURIComponent(rawPath).replace(/\\/g, '/')`, ohne `path.normalize`. `isPathAllowed` vergleicht diesen Rohpfad per `startsWith(root + '/')`. Ein PoC gegen die exakt nachgebaute Prüfkette:

  ```
  Guard sagt | OS liest tatsaechlich  | Fall
  ERLAUBT    | /etc/passwd            | Traversal, roh          <== AUSBRUCH
  ERLAUBT    | /etc/passwd            | Traversal, URL-kodiert  <== AUSBRUCH
  ERLAUBT    | <außerhalb>/.ssh/id_rsa | Traversal, Nachbarordner <== AUSBRUCH
  BLOCKIERT  | /etc/passwd            | direkt, ohne Prefix
  ```

  Der Kommentar ab [Z.25](src/FileServer.ts#L25) sagt zu, Anfragen außerhalb der Roots erhielten 403; das trifft nachweislich nicht zu. Zusätzlich setzt [Z.209](src/FileServer.ts#L209) `Access-Control-Allow-Origin: *`.
- **Risk:** Beschränkt, weil jede Anfrage das 24-Byte-Session-Token braucht und der Server nur an 127.0.0.1 lauscht. Wer das Token kennt, hat es aus dem Renderer-DOM und damit ohnehin weitgehenden Zugriff. Der Befund ist eine gebrochene Tiefenverteidigung, keine eigenständig ausnutzbare Lücke.
- **Remediation:** In `isPathAllowed` den Pfad per `path.resolve` normalisieren und erst danach gegen die Roots prüfen, zusätzlich `Access-Control-Allow-Origin` auf die Obsidian-Herkunft eingrenzen.
- **Effort:** S

### M-3: WebDAV akzeptiert http:// ohne Warnung

- **Severity:** Mittel
- **CWE-ID:** CWE-319 (Cleartext Transmission of Sensitive Information)
- **CVSS:** CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N = 5.2
- **Location:** [src/ui/MountManagerModal.ts:1141](src/ui/MountManagerModal.ts#L1141), [src/WebDAVAdapter.ts:26-34](src/WebDAVAdapter.ts#L26-L34)
- **FP:** A5-webdav-http
- **Status:** Confirmed
- **Evidence:** Die Validierung besteht aus `try { new URL(this.webdavUrl); } catch { ... }` und prüft damit ausschließlich die Parsebarkeit. Ein Schema-Check fehlt, `http://` passiert die Prüfung. `createClient(this.baseUrl, { username, password })` sendet die Zugangsdaten anschließend per Basic Auth.
- **Risk:** Bei einer http-URL gehen WebDAV-Benutzername und Passwort base64-kodiert im Klartext über das Netz und sind für jeden Mitleser auf dem Pfad verwertbar.
- **Remediation:** `https:` erzwingen und `http:` nur nach expliziter Bestätigung im Dialog zulassen, verbunden mit einem sichtbaren Hinweis am Mount.
- **Effort:** S

### M-4: Checkout im Release-Workflow behält den Token

- **Severity:** Mittel
- **CWE-ID:** CWE-522
- **Location:** [.github/workflows/release.yml:15](.github/workflows/release.yml#L15)
- **FP:** 005e99a3
- **Status:** Confirmed
- **Evidence:** Der Job läuft mit `permissions: contents: write`, `actions/checkout` wird ohne `persist-credentials: false` verwendet. Der Schritt `npm ci` ([Z.23](.github/workflows/release.yml#L23)) führt danach die Install-Scripts von vier Paketen aus (`esbuild`, `ssh2`, `cpu-features`, `fsevents`). Das hebt die Bewertung gegenüber der reinen Scanner-Einstufung an.
- **Risk:** Ein kompromittiertes Install-Script liest den in `.git/config` verbliebenen GITHUB_TOKEN und schreibt mit Write-Rechten ins Repository.
- **Remediation:** `with: persist-credentials: false` am Checkout setzen.
- **Effort:** S

### M-5: build-check.yml ohne permissions-Block und mit beweglichen Action-Tags

- **Severity:** Mittel
- **CWE-ID:** CWE-250 (Execution with Unnecessary Privileges), CWE-829
- **Location:** [.github/workflows/build-check.yml:18](.github/workflows/build-check.yml#L18), [:21](.github/workflows/build-check.yml#L21)
- **FP:** ea28fdd4, 70379dd2, a87360ab
- **Status:** Confirmed
- **Evidence:** Der Workflow deklariert keinen `permissions:`-Block und erbt damit die Standardrechte des Repository-Tokens, die weiter reichen als ein Build-Check benötigt. `actions/checkout@v4` und `actions/setup-node@v4` sind auf bewegliche Tags gepinnt.
- **Risk:** Niedriger als H-3 bis H-5, weil der Workflow keine Artefakte veröffentlicht, aber dieselbe Klasse: fremder Code mit unnötig breiten Rechten.
- **Remediation:** `permissions: contents: read` ergänzen und beide Actions auf Commit-SHAs pinnen.
- **Effort:** S

### M-6: fast-xml-parser 5.5.8 im ausgelieferten Bundle

- **Severity:** Mittel
- **CWE-ID:** CWE-1395 (Dependency on Vulnerable Third-Party Component)
- **Location:** package-lock.json, `node_modules/fast-xml-parser`
- **FP:** B1-fxp
- **Status:** **Unverified**
- **Evidence:** GHSA-gh4j-gqv2-49f6 (XML Comment and CDATA Injection, MODERATE), betroffen alle Versionen unter 5.7.0, installiert ist 5.5.8. Transitiv über `@aws-sdk/client-s3`; `esbuild.config.mjs` setzt `bundle: true` und listet nur Obsidian, Electron, CodeMirror und Node-Builtins als `external`, das Paket landet also in `main.js`.
- **Risk:** Das Advisory betrifft den XMLBuilder. Der S3-Pfad des AWS SDK nutzt vorrangig den Parser. Ich habe keinen Source-to-Sink-Pfad vom Plugin-Code zum verwundbaren Builder nachgewiesen, deshalb bleibt der Befund unbestätigt.
- **Remediation:** `@aws-sdk/client-s3` anheben, bis `fast-xml-parser` mindestens 5.7.0 aufgelöst wird, ersatzweise per `overrides` in package.json.
- **Effort:** S

### M-7: fast-xml-builder 1.1.4 im ausgelieferten Bundle

- **Severity:** Mittel
- **CWE-ID:** CWE-1395
- **Location:** package-lock.json, `node_modules/fast-xml-builder`
- **FP:** B2-fxb
- **Status:** **Unverified**
- **Evidence:** GHSA-5wm8-gmm8-39j9 (HIGH, Attributwerte umgehen die Maskierung), betroffen unter 1.1.7, installiert 1.1.4. Ebenfalls transitiv über das AWS SDK und im Bundle enthalten.
- **Risk:** Erreichbarkeit über den S3-Pfad nicht getraced, daher unbestätigt. Bei Erreichbarkeit wäre XML-Injection in aufgebauten Requests möglich.
- **Remediation:** Wie M-6, gemeinsam mit dem AWS-SDK-Update.
- **Effort:** S

### M-8: npm ci scheitert außerhalb von linux-x64

- **Severity:** Mittel
- **CWE-ID:** CWE-1104 (Use of Unmaintained Third Party Components), hier als Build-Integritätsproblem
- **Location:** [package.json:22](package.json#L22)
- **FP:** C1-npmci-arch
- **Status:** Confirmed
- **Evidence:** Der bestellte Clean-Room-Rebuild bricht ab: `npm error notsup Actual cpu: arm64`. Ursache ist `"@esbuild/linux-x64": "^0.27.3"` in den devDependencies. Diese plattformspezifische Binary wird normalerweise als `optionalDependency` von `esbuild` aufgelöst und darf nicht explizit deklariert werden.
- **Risk:** Kein direkter Angriffsvektor, aber der Build ist außerhalb von linux-x64 nicht reproduzierbar. Damit lässt sich nicht unabhängig prüfen, ob ein veröffentlichtes `main.js` wirklich aus diesem Quellstand entstanden ist. Das ist die Voraussetzung für jede Lieferketten-Verifikation.
- **Remediation:** `@esbuild/linux-x64` aus den devDependencies entfernen und esbuild die Plattform-Binary selbst auflösen lassen.
- **Effort:** S

---

## P3: Consider (Niedrig und Info)

### L-1: Quadratische Laufzeit in validateMount

- **Severity:** Niedrig
- **CWE-ID:** CWE-1333 (Inefficient Regular Expression Complexity)
- **Location:** [src/SecurityManager.ts:95](src/SecurityManager.ts#L95), gleiches Muster in [:100](src/SecurityManager.ts#L100), [:112](src/SecurityManager.ts#L112)
- **FP:** A6-redos-validate, f69499f7
- **Status:** Confirmed
- **Evidence:** Messung der Regex `/[\\/]+$/`: 10.000 Schrägstriche 42,9 ms, 20.000 164,4 ms, 40.000 654,9 ms. Verdopplung der Eingabe vervierfacht die Laufzeit, also quadratisch.
- **Risk:** Gering. Die Eingabe ist der selbst konfigurierte `virtualPath`, ein Angreifer müsste bereits `data.json` schreiben können. Praktisch nur Selbst-DoS.
- **Remediation:** Wiederholte Trennzeichen ohne Regex abschneiden, etwa per `while`-Schleife über das letzte Zeichen.
- **Effort:** S

### L-2: brace-expansion 2.0.3 unter webdav

- **Severity:** Niedrig, **Status: Unverified**, FP: B3-brace
- GHSA-3jxr-9vmj-r5cp, GHSA-mh99-v99m-4gvg, GHSA-rgw5-rvv9-x895 (DoS), behoben ab 2.1.4. Erreichbarkeit über den WebDAV-Pfad nicht getraced.

### L-3: 14 Dev-Pakete mit aktiven Advisories

- **Severity:** Niedrig, **Status: Confirmed**, FP: B4-devdeps
- Betroffen sind `vite`, `postcss`, `nanoid`, `js-yaml`, `esbuild`, `fast-uri`, `@humanfs/node` und mehrere `brace-expansion`-Instanzen, sämtlich mit `dev: true` im Lockfile. Sie landen nicht im ausgelieferten `main.js` und betreffen nur die Build- und Testumgebung. Bei Gelegenheit mit `npm update` anheben.

### Info: Install-Scripts ohne Opt-out

Vier Pakete führen Install-Scripts aus (`cpu-features`, `esbuild`, `fsevents`, `ssh2`), und keine `.npmrc` setzt `ignore-scripts=true` (FP: 2b97a176, ca96db9c, b5d41922, 9c5fb813, 8abce209). Für `esbuild` und `ssh2` ist das funktional notwendig. In CI ist `ignore-scripts` in Verbindung mit gezieltem Nachbauen dennoch die sicherere Variante, siehe M-4.

### Als False Positive verworfen

| FP | Fundstelle | Begründung |
|----|-----------|------------|
| 766f495f, da2fc40f, fea09353, 23d92fac, 926b3339 | src/ui/MountManagerModal.ts:2-6 | Der Grep-Treffer auf `../` steht in ES-Modul-Importzeilen (`from '../types'`), es findet kein Dateizugriff statt. |
| ec94a217 | src/ui/MountRootDeleteModal.ts:2 | Dito, Importzeile. |
| aea73c65 | src/ui/MountManagerModal.ts:564 | `setPlaceholder('AKIAIOSFODNN7EXAMPLE')` ist der offizielle AWS-Dokumentationsplatzhalter im Eingabefeld, kein gültiger Schlüssel. |

---

## Scope und Werkzeuge

| Werkzeug | Status | Anmerkung |
|----------|--------|-----------|
| CodeQL (javascript-queries) | gelaufen | Pack 2.3.2, 20 Tage alt |
| grep-Muster (Fallback) | gelaufen | Teil des Scan-Layers |
| semgrep | nicht verfügbar | nicht im PATH |
| gitleaks | nicht verfügbar | redigierender Musterabgleich als Ersatz |
| npm audit | **Fehler** | Registry-Proxy nexus.enbw.com antwortete HTTP 429 |
| OSV.dev API | gelaufen | Ersatz für npm audit, 585 Pakete per querybatch |
| osv-scanner (CLI) | nicht verfügbar | nicht im PATH |
| Lockfile-Provenance | gelaufen | 585 Pakete, alle von registry.npmjs.org, alle mit integrity |
| Action-Pinning, Install-Scripts, Manifest-Hygiene | gelaufen | 2 Workflows |
| Clean-Room-Rebuild | **Fehler** | `npm ci` scheitert auf arm64, siehe M-8 |
| gh attestation (Release-Verify) | nicht anwendbar | im Repository existieren keine Releases |
| Manuelle Triage | gelaufen | Source-to-Sink-Prüfung, 2 isolierte PoCs, 1 Laufzeitmessung |

Taxonomie-Snapshot: OWASP Top 10:2025, CWE Top 25 2025 (veröffentlicht 2025-12-15). OWASP LLM Top 10 nicht anwendbar, das Projekt bindet keine LLM-APIs ein. Erkannte Projektart: obsidian-plugin, electron.

## Abdeckung und Grenzen

- **SCA nur über OSV.** `npm audit` war blockiert, weil die lokale npm-Konfiguration auf einen internen Nexus-Proxy zeigt, der mit 429 antwortete. Die Abhängigkeitsprüfung stützt sich deshalb allein auf die OSV.dev-Datenbank. Die dortigen Treffer sind versionsgenau gegen die betroffenen Bereiche verifiziert, aber Advisories, die nur in der GitHub-Advisory-Datenbank stehen, können fehlen.
- **Reachability der SCA-Treffer nicht getraced.** M-6, M-7 und L-2 stehen bewusst auf Unverified. Dass ein verwundbares Paket im Bundle liegt, heißt nicht, dass der verwundbare Codepfad erreichbar ist.
- **Build-Integrität ungeprüft.** Der Clean-Room-Rebuild scheiterte an M-8, und es existieren keine Releases, gegen die sich eine Attestation prüfen ließe. Ob ein ausgeliefertes Bundle dem Quellcode entspricht, ist damit offen.
- **Kein semgrep, älteres CodeQL-Pack.** Die SAST-Schicht bestand aus CodeQL 2.3.2 plus Grep-Mustern. Die CodeQL-CLI 2.24.2 ist zu alt für das aktuelle Pack 2.4.4, weshalb ein 20 Tage altes Pack verwendet wurde. Regeln aus neueren Paketen fehlen.
- **Secrets nur musterbasiert und nur im Arbeitsstand.** Ohne gitleaks lief nur der redigierende Musterabgleich, die Git-Historie wurde nicht vollständig durchsucht.
- **Statische Analyse.** Ausser den beiden isolierten PoCs und der ReDoS-Messung wurde nichts zur Laufzeit getestet. Das Plugin lief zu keinem Zeitpunkt in Obsidian.
- **Mobile-Pfad nicht bewertet.** `manifest.json` setzt `isDesktopOnly: false`, während zentrale Funktionen Node-Module über `loadOptionalNodeModule` laden. Das Verhalten auf Obsidian Mobile wurde nicht geprüft.

## Empfehlung

**Release-Bewertung: rot.** H-1 und H-2 betreffen beide die Kernzusage des Plugins, nämlich dass Zugriffe die konfigurierte Grenze einhalten und die Gegenstelle die ist, für die sie sich ausgibt. Beide sind mit überschaubarem Aufwand behebbar. H-3 bis H-5 sollten im selben Zug erledigt werden, weil sie den Verteilweg zu den Nutzern betreffen und nur wenige Zeilen kosten.

---

## Fix-Loop und Re-Audit

Alle Findings wurden behoben (Option "alles fixen"). Jeder Fix wurde test-first
entwickelt: zuerst ein Test, der den Befund reproduziert und rot ist, dann die
Korrektur, dann derselbe Test grün. Die Testsuite wuchs dabei von 134 auf 172
Tests, alle grün, und `npm run validate` (lint, UI-Text-Check, Build, Tests)
läuft vollständig durch.

### Status je Finding

| ID | Befund | Status | Nachweis |
|----|--------|--------|----------|
| H-1 | SFTP ohne Host-Key-Verifikation | Resolved | `hostVerifier` mit Fingerprint-Pinning, 8 Tests in `tests/SFTPHostKey.test.ts` |
| H-2 | Allowlist per Symlink umgehbar | Resolved | `realpath`-Auflösung vor dem Präfixvergleich, 5 Tests mit echten Symlinks |
| H-3 bis H-5 | Actions auf bewegliche Tags gepinnt | Resolved | Commit-SHAs gepinnt, Scanner meldet 0 Action-Pinning-Findings |
| M-1 | Secrets im Klartext in sessionStorage | **Teilweise** | Desktop: prozessinterner Speicher, 5 Tests. Mobile: siehe Restrisiko unten |
| M-2 | Path Traversal im FileServer | Resolved | `path.resolve` vor dem Vergleich, 12 Tests in `tests/FileServerPath.test.ts` |
| M-3 | WebDAV akzeptiert http:// | Resolved | `classifyRemoteUrl`, 7 Tests; gilt jetzt auch für den S3-Endpoint |
| M-4 | persist-credentials fehlt | Resolved | `persist-credentials: false` in beiden Workflows |
| M-5 | build-check.yml ohne permissions | Resolved | `permissions: contents: read` ergänzt |
| M-6, M-7 | fast-xml-parser, fast-xml-builder | Resolved | Overrides auf 5.7.0 / 1.1.7, OSV-Recheck: 0 Treffer |
| M-8 | npm ci scheitert auf arm64 | Resolved | `@esbuild/linux-x64` entfernt, Installation läuft |
| L-1 | Quadratische Regex in validateMount | Resolved | Schleife statt Regex, Messung von 1509 ms auf unter 100 ms |
| L-2, L-3 | brace-expansion, 14 Dev-Pakete | Resolved | Gezielte Overrides, OSV-Recheck: 0 Treffer |

### Während des Fix-Loops eingeschleppt und behoben

Der erste Entwurf von `normalizeRootForServing` in `src/FileServer.ts` enthielt
dieselbe quadratische Regex `/\/+$/`, die in L-1 gerade beseitigt worden war.
CodeQL hat das im Re-Audit als `js/polynomial-redos` gemeldet. Die Funktion nutzt
jetzt `stripTrailingSeparators`, das für beide Module gemeinsam in `OSHelpers`
liegt. Auf dem Desktop war der Fall durch das vorgeschaltete `path.resolve`
ohnehin entschärft; auf Mobile, wo `pathMod` null ist, wäre er erreichbar gewesen.

Ein zweiter Fehlgriff betraf `eslint --fix`: Die Regel
`no-unnecessary-type-assertion` entfernte in `src/VirtualAdapter.ts` einen Cast,
der die Aufrufsignatur von `trashLocal` erweiterte, was den Build brach. Die
Änderung wurde zurückgenommen.

### Verbleibendes Restrisiko

**Zugangsdaten auf Obsidian Mobile.** `saveSessionCredential` schreibt weiterhin
in `sessionStorage`, wenn `isEncryptionAvailable()` false liefert. Auf Mobile
existiert keine OS-Keychain, also gibt es dort keinen geschützten Ablageort. Die
Alternative wäre, Zugangsdaten gar nicht zu halten und sie nach jedem Reload neu
abzufragen. CodeQL meldet die Stelle weiterhin als
`js/clear-text-storage-of-sensitive-data` (`src/CredentialStore.ts:159`); der
Treffer ist zutreffend und wird bewusst in Kauf genommen. Auf dem Desktop ist der
Pfad nicht mehr erreichbar.

**Race zwischen Prüfung und Zugriff.** `isAllowed()` prüft den Zustand des
Dateisystems zum Aufrufzeitpunkt. Ein Symlink, der zwischen Prüfung und der
darauffolgenden I/O-Operation ausgetauscht wird, ist damit nicht abgedeckt
(CWE-367). Ein vollständiger Schutz bräuchte `openat` mit `O_NOFOLLOW`, was die
Node-API in dieser Form nicht anbietet. Der Kommentar an der Methode hält das fest.

**Kosten der Symlink-Auflösung.** `isAllowed()` ruft jetzt `fs.realpathSync` auf
und liegt im Pfad jeder I/O-Operation. Ein Cache wurde bewusst weggelassen, weil
er genau die Race-Bedingung vergrößern würde, die der Fix schließt. Ob die
zusätzlichen Syscalls bei sehr großen Mounts spürbar sind, wurde nicht gemessen.

### Nicht verifiziert

Die Fixes sind durch Tests, Build und Re-Scan abgesichert, aber das Plugin lief
zu keinem Zeitpunkt in einer echten Obsidian-Instanz. Drei Änderungen berühren
Verhalten, das sich nur dort abschließend beurteilen lässt:

- Der CORS-Header des FileServers echot jetzt die Origin des Aufrufers, statt `*`
  zu senden. Medien-Einbettungen ohne `crossorigin`-Attribut brauchen keinen
  CORS-Header, ein Bruch ist daher unwahrscheinlich, aber ungeprüft.
- Das Host-Key-Pinning zeigt beim ersten Verbinden eine Notice und schreibt den
  Fingerprint in die Settings. Der Ablauf wurde nicht gegen einen echten
  SFTP-Server durchgespielt.
- `http://` auf entfernte Hosts wird bei WebDAV und S3 jetzt abgelehnt. Wer bisher
  einen unverschlüsselten Server genutzt hat, muss auf https wechseln.

### Werkzeuge im Re-Audit

`npm audit` blieb durch den Registry-Proxy blockiert, die SCA lief erneut über
OSV.dev (586 Pakete, 0 Treffer). Der CodeQL-Aufruf innerhalb von `audit_scan.py`
brach reproduzierbar mit `database create failed (exit 2)` ab; die Analyse wurde
deshalb direkt über die CodeQL-CLI gefahren, mit demselben Pack 2.3.2. Der
Delta-Vergleich über Fingerprints weist 10 aufgelöste Findings aus; die als neu
gemeldeten Fingerprints sind zwei bereits bekannte False Positives, deren Snippet
sich durch die Änderungen verschoben hat.
