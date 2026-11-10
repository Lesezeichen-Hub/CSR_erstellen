# CSR Generator

Reine Browser-Webapp fuer den Lesezeichen-Hub. Erzeugt fuer die Telekom-CA
bei jedem Aufruf ein neues RSA-Schluesselpaar und einen passenden PKCS#10-CSR.
Kein eigener Server, keine EXE, kein Go und kein OpenSSL erforderlich.

## Im Hub verwenden

1. **Hinzufuegen > Lokales Modul** im Hub oeffnen.
2. Name **CSR Generator**, gewuenschte Gruppe und diesen Ordner auswaehlen.
3. Das angelegte Modul-Lesezeichen oeffnen.

Die benoetigten Browserdateien einschliesslich `crypto.bundle.js` und dessen
Lizenzhinweisen liegen bereits im Repository. Fuer den Betrieb ist kein npm
notwendig. Die `version.json` enthaelt das Hub-Versionsfeld `version: 1.1.0`.
Der Hub bekommt einen Modul-Eintrag, keinen zusaetzlichen globalen Navigationspunkt.
Hub-Styles und das Farbschema modern/terminal werden uebernommen.

Die Seite muss ueber einen vertrauenswuerdigen Ursprung geladen werden:
`http://localhost`, `http://127.0.0.1` oder HTTPS. Ueber unverschluesseltes HTTP
mit einer LAN-IP stellt der Browser Web Crypto nicht zur Verfuegung.

## Bedienung

Stage und RSA-Laenge (2048, 3072 oder standardmaessig 4096 Bit) auswaehlen,
bei Bedarf CN und alternative DNS-Namen bearbeiten und **Schluessel & CSR erstellen**
ausfuehren. Private Key, CSR und `csr.conf` werden angezeigt und lassen sich
einzeln kopieren oder herunterladen.

Direkt unter dem CSR zeigt ein schreibgeschuetztes Textfeld die CSR-Pruefung:
Signaturstatus, Subject, RSA-Public-Key, angeforderte Extensions und Signatur.
Der PEM-kodierte CSR wird dafuer erneut eingelesen und seine Signatur mit
PKIjs/Web Crypto geprueft. Die Ausgabe entspricht inhaltlich fuer die erzeugten
CSRs `openssl req -noout -text -verify`, verwendet aber ein OpenSSL-aehnliches
Format und fuehrt kein OpenSSL aus. Sie bestaetigt die CSR-Selbstsignatur,
nicht die Freigabe durch eine CA oder die Zulaessigkeit der DNS-Namen.

Es gibt keine Verlinkung zurueck zum Hub. Die Downloadnamen folgen dem Schema
`BNET2_<Stage>_<Monat>_<Jahr>.key` beziehungsweise `.csr`, z.B.
`BNET2_LIVE_11_2026.key` und `BNET2_LIVE_11_2026.csr`. Fuer LABOR wird entsprechend
`BNET2_LABOR_11_2026` verwendet. Monat (1 bis 12, ohne fuehrende Null) und Jahr
stammen vom Erstellungsdatum. `csr.conf` behaelt seinen Namen.

LIVE, CN `tect.prod.d001.loc`, SANs:

```text
tect.prod.d001.loc
bek-cta-fv-012.v001.tk.loc
tect.v001.tk.loc
tect
```

LABOR, CN `tect-labor.prod.d001.loc`, SANs:

```text
tect-labor.prod.d001.loc
bek-cta-ft-012.v008.tk.loc
tect-labor.v008.tk.loc
```

Der Stage-Wechsel ersetzt CN und SAN-Liste. CN muss auch als SAN enthalten
sein. Maximal 100 eindeutige DNS-Namen, keine URLs, Wildcards oder IP-SANs.
Der Kurzname `tect` ist erlaubt. Die CA entscheidet ueber die Zulaessigkeit
der internen Namen.

## Kryptografie und Datenschutz

Native Web Crypto erzeugt RSA-Schluessel und signiert mit SHA-256 und PKCS#1 v1.5.
PKIjs/ASN1js kodieren den PKCS#10-CSR. Alle Bibliotheken sind lokal gebuendelt;
es gibt keine API-Aufrufe, CDN-Abhaengigkeiten oder Telemetrie im Modul.
Der private Schluessel verlaesst den Browser nicht automatisch.

Subject: `C=DE`, `O=T-Systems International GmbH`, `OU=Barmer Infrastruktur`,
`OU=Serverdienste`, CN aus dem Formular. Extensions: kritische Key Usage
`digitalSignature,keyEncipherment`, Extended Key Usage `serverAuth,clientAuth`
und alle DNS-SANs. Export: unverschluesselter PKCS#8-Private-Key und PKCS#10-CSR,
beide PEM-kodiert und mit OpenSSL kompatibel.

Die `csr.conf` beschreibt dieselben Einstellungen als OpenSSL-Konfiguration;
der Browser erzeugt den CSR direkt, ohne diese Datei auszufuehren.
`0.OU` und `1.OU` erhalten beide OU-Werte auch bei manueller OpenSSL-Verwendung.

Artefakte bleiben ausschliesslich im Arbeitsspeicher. Sie werden bei neuer
Erstellung, Formularaenderung, Stage-Wechsel, Verlassen der Seite, nach 15 Minuten
oder ueber **Ausgaben verwerfen** aus der Anwendung entfernt. Es gibt keine
Datenbank, keinen Artefakt-Storage und keinen Service Worker. Nur das Farbschema
wird in localStorage gespeichert. Downloads werden aus kurzlebigen Blob-URLs erzeugt.

Nach einem Download bleibt die Anzeige fuer den Download des zweiten Artefakts
erhalten. Heruntergeladene Dateien, Zwischenablage und deren Verlauf liegen unter
Kontrolle des Nutzers und werden nicht automatisch geloescht. Garantierte
physische RAM-Loeschung ist in JavaScript nicht moeglich. Eine bereits gestartete
Web-Crypto-Operation laesst sich nicht abbrechen; ihre Ausgabe wird nach Verlassen
der Seite nicht mehr angezeigt. Die Webapp sollte nur in einem vertrauenswuerdigen
Hub ohne fremde Skripte oder Browsererweiterungen verwendet werden.

## Entwicklung

Nur fuer Quellcodeaenderungen ist Node.js 22 oder neuer erforderlich:

```powershell
npm.cmd ci
npm.cmd run check
npm.cmd test
npm.cmd run build
npm.cmd run dev
```

Der optionale Entwicklungsserver liefert die statischen Dateien unter
http://127.0.0.1:18780 aus; produktiv uebernimmt das der vorhandene Hub.
Nach Aenderungen an `crypto.js` das Browserbundle neu bauen und mit einchecken.
Lizenzhinweise neben dem Bundle behalten.

Die Tests pruefen LIVE und LABOR, neue Schluessel, alle drei RSA-Laengen,
CSR-Signatur, passende oeffentliche/private Schluessel, CN, beide OU-Werte,
SANs, Key Usage, Extended Key Usage und Eingabevalidierung. Der Pruefbericht
wird ebenfalls geprueft, einschliesslich der Erkennung manipulierter Signaturen.