# Diagrammi di architettura — AURORA

Sorgenti [Mermaid](https://mermaid.js.org/) dei diagrammi dell'architettura e i
relativi PNG renderizzati. Seguono il **modello C4** (dal più astratto al più
concreto) più una vista a runtime.

| File | Diagramma | Livello | Usato in |
|------|-----------|---------|----------|
| `01-context.mmd` | Vista di contesto — attori e sistemi esterni | C4 · contesto | README §Architettura · tesi Fig. 4.1a |
| `02-services.mmd` | Servizi cooperanti e protocolli | C4 · container | README §Architettura · tesi Fig. 4.1b |
| `03-components.mmd` | Componenti interni dell'API (pipeline) | C4 · componenti | README §Architettura |
| `04-sequence.mmd` | Sequenza di una richiesta `/api/bitm/collect` | runtime | README §Come funziona · tesi Fig. 6.2 |

Gli stessi diagrammi sono inline come blocchi ```mermaid nel
[README](../../README.md) (si renderizzano da soli su GitHub). Questi file `.mmd`
sono la **sorgente unica** per i PNG usati nella tesi e nelle slide.

## Rigenerare i PNG

Serve [Node.js](https://nodejs.org/) (per `npx`). Da questa cartella:

```bash
for f in 01-context 02-services 03-components 04-sequence; do
  npx -y @mermaid-js/mermaid-cli -i "$f.mmd" -o "$f.png" -b white -s 3
done
```

- `-b white` → sfondo bianco (stampa/tesi)
- `-s 3` → scala 3× per testo nitido

## Aggiornare la tesi

I PNG usati nel `.docx` vivono in `tesi/figures/` (`arch_context.png`,
`arch_services.png`, `arch_sequence.png`) e sono inseriti da
`tesi/genera_tesi.py`. Dopo aver rigenerato un PNG, ricopialo:

```bash
cp 01-context.png  ../../tesi/figures/arch_context.png
cp 02-services.png ../../tesi/figures/arch_services.png
cp 04-sequence.png ../../tesi/figures/arch_sequence.png
python ../../tesi/genera_tesi.py
```

> Se modifichi un diagramma, aggiorna **sia** il `.mmd` qui **sia** il blocco
> ```mermaid corrispondente nel README, così le due copie restano allineate.
