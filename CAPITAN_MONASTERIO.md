# Capitán Monasterio — un maker malicioso real, sobre el código real de ElZorro

(nombre por el villano de la temporada 1 del Zorro clásico de Disney: el que le mueve el precio al Zorro.)

**Qué es:** un PoC de seguridad en Foundry. No es un contrato nuevo ni un modelo teórico de
ataque — es el **contrato real de `PropAMM.sol`** (el mismo que esta factory deploya para
ElZorro) corriendo local, donde la pieza "maliciosa" es simplemente una key de updater que hace
lo mismo que el updater honesto (`quote-updater/src/node.rs: updateState(...)`), pero con mala
intención. No se escribió ningún contrato atacante nuevo: el ataque vive enteramente en CUÁNDO y
QUÉ escribe esa key, no en código custom.

**Por qué importa:** si un día una key de updater se compromete (laptop, CI, secret leak), esto
es exactamente lo que podría hacer y qué le pasa al taker. Sirve para decidir qué defensa agregar
antes de que haga falta, no después.

**Archivo:** `contracts/test/CapitanMonasterioQuoteAndPull.t.sol`

**Cómo correrlo** (no necesita RPC, no toca mainnet, 100% local — verificado, 4/4 pasan):
```
cd contracts
forge test --match-path 'test/CapitanMonasterioQuoteAndPull.t.sol' -vv
```

## El mecanismo (quote-and-pull)

`PropAMM.sol` separa dos cosas: `quote()` (lo que ve el taker antes de operar) y `swap()` (lo que
ejecuta). **Las dos leen el mismo oráculo (`IPrioUpdateRegistry`/PUR), cada una en su propio
momento.** `swap()` NO reutiliza lo que devolvió `quote()` — vuelve a leer el precio fresco al
momento de ejecutar (`PropAMM.sol:168`, `_quote` llamado de nuevo dentro de `swap`). Esto es
bueno: significa que el contrato en sí mismo no puede mentir entre su propia cotización y su
propio fill.

El hueco está un nivel más abajo: **entre el momento en que el taker lee `quote()` off-chain (o
simula su tx) y el momento en que su `swap()` realmente entra en un bloque, nada impide que el
updater reescriba el precio.** Eso es el "pull":

1. El updater publica un precio atractivo (`delta=0`, `mid=2500`).
2. El taker lee `quote()`, decide operar, arma su tx con un `minAmountOut` basado en ESE precio.
3. Antes de que la tx del taker entre, el updater reescribe el precio (`delta=50bps`, mismo mid).
4. `swap()` del taker re-cotiza contra el precio YA PULLEADO, no el que vio.

**Dos resultados posibles, según qué tan ajustado puso el taker su `minAmountOut`:**

| Escenario | `minAmountOut` | Resultado | Test |
|---|---|---|---|
| Piso ajustado al precio que vio | == quote atractiva | `swap()` revierte (`InsufficientOutput`), **sin fallback** — perdió solo gas | `test_pulledBeforeSwap_tightMinOut_revertsNoFallback` |
| Piso laxo (slippage genérico, ej. 5%) | < quote atractiva | `swap()` pasa, el taker recibe menos de lo que vio, sin que el contrato lo marque como nada raro | `test_pulledBeforeSwap_looseMinOut_takerShortchangedSilently` |

Importante: **llamado directo al venue (como en este test) no tiene fallback.** El fallback a
Uniswap solo existe un nivel arriba, en el router (`PropAMMRouter._coreSwap`), si el fill llega
por ahí. Un taker que llama a ElZorro directo, o cuyo agregador eligió este venue a mano, no tiene
ese colchón.

## Caso de control (no es exploit): phantom depth

`test_phantomDepth_emptyVaultCaughtAtQuoteNotAtFill` muestra lo contrario: si el vault detrás del
par no tiene `tokenOut`, `quote()` revierte ANTES de que nadie intente operar (`EmptyVault`,
`PropAMM.sol:304`). Esta falla sí está cubierta hoy. Sirve de contraste: la insolvencia del vault
se cacha en el momento de cotizar; el pull de precio, no.

## Qué decidir con esto

El contrato no tiene memoria de cuánto cambió el lane entre una lectura y la siguiente, ni una
ventana de frescura propia (`PropAMM.sol` lee `oracle.getState(pairKey, now, now)` — la frescura,
si existe, vive enteramente en el registry real, cuyo código no está en este repo). Dos capas
donde podría agregarse una defensa, sin que sea una decisión tomada acá:

- **En el updater/oracle:** límite de cuánto puede moverse `mid`/`delta` entre dos
  `updateState` consecutivos en una ventana corta — mismo espíritu que
  `max_source_age_ms`/`max_source_divergence` del PR `propamm-factory#9`, pero mirando hacia
  adentro (key propia) en vez de hacia afuera (fuente de precio).
- **En el taker/agregador:** no es responsabilidad del contrato, pero vale decirlo: un
  `minAmountOut` ajustado convierte el ataque en "revert, pierdo gas" en vez de "me cobran la
  diferencia en silencio".

## Qué NO prueba este PoC

- No mide si el registry REAL (no el `MockPUR` de test) ya tiene alguna ventana de frescura o
  límite de variación — su código no está en este repo (`contracts/src/interfaces/
  IPrioUpdateRegistry.sol` es solo la interfaz). Eso habría que confirmarlo mirando el registry
  real on-chain.
- No corre contra Kipseli ni ningún venue de terceros — ese intento (en
  `propamm-router-contracts`) quedó bloqueado porque su cadena de contratos reales no está
  documentada en ningún repo al que tengamos acceso, y reversarla a ciegas dio una dirección de
  registry equivocada. Este PoC usa el contrato que SÍ conocemos de punta a punta: el nuestro.
