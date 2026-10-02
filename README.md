# EyesOfNico

Monitor de Linux em terminal, com o tema neon magenta → roxo → azul. A versão 2 substitui o loop Bash por um binário Go, sem dependências externas de runtime e sem executar comandos durante a coleta.

## Executar

Requisitos: Linux, `/proc`, terminal com controle de cursor e Go **1.22+** para compilar. `/sys` fornece dispositivos e sensores opcionais. O binário compilado não precisa de Go, Bash, ncurses, Docker ou systemd.

```bash
./nicotop.sh
```

O launcher compila na primeira execução e recompila quando os fontes mudam. Também é possível compilar e executar diretamente:

```bash
make build
./bin/nicotop
```

Para instalar o binário:

```bash
make install PREFIX="$HOME/.local"
# ou, para instalação no sistema:
sudo make install
```

A interface se adapta ao tamanho real do terminal. **120×40** acomoda todos os painéis; em **80×24** o overview prioriza o resumo e os processos. O mínimo é **40×12**. Abaixo disso, aparece uma mensagem de resize. O histórico é preservado ao redimensionar ou trocar de visão.

## O que monitora

| Visão | Dados |
| --- | --- |
| **1 · Overview** | CPU, RAM, swap, tráfego, disco e tabela interativa de processos |
| **2 · CPU** | Uso por núcleo, user/system, iowait, steal, load 1/5/15, context switches, forks, frequência, temperatura e PSI |
| **3 · Memory** | Memória disponível, uso, cache, buffers, slab, páginas sujas/writeback, swap, pressão e processos |
| **4 · Network** | RX/TX, gráficos por interface ou agregado, pacotes/s no JSON, erros, drops e contadores de bytes |
| **5 · Disks** | Leitura/escrita, IOPS, ocupação, latência, fila e capacidade/inodes dos filesystems locais |
| **6 · Processes** | PID, usuário, estado, CPU, RSS, memória %, nice, threads, tempo de CPU, comando e I/O opcional |

Colunas e gráficos se adaptam à largura disponível. Nas visões de CPU, rede e disco, use as setas para acessar listas maiores que a tela. Temperaturas e frequências dependem dos sensores exportados pelo kernel.

A tabela oferece busca incremental, ordenação, árvore de processos, filtro do usuário atual e detalhes. Ao navegar, a seleção acompanha a identidade do processo mesmo se ele mudar de posição. A busca em árvore mantém os ancestrais necessários para entender a hierarquia.

## Teclado

| Tecla | Ação |
| --- | --- |
| `1` … `6`, `Tab` | Selecionar ou alternar visões |
| `↑` / `↓`, `PgUp` / `PgDn`, `Home` / `End` | Selecionar processo ou percorrer a lista da visão |
| `/` | Buscar PID, usuário, nome ou comando; Enter aplica, Esc cancela |
| `Esc` | Limpar filtro, fechar diálogo ou voltar ao overview |
| `c`, `m` | Ordenar por CPU ou memória |
| `s`, `r` | Alternar critério de ordenação / inverter ordem |
| `t`, `u`, `f` | Árvore / somente meu usuário / comando completo ou nome |
| `i` | Ativar/desativar coleta de I/O por processo |
| `Enter` | Detalhes do processo selecionado |
| `k`, `x`, `z` | SIGTERM / SIGKILL / suspender ou retomar processo |
| `[` / `]`, `←` / `→` | Escolher interface ou disco |
| `p` ou espaço | Pausar/retomar a amostragem |
| `+` / `-` | Acelerar/desacelerar, de 0,2 a 10 segundos |
| `?` ou `h` | Ajuda; setas percorrem diálogos em terminais pequenos |
| `Ctrl-Z` | Suspender o monitor e devolver o terminal ao shell |
| `q` ou `Ctrl-C` | Sair |

Os atalhos antigos `d` (overview), `y` (CPU) e `n` (rede) continuam disponíveis.

Sinais exigem confirmação com **y** e usam **pidfd** para verificar a identidade antes de agir. Isso requer Linux 5.3+ em amd64/arm64; em kernels antigos, o monitor funciona, mas a ação é recusada. PID 1 e o próprio monitor são protegidos. As permissões normais do Linux se aplicam; o programa não eleva privilégios. Colar texto não confirma ações.

## Opções

```bash
./bin/nicotop --refresh 0.5
./bin/nicotop --view processes --sort mem --filter postgres
./bin/nicotop --process-io
./bin/nicotop --ascii --no-color
./bin/nicotop --no-alt
./bin/nicotop --help
```

`NO_COLOR` também desativa cores. Locales `C` e `POSIX` ativam bordas ASCII automaticamente. Terminais ANSI básicos usam a paleta de 16 cores; terminais de 256 cores usam a paleta neon. `--safe` permanece como opção de compatibilidade: toda coleta já é local.

Sem terminal, inclusive via cron, pipe ou SSH:

```bash
# Uma linha JSON por amostra, após estabelecer o baseline.
./bin/nicotop --json --count 5 --refresh 1

# Fluxo contínuo; Ctrl-C/SIGTERM encerra.
./bin/nicotop --json

# Retrato legível, sem códigos ANSI; usa duas amostras separadas por 200 ms.
./bin/nicotop --snapshot 120x40
./bin/nicotop --snapshot 100x30 --view disks
```

JSON inclui contadores, taxas, identidade dos processos, disponibilidade de PSI/I/O, horário, intervalo medido, duração da coleta e avisos. A primeira linha já tem taxas calculadas. Campos de taxas usam bytes/s; memória e capacidade usam bytes.

## Como as métricas são calculadas

- CPU usa diferenças de todos os campos relevantes de `/proc/stat`. Guest não é somado novamente, e iowait é exibido separadamente. Na tabela de processos, **100% equivale a um núcleo**; um processo multithread pode ultrapassar 100%.
- Memória usada é `MemTotal - MemAvailable`. Cache recuperável não é tratado integralmente como memória indisponível. RSS é a estimativa rápida fornecida pelo kernel.
- Rede, disco e CPU dos processos usam o **tempo monotônico efetivamente transcorrido**. Não há sleeps dentro dos coletores. Interfaces novas e PIDs reutilizados começam com um novo baseline; contadores que diminuem não geram underflow.
- Setores de `diskstats` são convertidos usando **512 bytes**, independentemente do setor físico. Await e IOPS consideram leituras e escritas. Ocupação mede tempo ativo; não representa toda a capacidade de paralelismo de um NVMe.
- PSI mostra as médias de 10, 60 e 300 segundos. `some` mede espera de uma ou mais tarefas; `full`, de todas as tarefas não ociosas. Ausência de suporte aparece como indisponível.
- O agregado de rede soma interfaces exceto loopback. Bridges, túneis e veth podem representar o mesmo tráfego em mais de uma camada; selecione uma interface para analisar seu tráfego. Discos são exibidos individualmente, sem somar partições ou camadas de device-mapper.
- Uso percentual de filesystem segue `used / (used + available)`, considerando blocos reservados. Montagens remotas, autofs, FUSE e camadas internas de overlay de containers são excluídas.
- O escopo é o **`/proc` visível ao monitor**. Em containers, CPU/memória podem refletir o host e processos podem estar limitados pelo namespace. Não há normalização por cotas cgroup, métricas GPU ou gerenciamento de serviços.
- Usuários locais são resolvidos por `/etc/passwd`; outros aparecem por UID. Processos encerrados durante a coleta são ignorados. Restrições como `hidepid` e falta de permissão para `/proc/PID/io` podem limitar os dados.

Referências do kernel: [procfs](https://docs.kernel.org/filesystems/proc.html), [estatísticas de bloco](https://docs.kernel.org/block/stat.html) e [PSI](https://docs.kernel.org/accounting/psi.html).

## Eficiência e organização

O caminho normal lê um registro `stat` por processo e os contadores agregados do kernel. Um buffer reutilizável e parsing com array fixo evitam um `stat()` auxiliar e alocações grandes por PID. Comandos e UIDs têm cache de 5 segundos. A coleta de I/O por processo fica desligada até ser solicitada.

Filesystems, sensores e frequência usam um único worker com fila limitada e cache de 5 segundos. Um `statfs` bloqueado não trava a interface nem cria workers indefinidamente. A descoberta de dispositivos de bloco é renovada a cada 10 segundos.

A amostragem roda separada do tratamento de teclas. Não há ticks de animação em alta frequência. O renderer escreve apenas linhas alteradas, em uma única escrita por frame, e os históricos têm limite de 240 amostras por série. Pausar impede novas amostragens; uma coleta já iniciada pode terminar em segundo plano.

```text
cmd/nicotop/          CLI, JSON e snapshot
internal/monitor/    Coleta, parsing, cache e sinais via pidfd
internal/ui/         Estado, interação, layout e terminal
scripts/pty_check.py Teste do binário em pseudoterminal real
nicotop.sh           Launcher compatível
```

Foram removidos o dashboard de nove caixas, as consultas recorrentes a systemd/Docker/journal, a coleta de histórico de shell/audit e a geolocalização externa de IPs. O código anterior permanece no histórico Git.

## Verificar

```bash
make test          # Contadores, hotplug, PID reuse, árvore, busca, layouts e CLI
make check         # go vet e detector de data races
make integration   # PTY: teclado, resize, pausa, sinais, Ctrl-Z e restauração
make bench         # Parsing, coleta no host e renderização; inclui alocações
```

Os testes de sinais usam apenas processos descartáveis criados pelo próprio teste. O teste PTY requer Python 3; o detector de races requer o toolchain C usado pelo Go. A captura opcional usa Pillow e fontconfig:

```bash
python3 scripts/pty_check.py --capture /tmp/nicotop.png
```

Compilação sem CGO para outra arquitetura:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o bin/nicotop-arm64 ./cmd/nicotop
```

Benchmarks dependem do número de processos, hardware, permissões e intervalo. Compare em condições equivalentes e use `collection_ms` no JSON para acompanhar o custo no seu próprio host.
