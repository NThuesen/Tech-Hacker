# Endpoint Investigator

PI de Tecnologias Hackers — ferramenta local de investigação de segurança para GNU/Linux.

## Status

**B0–B8 concluídos: coleta live, snapshots JSON e integração offline com o dataset do professor. Nenhum novo bloco aprovado.**

O projeto foi deliberadamente desenhado para ser pequeno: snapshot sob demanda, coletores read-only, três correlações explicáveis e saída texto/JSON. Não há banco, servidor web, daemon ou LLM no núcleo.

## Documentação

Leia nesta ordem:

1. [docs/PROJECT_BRIEF.md](docs/PROJECT_BRIEF.md) — requisitos do enunciado;
2. [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — solução técnica e cobertura da rubrica;
3. [docs/IMPLEMENTATION_PLAN.md](docs/IMPLEMENTATION_PLAN.md) — execução por blocos;
4. [docs/PROGRESS.md](docs/PROGRESS.md) — bloco atual e handoff;
5. [AGENTS.md](AGENTS.md) — regras para agentes de código.

Para apresentação e entrega: [roteiro e cobertura da rubrica](docs/DEMO.md), [documento técnico final (DOCX)](docs/Endpoint_Investigator_Relatorio_Tecnico_Final.docx) e [fonte textual do relatório](docs/TECHNICAL_REPORT.md).

## Ideia central

```text
coleta -> normalização -> correlação -> evidências -> hipóteses -> resultado
```

Dimensões obrigatórias:

- processos;
- permissões;
- serviços.

Correlações implementadas:

- serviço privilegiado + recurso modificável;
- processo + serviço + socket de escuta;
- processo + PPID + identidade.

Cada finding deve separar **evidência, interpretação, hipótese e evidência ausente**.

## Escopo

O núcleo deve funcionar na VM Kali e também analisar snapshots JSON salvos, permitindo testes e demonstrações determinísticas.

Coleta de processos, sockets, serviços, permissões e análise por correlações disponíveis pela API Python e pelos comandos `scan`/`analyze`. Quatro cenários sintéticos permitem demonstrar a investigação sem internet ou incidentes reais, após preparar o ambiente.

O script original fornecido pelo professor está preservado em `tools/generate_dataset.py`. B8 adiciona `analyze-dataset DATASET_DIR` para normalizar a saída dele em `Snapshot` v1 e reutilizar as mesmas correlações C1/C2/C3. Os datasets gerados localmente ficam em `training-generated/`, ignorado pelo Git.

## Arquitetura e fontes

Coletores observam; dataclasses normalizam; `correlations.py` relaciona os dados e constrói findings; `reporting.py` apresenta o resultado; a CLI coordena os fluxos. A análise offline usa as mesmas correlações, sem nova coleta. Não há banco, daemon ou LLM no núcleo.

| Dimensão | Fonte | Relação utilizada |
| --- | --- | --- |
| Processos e identidade | psutil | PID, PPID, UID/GID, executável |
| Serviços | systemctl list-units/show | MainPID, estado, unit e ExecStart |
| Rede | psutil.net_connections | socket local → PID |
| Permissões | os.stat, pwd, grp | recurso/pai → owner, grupo e modo |

## Instalação e validação

Requer Python 3.11+ com suporte a `venv` e pip. Execute a partir de `PI/`:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/python -c 'import endpoint_investigator'
.venv/bin/python -m endpoint_investigator --help
.venv/bin/python -m pytest
```

O ambiente virtual mantém as dependências isoladas. A única dependência de runtime é `psutil`, usada pelos coletores de processos/rede; os testes usam `pytest`. O build usa `setuptools`.

## Execução

Para usar a CLI, execute a partir de `PI/`:

```bash
.venv/bin/python -m endpoint_investigator scan
.venv/bin/python -m endpoint_investigator scan --format json
.venv/bin/python -m endpoint_investigator scan --save-snapshot snapshot.json
.venv/bin/python -m endpoint_investigator analyze snapshot.json
.venv/bin/python -m endpoint_investigator analyze snapshot.json --format json
```

`scan` observa o host; `analyze` usa exclusivamente o arquivo informado e a mesma função de correlação. `--save-snapshot` cria um arquivo novo com permissões 0600 e recusa sobrescrever arquivos existentes. Essa gravação explícita é a única escrita do fluxo de coleta.

O relatório JSON v1 contém `report_version`, `snapshot`, `summary` e `findings`. O arquivo salvo por `--save-snapshot` contém somente o snapshot JSON v1, aceito por `analyze`; um relatório completo não é um arquivo de entrada de snapshot. O resumo inclui contagens, dispositions e `collection_status`: `partial_or_limited` quando há issues, ou `no_reported_issues` quando não há avisos registrados, sem garantir cobertura completa.

Texto apresenta evidência, interpretação, hipótese e evidência ausente, além das entidades e dos avisos de coleta. Relatórios vão para stdout; erros para stderr. Códigos: **0** para execução concluída, inclusive findings e coleta parcial; **1** para falha de leitura, gravação ou dados inválidos; **2** para argumentos inválidos. Findings não são erros de execução.

```python
from endpoint_investigator.scan import collect_snapshot

snapshot = collect_snapshot()
print(len(snapshot.processes), len(snapshot.sockets), len(snapshot.issues))
```

A chamada observa o host uma vez, sem port scan ou alteração do endpoint. Os coletores retornam `(registros, issues)` e podem ser substituídos em testes. A coleta de serviços usa comandos read-only de `systemctl`, centralizados em `system.py`, sem shell, com timeout de dez segundos por chamada e sem interação para autenticação.

Processos incluem PID/PPID, identidade efetiva (UID/GID), username informado por psutil, estado, argumentos e executável. Acesso negado preserva os demais campos; processos encerrados ou com PID reutilizado ficam apenas com PID e aviso. Nomes são dados, sem classificação de risco.

Rede inclui TCP em LISTEN e UDP com endereço local sem peer remoto, em IPv4/IPv6. UDP não possui estado LISTEN: o estado da fonte é preservado, e a presença do socket não prova que seja um servidor. O PID é mantido quando fornecido; ausências geram aviso. Sem privilégios, sockets podem ser omitidos silenciosamente pelo SO, e a coleta registra essa limitação.

Serviços são selecionados por `systemctl list-units --type=service --state=running`; as propriedades vêm de `systemctl show`. `MainPID` é associado aos processos observados por `collectors.services.associated_process()`. PID ausente/zero vira `null` com aviso; PID sem processo observado também gera aviso. User/Group vazios são preservados como configuração vazia, sem inferir identidade. ExecStart é mantido como texto da fonte. Falhas por unit preservam as demais; systemd indisponível gera snapshot parcial válido.

O snapshot não é atômico: processos, sockets, serviços e arquivos podem mudar entre observações, e um PID coincidente não garante identidade temporal. Os testes usam mocks e fixtures de `systemctl show`, cobrindo casos completos, falhas parciais, corrida de PID, filtragem de sockets e ausência de systemd.

## Permissões contextuais

A seleção deduplica executáveis dos processos, arquivos de unit e caminhos absolutos extraíveis de `ExecStart`. Scripts absolutos no primeiro argumento de interpretadores conhecidos são aceitos; opções de interpretador, shell, variáveis e escapes ambíguos geram aviso. Nenhum comando de `ExecStart` é executado.

`os.stat` consulta somente esses recursos e seus pais imediatos, sem varredura recursiva. Registros separados dos pais preservam owner, grupo e bits necessários à avaliação de substituição; `parent_mode` também fica no recurso. Arquivo ausente usa `exists=false`; falha de acesso preserva `exists=null`. Falha na resolução de nomes mantém os IDs numéricos.

`permissions.assess_permissions(recurso, pai)` retorna uma indicação separada dos fatos: `direct_write` e `replacement` podem ser `True` (possibilidade pelos bits), `False` (ausência desse sinal POSIX) ou `None` (informação insuficiente). Escrita apenas por grupo permanece inconclusiva sem conhecer seus membros. Substituição considera escrita/travessia do pai e sticky bit. Isso não afirma vulnerabilidade nem comprova acesso efetivo.

As limitações ficam nos avisos do snapshot e em `missing_evidence` da avaliação: ACLs, capabilities, flags de mount, atributos imutáveis, namespaces, membros de grupos, ancestrais e symlinks. `os.stat` segue symlinks; os metadados não descrevem necessariamente o próprio link. Os testes cobrem root-only, owner não-root, group-writable, world-writable, falhas e diretório pai.

## Modelos e snapshot JSON

A análise usa `correlations.analyze_snapshot(snapshot)` e retorna uma lista de `Finding`, sem consultar o host nem modificar os dados recebidos:

```python
from endpoint_investigator.correlations import analyze_snapshot

findings = analyze_snapshot(snapshot)
```

C1 associa cada serviço aos caminhos resolvidos e ao processo MainPID. Produz `needs_review` somente com estado ativo, UID efetivo 0 observado e indicação POSIX de escrita/substituição por não-root. Dados insuficientes produzem `inconclusive`; serviço root com permissões observadas sem esse sinal não gera C1. User configurado como root não substitui UID observado. Ausência de C1 não prova segurança.

C2 descreve sockets TCP LISTEN ou UDP vinculado, processo, identidade e serviços associados. Produz `informational` quando o vínculo está completo, ou `inconclusive` quando faltam dados. C3 descreve PPID e identidades somente dos processos ligados a serviços/listeners, uma vez por PID; pai ou UID ausente mantém o resultado inconclusivo.

C2 registra `direct_main_pid` quando `socket.pid == service.main_pid` e `descendant_of_main_pid` quando a cadeia PPID observada alcança o MainPID. Na associação indireta, a evidência mostra a cadeia (por exemplo, `43 -> 42`) e as entidades incluem os processos usados. A resolução é pura, termina em pai ausente, PPID desconhecido, self-parent ou ciclo e não preenche lacunas. Todas as units alcançadas são preservadas, sem escolher ownership exclusivo. Descendência exige registros de todos os PIDs até o MainPID; ausência de associação mantém C2 inconclusiva. A ancestralidade é contexto, não prova autoritativa de membership systemd.

Cada finding separa fatos com referências às entidades, interpretação, hipótese e evidência ausente. Avisos pertinentes de coleta acompanham as lacunas. Identificadores C1/C2 usam o índice da entidade no snapshot; C3 usa PID. São reproduzíveis para o mesmo snapshot, sem promessa de estabilidade entre snapshots. Nomes e portas isolados nunca determinam risco. Limitações POSIX, exposição real e identidade temporal continuam exigindo investigação.

`src/endpoint_investigator/models.py` define `ProcessRecord`, `ServiceRecord`, `NetworkRecord`, `PermissionRecord`, `Snapshot` e `Finding`, além de metadata e avisos estruturados. Todos oferecem `to_dict()`, `from_dict()`, `to_json()` e `from_json()`.

```python
from endpoint_investigator.models import ProcessRecord, Snapshot

snapshot = Snapshot(processes=[ProcessRecord(pid=42)])
restored = Snapshot.from_json(snapshot.to_json())
assert restored == snapshot
```

O contrato atual usa `schema_version: 1`. Campos opcionais desconhecidos usam `null`; listas vazias representam ausência de registros, sem provar ausência de processos/serviços no endpoint. Limitações observadas devem acompanhar os dados em `issues`. Tipos inválidos, campos desconhecidos e versões incompatíveis são rejeitados com `ValueError`. Os detalhes estão em [ARCHITECTURE.md](docs/ARCHITECTURE.md#contrato-json-v1-b0).

Os testes validam round-trip de snapshots completos e parciais, preservação das camadas de findings, dados inválidos e execução da CLI. Os registros dos testes são sintéticos.

## Cenários integrados e demonstração offline

```bash
.venv/bin/python -m endpoint_investigator analyze tests/fixtures/scenario_normal.json
.venv/bin/python -m endpoint_investigator analyze tests/fixtures/scenario_unsafe_service.json
.venv/bin/python -m endpoint_investigator analyze tests/fixtures/scenario_listener.json
.venv/bin/python -m endpoint_investigator analyze tests/fixtures/scenario_partial.json
.venv/bin/python -m pytest tests/test_scenarios.py
```

| Cenário | Resultado esperado |
| --- | --- |
| normal | C3 informational; sem C1 apesar de UID 0 |
| unsafe_service | C1 needs_review por executável 0777 + serviço privilegiado; C3 informational |
| listener | C2 informational por filho PID 43 → MainPID 42; dois C3 informational; sem C1 |
| partial | C1/C2/C3 inconclusive, com avisos de coleta |

Os testes end-to-end executam texto e JSON, verificam resultados exatos, fontes e preservação das fixtures. Testes adicionais bloqueiam coleta/comandos/sockets durante a análise offline. O [roteiro](docs/DEMO.md) explica cada etapa e mapeia todos os critérios da rubrica. A instalação deve ser preparada antes da demonstração; a análise das fixtures não depende de internet.

## Dataset do professor (B8)

Execute a partir de `PI/`:

```bash
.venv/bin/python tools/generate_dataset.py --level intermediate --seed 5 --output training-generated/professor-correlation
.venv/bin/python -m endpoint_investigator analyze-dataset training-generated/professor-correlation
.venv/bin/python -m endpoint_investigator analyze-dataset training-generated/professor-correlation --format json
```

`dataset.import_dataset(directory)` lê `processes.csv`, `permissions.csv`, `services.txt` e `metadata.json`. `dataset.parse_dataset(processes, permissions, services, metadata)` normaliza esses quatro textos sem I/O. O Snapshot v1 resultante usa o mesmo `analyze_snapshot()` e reporting, sem alterar C1/C2/C3 ou adicionar dependências. O generator original permanece intacto.

O seed 5 seleciona `correlation`: backup-agent.service → PID 2417 → `/bin/bash /opt/backup/backup.sh` → script 0777 gera C1 `needs_review`, sem afirmar exploração. Outros serviços ficam inconclusivos por permissões ausentes. MainPID exige correspondência textual única e exata de ExecStart/cmd; a proveniência inferida aparece nos issues e nas lacunas dos findings. Não há escolha entre duplicatas ou aproximação por nome.

Somente o nome literal root recebe UID/owner UID/group GID 0. Outros nomes mantêm IDs desconhecidos. Pais vêm apenas de registros de diretórios presentes no CSV; caminhos e identidades nunca são consultados no host. Nenhum comando dos dados é executado. GID dos processos, FragmentPath e grupo configurado não são fornecidos. Entradas malformadas, identificadores duplicados e arquivos obrigatórios ausentes retornam código 1 com erro em stderr; vínculos incompletos produzem issues e resultados parciais com código 0.

`generated_at` fica no aviso de origem, sem ser apresentado como data de coleta; hostname/platform permanecem desconhecidos. Timestamps por linha não são usados para correlação temporal. `journal.log` e `README.txt` não são analisados. Não há sockets nessa fonte, portanto não há C2. O seed reproduz o cenário, mas `metadata.generated_at` varia entre gerações. As quatro fixtures próprias continuam disponíveis.

## Limitações

- A coleta não é atômica; relações por PID podem sofrer corrida ou reutilização. A cadeia PPID cobre somente ancestrais observados; cgroups, units `.socket`, socket activation e PID namespaces/containers não são resolvidos.
- Visibilidade depende das permissões e do namespace; listas vazias e ausência de findings não comprovam segurança ou cobertura completa.
- Permissões POSIX são indícios. ACLs, capabilities, mounts, atributos imutáveis, membros de grupos, ancestrais e symlinks podem mudar o acesso efetivo.
- ExecStart ambíguo não é executado nem resolvido por tentativa. Sockets UDP podem pertencer a clientes; escuta não comprova exposição externa.
- Não há verificação de exploração, integridade histórica, firewall, autenticação ou intenção de configuração. Hipóteses podem ter falsos positivos e lacunas; os dados ausentes são explicitados.
- Python mínimo declarado é 3.11; a validação registrada foi feita em 3.13.12. Os cenários são sintéticos e não equivalem a uma avaliação em todos os ambientes Linux.

IA auxiliou o desenvolvimento/documentação; a ferramenta não usa IA em execução. O documento técnico final em `docs/Endpoint_Investigator_Relatorio_Tecnico_Final.docx` incorpora B8 e permanece com quatro páginas; `docs/TECHNICAL_REPORT.md` é a fonte textual de apoio.
