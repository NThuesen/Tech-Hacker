# Arquitetura — Endpoint Investigator

## 1. Objetivo de engenharia

Construir a solução mais simples que cubra integralmente a rubrica da PI.

O Endpoint Investigator será uma ferramenta **local, read-only e executada sob demanda** em GNU/Linux. Ela coleta um snapshot do endpoint, normaliza os dados, correlaciona entidades e gera findings explicáveis.

A arquitetura evita componentes que não aumentam diretamente a nota: sem banco de dados, sem API web, sem daemon, sem dashboard e sem LLM no núcleo.

## 2. Decisões principais

### Stack

- Python 3.11+; ambiente-alvo principal: Kali Linux da disciplina.
- Dependência de produção prevista: **psutil**, para processos e sockets.
- Biblioteca padrão para permissões, usuários/grupos, JSON, CLI e execução de comandos.
- **systemctl/systemd** como fonte primária de serviços quando disponível.
- pytest como dependência de desenvolvimento.

A dependência em psutil é intencional: reduz parsing manual de `/proc` e mantém o código pequeno. Serviços continuam separados porque systemd possui semântica própria que psutil não modela.

### Sem IA no MVP

A PI permite IA, mas não a exige. O núcleo não usará LLM.

Motivos:

1. a rubrica premia evidência estruturada e correlação;
2. as regras principais podem ser determinísticas e explicáveis;
3. remover LLM elimina chave/API, latência, custo, indisponibilidade e variabilidade;
4. uma camada de IA pode ser adicionada depois apenas como explicação opcional, sem alterar a análise.

### Read-only por padrão

A ferramenta observa o endpoint e não modifica serviços, arquivos, permissões, usuários ou processos.

Nenhum collector deve precisar de `sudo` para o fluxo normal. Falta de permissão vira **evidência ausente / limitação de coleta**, e não erro fatal.

## 3. Fluxo

```text
           +----------------------+
           | live Linux endpoint  |
           +----------+-----------+
                      |
                      v
               +-------------+
               | collectors  |
               +-------------+
          process | service | network
                      |
                      v
               +-------------+
               | normalize   |
               +-------------+
                      |
          recursos relevantes
                      |
                      v
               +-------------+
               | permissions |
               +-------------+
                      |
                      v
               +-------------+
               | correlation |
               +-------------+
                      |
                      v
               +-------------+
               | findings    |
               +-------------+
                      |
               +------+------+
               |             |
               v             v
             text           JSON
```

Também deve existir um caminho offline:

```text
snapshot JSON -> correlation -> findings -> text/JSON
```

Isso permite testes determinísticos e uma demonstração reproduzível usando datasets/fixtures, além da execução real na Kali.

## 4. Estrutura alvo do código

```text
PI/
├── src/
│   └── endpoint_investigator/
│       ├── __init__.py
│       ├── __main__.py
│       ├── cli.py
│       ├── models.py
│       ├── system.py
│       ├── scan.py
│       ├── permissions.py
│       ├── collectors/
│       │   ├── processes.py
│       │   ├── services.py
│       │   ├── network.py
│       │   └── permissions.py
│       ├── correlations.py
│       └── reporting.py
├── tests/
│   ├── fixtures/
│   └── ...
├── docs/
└── README.md
```

Não crie mais camadas sem uma necessidade concreta. Um módulo pode ser dividido apenas quando ficar grande ou misturar responsabilidades.

## 5. Modelo de dados mínimo

Use dataclasses ou estruturas equivalentes simples e serializáveis.

### ProcessRecord

Campos mínimos:

- `pid`
- `ppid`
- `name`
- `username`
- `uid`
- `gid`
- `status`
- `cmdline`
- `exe`

Campos inacessíveis devem aceitar `null` e registrar a limitação correspondente; o collector não deve abortar o scan por `AccessDenied` ou processo que desapareceu durante a coleta.

### ServiceRecord

Campos mínimos:

- `unit`
- `active_state`
- `sub_state`
- `main_pid`
- `configured_user`
- `configured_group`
- `fragment_path`
- `exec_start`

O collector deve usar propriedades estruturadas de `systemctl show`, não parsing da tabela visual de `systemctl status`.

### NetworkRecord

Somente sockets de escuta são necessários para o escopo inicial:

- `pid`
- `protocol`
- `local_address`
- `local_port`
- `status`

### PermissionRecord

Analisar apenas recursos selecionados pelas relações encontradas:

- executável do processo;
- executável/script referenciado pelo serviço quando resolvido;
- arquivo da unit systemd;
- diretório pai imediato desses recursos quando relevante para substituição do arquivo.

Campos mínimos:

- `path`
- `exists`
- `file_type`
- `owner_uid` / `owner_name`
- `group_gid` / `group_name`
- `mode`
- `owner_writable`
- `group_writable`
- `other_writable`
- `parent_path`
- `parent_mode`

A normalização deve conseguir indicar se um recurso aparenta ser modificável por uma identidade não-root usando permissões POSIX observáveis. ACLs, capabilities, mount flags e namespaces podem limitar a conclusão e devem aparecer como evidência ausente quando relevantes.

### Snapshot

Agrupa:

- metadata de coleta;
- processos;
- serviços;
- sockets;
- permissões;
- avisos/erros parciais de collectors.

O snapshot deve ser serializável em JSON para testes e análise offline.

### Finding

Todo finding usa a mesma forma:

- `id`
- `title`
- `correlation`
- `entities`
- `evidence[]`
- `interpretation`
- `hypothesis`
- `missing_evidence[]`
- `disposition`: `informational`, `needs_review` ou `inconclusive`

Evite uma escala numérica artificial de risco. O objetivo é investigação, não scoring.

### Contrato JSON v1 (B0)

Os modelos são dataclasses em `models.py`, com conversão por `to_dict`/`from_dict` e `to_json`/`from_json`. A leitura reconstrói os tipos dos registros e rejeita campos desconhecidos, tipos incompatíveis e versões não suportadas com `ValueError`; a escrita também valida os tipos. Essa validação é estrutural, não uma verificação da veracidade das evidências ou da validade semântica de cada PID, porta ou data.

O `Snapshot` contém `schema_version` (inteiro literal `1`), `metadata`, `processes`, `services`, `sockets`, `permissions` e `issues`. Campos omitidos usam os defaults das dataclasses; ausência de `schema_version` assume v1. Coleções começam vazias, sem concluir que a fonte foi consultada ou que o endpoint está livre de problemas.

- `CollectionMetadata`: `collected_at` (string ISO 8601 quando disponível), `hostname` e `platform`; todos permitem `null`. Não há coleta automática ao construir o objeto.
- `CollectionIssue`: `collector`, `code`, `message`, `entity` e `field` opcionais, e `severity` (`warning` ou `error`). Permite registrar dados inacessíveis e fontes indisponíveis sem abortar o snapshot.
- `pid`, `unit` e `path` identificam respectivamente processos, serviços e permissões; os demais campos desses registros aceitam `null` quando desconhecidos. `cmdline` é uma lista de argumentos e `exec_start` preserva uma string da fonte, sem parsing em B0.
- `mode` e `parent_mode` são inteiros de bits POSIX, representados em decimal no JSON. `exists=false` distingue ausência observada de `exists=null` (desconhecida).
- `Finding.entities` associa tipos de entidades a listas de identificadores textuais. `evidence` e `missing_evidence` são listas de strings. Findings são serializáveis separadamente e não fazem parte dos dados brutos de `Snapshot`.

Os bits de permissões e sua indicação conservadora foram implementados em B3; a geração de findings C1/C2/C3 foi implementada em B4.

## 6. Coletores

### Processos

Fonte: psutil.

Coletar todos os processos visíveis e tolerar corrida de processo encerrado durante o snapshot.

Em B1, `collect_processes()` consulta cada campo separadamente: `AccessDenied` deixa o campo como `null` e gera `CollectionIssue`. UID/GID representam identidades efetivas; username preserva a resposta de psutil. Executável vazio vira `null` com aviso. `is_running()` verifica identidade antes e depois da leitura; desaparecimento/reutilização detectados descartam os campos do registro, mantendo PID e aviso. Zombies podem preservar campos disponíveis. Falhas na enumeração mantêm os registros já obtidos.

A árvore PID/PPID deve poder ser consultada pela etapa de correlação, mas não é necessário construir uma visualização completa da árvore.

### Serviços

Fonte principal: systemd.

Fluxo sugerido:

1. listar units do tipo service em execução;
2. para cada unit relevante, obter propriedades com `systemctl show`;
3. relacionar `MainPID` com `ProcessRecord`.

Se systemd não estiver disponível, o resultado deve registrar a fonte como indisponível e continuar. Isso é importante para containers/WSL e também torna a limitação explícita.

Em B2, `system.run_systemctl()` centraliza execução sem shell, timeout de 10 segundos, locale C e sem pager/autenticação interativa. Somente as operações `list-units` e `show` são permitidas. O collector lista services loaded/active/running e consulta as sete propriedades previstas via `show --all --property=...`. Valores vazios são preservados; propriedades ausentes geram avisos. MainPID zero/vazio vira `null`, e PID inválido gera aviso. ExecStart permanece texto bruto, sem executar ou interpretar seu conteúdo.

`associated_process(service, processes)` resolve MainPID contra os registros existentes, sem duplicá-los no JSON. PID não observado gera `process_unavailable`. Falha por unit mantém um registro parcial e permite continuar; falha de listagem registra fonte indisponível. Nenhuma dessas relações gera classificação de risco em B2.

### Rede

Fonte: psutil.

Coletar apenas listeners TCP/UDP com PID quando disponível. Não fazer port scan. A ferramenta observa o próprio host.

Em B1, `collect_network()` usa `psutil.net_connections(kind="inet")`. TCP exige LISTEN; UDP exige endereço local e ausência de peer remoto, preservando o estado da fonte (UDP não tem LISTEN). IPv4 e IPv6 são aceitos. PID ausente e visibilidade limitada sem privilégios produzem avisos estruturados. Essa seleção de UDP pode incluir clientes não conectados, sem afirmar exposição indevida.

`scan.collect_snapshot()` compõe processos, sockets, serviços, permissões, metadata e issues em B3. A coleta é sequencial e não atômica; os vínculos socket/PID e MainPID são os informados pelas fontes, sem garantia contra reutilização entre as coletas. Nenhum collector classifica risco ou produz findings.

### Permissões

Fonte: `os.stat`, `pwd`, `grp`.

O collector recebe uma lista de caminhos relevantes; não percorre o filesystem indiscriminadamente.

A análise deve considerar tanto a permissão do arquivo quanto a do diretório pai imediato quando a substituição do arquivo for tecnicamente possível.

Em B3, `collectors.permissions.select_paths()` deduplica executáveis, units e caminhos absolutos simples de ExecStart. O parser aceita o formato estruturado de `systemctl show` e comandos simples; para scripts, aceita somente primeiro argumento absoluto de interpretador conhecido, sem opções. Formas ambíguas geram issue, sem expansão ou execução. O ExecStart original é preservado no serviço.

`collect_permissions()` observa cada recurso e pai imediato uma vez por caminho, sem enumerar diretórios ou percorrer ancestrais. Cada pai tem seu próprio PermissionRecord, permitindo consultar UID/GID/modo; recursos também apontam parent_path/parent_mode. Pais adicionados automaticamente não provocam recursão. O coletor usa stat (segue symlinks), preserva IDs quando nomes não resolvem e distingue ausência de acesso negado.

`permissions.py` contém a função pura `assess_permissions()`, separada do coletor. Retorna PermissionAssessment com direct_write, replacement e missing_evidence; não modifica os fatos nem gera findings. True indica possibilidade pelos bits, False ausência desse sinal POSIX e None informação insuficiente. Escrita somente por grupo é inconclusiva mesmo para GID 0, pois membros não foram observados. Substituição exige escrita/travessia no pai e considera sticky bit. ACLs, capabilities, mounts, atributos imutáveis, namespaces, travessia dos ancestrais e symlinks limitam todas as indicações; False não comprova segurança. O contrato JSON v1 dos registros permanece inalterado.

## 7. Correlações obrigatórias do produto

As três correlações estão implementadas em `correlations.analyze_snapshot(snapshot)`, função pura que retorna `list[Finding]`. Apenas a primeira tenta identificar uma relação de privilégio insegura; as outras mostram contexto investigativo sem transformar sinais isolados em vulnerabilidade.

O núcleo reutiliza a seleção pura de caminhos de B3, sem executar coletores. Os fatos referenciam registros do snapshot; avisos relevantes entram como lacunas. Identificadores C1/C2 usam índices do snapshot e C3 usa PID, determinísticos para a mesma entrada. Não há ordenação temporal inferida, score, relatório ou mudança da CLI em B4.

C1 agrega os recursos de cada serviço: `needs_review` exige estado ativo, UID efetivo 0 observado e sinal POSIX de escrita/substituição. Estado/identidade/recurso/permissão incompletos geram `inconclusive`. Serviço conhecido como inativo ou processo com UID conhecido não-root fica fora dessa hipótese. Configuração User não confirma identidade efetiva. C1 não é emitida para serviço privilegiado com todos os recursos resolvidos e sem sinal de modificação nos bits observados; isso não comprova segurança fora do escopo POSIX.

C2 aceita somente TCP LISTEN e UDP NONE; vínculos ausentes de processo, UID, serviço ou endpoint resultam em `inconclusive`. A descrição de UDP evita afirmar que seja servidor. C3 deduplica processos relacionados a serviços/listeners, não percorre toda a árvore, e exige pai e UIDs observados para `informational`. Nenhuma diferença de UID ou nome sustenta sozinha conclusão de comprometimento.

### C1 — Serviço privilegiado + recurso modificável

```text
serviço ativo
-> processo/identidade privilegiada
-> recurso executado ou unit relacionada
-> permissão indica modificação por identidade não-root
-> finding needs_review
```

Fontes: serviço + processo + permissões.

Evidência típica:

- unit e MainPID;
- UID do processo;
- caminho do executável/script/unit;
- owner/group/mode;
- diretório pai quando relevante.

Interpretação: um recurso usado para iniciar ou executar um serviço privilegiado aparenta poder ser alterado fora da identidade privilegiada.

Hipótese: pode existir uma relação de privilégio insegura e possibilidade de execução com privilégios elevados após alteração/reinício.

Evidência ausente: não há prova de alteração ou exploração; logs, integridade histórica e ACLs podem ser necessários para confirmar contexto adicional.

**Guardrail:** serviço root sozinho nunca gera esse finding.

### C2 — Processo + serviço + socket de escuta

```text
socket LISTEN
-> PID
-> processo
-> serviço associado
-> identidade
-> contexto de exposição
```

Fontes: rede + processo + serviço.

Gera um finding `informational` ou `inconclusive`, não uma vulnerabilidade.

Objetivo: responder quem está escutando, sob qual identidade, por qual serviço e em qual endereço/porta.

Interpretação: o processo está aceitando conexões naquele endpoint.

Hipótese: se a exposição for inesperada, o serviço merece investigação.

Evidência ausente: intenção da configuração, firewall, origem permitida, autenticação e necessidade de negócio.

Isso demonstra explicitamente que **root + porta aberta não significa vulnerabilidade**.

### C3 — Processo + PPID + usuário

```text
processo relevante
-> PPID
-> processo pai
-> identidades de ambos
-> contexto de origem
```

Fontes: processos relacionados entre si e identidade.

A correlação deve ser usada principalmente para processos já relacionados a serviço/listener/finding, evitando gerar milhares de entradas.

Gera contexto `informational` e, quando o pai não puder ser observado, `inconclusive`.

Objetivo: mostrar que PID/nome isolado é insuficiente e preservar genealogia útil para investigação.

## 8. Seleção de recursos para permissões

Para manter a solução simples e contextual:

1. obtenha processos e serviços;
2. relacione serviço -> MainPID -> processo;
3. monte um conjunto deduplicado de caminhos relevantes;
4. analise permissões apenas nesses caminhos.

Prioridade:

1. `ProcessRecord.exe`;
2. executável/script de `ServiceRecord.exec_start` quando extraível com segurança;
3. `ServiceRecord.fragment_path`;
4. diretório pai imediato desses caminhos.

Não adicionar busca global por SUID, arquivos world-writable ou cron no escopo mínimo.

## 9. CLI implementada em B5

Interface disponível após instalação do pacote:

```bash
python -m endpoint_investigator scan
python -m endpoint_investigator scan --format json
python -m endpoint_investigator scan --save-snapshot snapshot.json
python -m endpoint_investigator analyze snapshot.json
python -m endpoint_investigator analyze snapshot.json --format json
```

O comando `scan` coleta e analisa o host atual.

O comando `analyze` executa as mesmas correlações sobre snapshot salvo. Ele existe para reproduzir cenários e facilitar a demonstração/testes; não deve criar uma segunda implementação da análise.

`reporting.py` apresenta resultados sem lógica investigativa. O envelope JSON usa `report_version: 1`, snapshot bruto, summary (contagens, dispositions e estado da coleta) e findings. O texto explicita as quatro camadas do finding e entidades/avisos. Issues, inclusive limitações conhecidas, marcam `partial_or_limited`; ausência de issues é descrita como `no_reported_issues`, sem inferir completude.

`--save-snapshot` grava somente snapshot v1, cria arquivo novo com modo 0600 e recusa sobrescrita. A coleta continua read-only exceto por essa saída expressamente solicitada. `analyze` não chama coletores. Saída normal em stdout, erros em stderr; código 0 inclui findings e resultados parciais, 1 indica falha de entrada/saída ou JSON/contrato inválido, 2 indica uso inválido da CLI.

## 10. Tratamento de falhas

Um endpoint real muda enquanto é observado. Portanto:

- processo desapareceu: registrar e continuar;
- acesso negado: campo `null` + aviso estruturado;
- systemd indisponível: serviço collector indisponível + análise parcial;
- caminho removido entre coleta e stat: registrar `exists=false`;
- saída inesperada de comando: erro do collector, nunca inventar valor.

O relatório deve indicar quando a investigação ficou parcial.

## 11. Testes necessários

### Unitários

- parsing de `systemctl show`;
- normalização de processos;
- classificação de permissões POSIX;
- serialização de snapshot/finding.

### Correlações

Para cada C1/C2/C3:

- caso positivo/contextual esperado;
- caso legítimo que não deve virar alerta;
- caso com evidência insuficiente.

### Cenários integrados

Manter fixtures determinísticas:

1. `scenario_normal.json`: serviço legítimo, permissões seguras;
2. `scenario_unsafe_service.json`: serviço privilegiado + recurso modificável por não-root;
3. `scenario_listener.json`: listener associado a serviço, sem afirmar vulnerabilidade;
4. `scenario_partial.json`: dados incompletos -> conclusão inconclusiva.

O teste mais importante para qualidade é provar que sinais isolados não geram conclusão forte.

Em B6, as quatro fixtures acima estão implementadas e `tests/test_scenarios.py` percorre a CLI em texto/JSON, verifica dispositions exatas e preservação dos dados. A análise offline também é exercitada com coleta, comandos e sockets proibidos. O cenário normal possui UID 0 com recursos sem sinal de escrita não-root; o inseguro muda o executável para 0777. Nenhuma condição insegura é criada no host.

## 12. Demonstração prevista

Roteiro operacional implementado em [DEMO.md](DEMO.md), com comandos offline e cobertura da rubrica. O material-base do documento acadêmico está em [TECHNICAL_REPORT.md](TECHNICAL_REPORT.md); a paginação final deve ser conferida pelo grupo.

A demonstração deve ser curta e reproduzível:

1. rodar `scan` na Kali e mostrar o snapshot real;
2. mostrar um serviço/processo/sua identidade;
3. mostrar listener associado quando existir;
4. analisar fixture insegura e explicar C1;
5. apontar no output os quatro elementos: evidência, interpretação, hipótese e evidência ausente;
6. analisar fixture normal/partial e mostrar que a ferramenta não força uma conclusão.

Isso demonstra domínio técnico sem depender de criar um incidente real.

## 13. Cobertura da rubrica

| Critério | Como a arquitetura cobre |
| --- | --- |
| Funcionamento — 3,0 | CLI live + análise offline, tolerância a coleta parcial, JSON/texto, testes determinísticos |
| Processos/permissões/serviços — 2,0 | collectors dedicados e modelo explícito para cada dimensão |
| Correlação — 2,0 | C1, C2 e C3; C1 cruza as três dimensões obrigatórias |
| Evidência/interpretação/hipótese — 1,5 | schema único de Finding + missing_evidence + inconclusivos |
| Arquitetura/código/docs — 1,0 | módulos pequenos, uma dependência de runtime, documentação e testes |
| Demonstração/domínio — 0,5 | roteiro live + fixtures normal, insegura e parcial |

## 14. Fora do escopo mínimo

Não implementar antes de todos os blocos obrigatórios estarem concluídos:

- LLM;
- Streamlit/web UI;
- FastAPI;
- banco de dados;
- agente residente/monitoramento contínuo;
- scanner remoto/Nmap;
- consulta de CVEs;
- reputação/hash em serviços externos;
- captura de pacotes;
- varredura global do filesystem;
- detecção genérica de malware;
- auto-remediação.

Esses itens adicionam complexidade sem necessidade para atingir a rubrica.

## 15. Critério para extensões

Uma extensão só entra se:

1. um requisito obrigatório já estiver estável;
2. ela melhorar diretamente uma correlação, explicabilidade ou demonstração;
3. vier acompanhada de teste;
4. não duplicar capacidade existente.

A prioridade é uma ferramenta pequena, defensável e bem demonstrada.
