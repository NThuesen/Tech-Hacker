# Demonstração reproduzível

Execute os comandos a partir de `PI/`. Prepare previamente o ambiente virtual conforme o README; instalar dependências pode exigir internet. Com o ambiente instalado, toda a demonstração abaixo funciona offline, sem incidentes reais, sudo, criação de serviços ou alteração de permissões.

## Preparação

```bash
.venv/bin/python -m endpoint_investigator --help
.venv/bin/python -m pytest
```

As quatro fixtures são sintéticas e versionadas. Os caminhos nelas são dados: `analyze` não os consulta nem executa seus comandos. UID 0, PID 42 e porta 8080 não representam um incidente real.

## Roteiro de cinco a sete minutos

1. Apresente o problema: observar processos, serviços e permissões e explicar relações, sem confundir sinal isolado com incidente. Mostre o fluxo coleta → modelos → correlações → findings → apresentação.
2. Mostre o caso normal:

   ```bash
   .venv/bin/python -m endpoint_investigator analyze tests/fixtures/scenario_normal.json
   ```

   Resultado esperado: somente C3 `informational`. O serviço usa UID 0, mas executável 0755, unit 0644 e pais 0755 pertencem a root. Não há C1. Explique que ausência de alerta não comprova segurança absoluta.
3. Mostre a alteração controlada nos dados:

   ```bash
   .venv/bin/python -m endpoint_investigator analyze tests/fixtures/scenario_unsafe_service.json
   ```

   Resultado esperado: C1 `needs_review` e C3 `informational`. A diferença relevante é `/opt/demo/worker` com modo 0777. Aponte unit, MainPID 42, UID 0, caminho, owner/grupo e modo. Leia separadamente evidência, interpretação, hipótese e evidência ausente. Não afirme exploração: ACLs, mounts, integridade e intenção ainda precisam de confirmação.
4. Mostre contexto de rede:

   ```bash
   .venv/bin/python -m endpoint_investigator analyze tests/fixtures/scenario_listener.json
   ```

   Resultado esperado: um C2 e dois C3 `informational`, sem C1. Relacione `0.0.0.0:8080` → filho PID 43 → PPID/MainPID 42 → demo.service, com UID 0 observado. Mostre `association=descendant_of_main_pid` e a cadeia `43 -> 42` na evidência. O vínculo direto, quando o socket usa o próprio MainPID, é identificado como `direct_main_pid`. Ancestralidade é contexto, não membership autoritativo: cgroups, units `.socket`, socket activation e namespaces/containers não foram verificados. A porta em escuta não comprova exposição pela rede nem vulnerabilidade; firewall e autenticação não foram observados.
5. Mostre dados insuficientes:

   ```bash
   .venv/bin/python -m endpoint_investigator analyze tests/fixtures/scenario_partial.json
   ```

   Resultado esperado: C1, C2 e C3 `inconclusive`, resumo parcial e avisos. Faltam UID, permissões e pai PID 999. A ferramenta não transforma User=root em prova de UID efetivo.
6. Mostre o formato auditável:

   ```bash
   .venv/bin/python -m endpoint_investigator analyze tests/fixtures/scenario_unsafe_service.json --format json
   ```

   Aponte `report_version`, snapshot original, summary, entidades e camadas dos findings. Todos os cenários retornam código zero, pois findings não são falhas de execução.

## Complemento ao vivo na Kali

```bash
.venv/bin/python -m endpoint_investigator scan
```

Escolha um serviço/processo e explique seus dados e eventuais lacunas. Resultados dependem do host; não espere quantidades ou dispositions fixas. Se systemd ou permissões não estiverem disponíveis, mostre a coleta parcial e continue com as fixtures. A parte reproduzível da demonstração não depende do host.

Opcionalmente, para demonstrar persistência, use um nome de arquivo que ainda não exista:

```bash
.venv/bin/python -m endpoint_investigator scan --save-snapshot demo-snapshot.json
.venv/bin/python -m endpoint_investigator analyze demo-snapshot.json
```

Esse arquivo é uma saída local solicitada, com modo 0600. Pode conter argumentos e caminhos reais do host; não faz parte das fixtures nem deve ser incluído no material público. A CLI recusa sobrescrita. A demonstração principal não precisa gravar dados reais.

## Cobertura da rubrica

| Critério | Evidência demonstrável |
| --- | --- |
| Funcionamento — 3,0 | scan local; quatro comandos analyze; texto/JSON; testes de salvar/reanalisar em test_cli.py |
| Processos/permissões/serviços — 2,0 | C1 inseguro mostra UID/PID, unit e modo do executável/pai; collectors testados com falhas |
| Correlação — 2,0 | inseguro prova C1; listener prova C2; normal mostra C3 |
| Qualidade da análise — 1,5 | quatro camadas no texto; normal sem C1; partial com três inconclusivos |
| Arquitetura/código/documentação — 1,0 | fronteiras em ARCHITECTURE.md, testes e README com fontes/comandos/limitações |
| Demonstração e domínio — 0,5 | roteiro offline e explicação das hipóteses, limites e diferenças entre os cenários |

Os testes demonstram comportamento do software; a apresentação e a avaliação acadêmica continuam sob responsabilidade do grupo.

## Complemento com o dataset do professor (B8)

```bash
.venv/bin/python tools/generate_dataset.py --level intermediate --seed 5 --output training-generated/professor-correlation
.venv/bin/python -m endpoint_investigator analyze-dataset training-generated/professor-correlation
.venv/bin/python -m endpoint_investigator analyze-dataset training-generated/professor-correlation --format json
```

Mostre backup-agent.service, MainPID 2417 inferido por igualdade textual única entre ExecStart e cmd, usuário root e `/opt/backup/backup.sh` 0777 com pai 0755. Resultado: um C1 needs_review para backup, dois C1 inconclusive para ssh/cron sem permissões e três C3 informational. Explique a hipótese de alteração do script, sem afirmar exploração. A proveniência do MainPID aparece como limitação: não veio de systemd. Não há C2 porque não há sockets nessa fonte; curl ou eventos do journal não provam escuta.

Leia a legenda: dispositions são estados da investigação/evidência, não níveis de risco. `informational` oferece contexto sem afirmar vulnerabilidade, `inconclusive` indica evidências necessárias ausentes e `needs_review` pede revisão sustentada por evidência concreta, sem provar comprometimento. Mostre os campos separados de ID técnico, correlação, entidade principal e disposition; `C1:1` e `C1:2` não são níveis.

Compare os dois C1:

- `C1:1`, `cron.service`, `inconclusive`: a relação escrita/privilégio não pôde ser avaliada; faltam permissões de `/usr/sbin/cron`. A hipótese pede evidências faltantes, sem tratar a condição insegura como observada.
- `C1:2`, `backup-agent.service`, `needs_review`: `/opt/backup/backup.sh` com modo `0777` e owner UID 0 sustenta a revisão junto ao serviço ativo e UID efetivo 0. Se uma identidade não-root puder alterar o recurso e o serviço privilegiado depois executá-lo, código modificado pode executar com privilégios elevados. Alteração e exploração não foram demonstradas.

O total continua 3 `informational`, 1 `needs_review` e 2 `inconclusive`. Mostre as quatro camadas e as lacunas preservadas, inclusive limites POSIX e vínculo MainPID inferido. A melhoria B9 modifica a redação e o texto do relatório; os critérios de detecção, campos JSON v1, IDs e dispositions continuam os mesmos.

Contraprovas reproduzíveis:

```bash
.venv/bin/python tools/generate_dataset.py --level intermediate --seed 1 --output training-generated/professor-privileged
.venv/bin/python -m endpoint_investigator analyze-dataset training-generated/professor-privileged
.venv/bin/python tools/generate_dataset.py --level intermediate --seed 2 --output training-generated/professor-permission
.venv/bin/python -m endpoint_investigator analyze-dataset training-generated/professor-permission
```

Seed 1: script 0700, nenhum needs_review; C1 fica inconclusivo por recursos ausentes como `/bin/bash`. Seed 2: `/opt/reports/report.sh` 0777 não tem vínculo com serviço e não entra em C1. O generator registra o segundo cenário como normal em metadata apesar da permissão adicional. Não conclua segurança absoluta. O seed reproduz o cenário, mas generated_at varia. Estes exemplos complementam as quatro fixtures próprias; comandos e caminhos dos dados não são executados/consultados durante a análise.
