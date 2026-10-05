# Endpoint Investigator — material-base do documento técnico

Texto-base de apoio ao documento técnico final de **até quatro páginas**. A divisão abaixo sugere uma página por seção e descreve somente o comportamento implementado em B0–B8. O DOCX final versionado incorpora B8 e foi novamente validado com quatro páginas.

## 1. Problema e estratégia

Investigar um endpoint GNU/Linux exige relacionar dados que, isoladamente, não caracterizam incidente. Um processo com nome incomum, um serviço root ou uma porta aberta podem ser legítimos. O Endpoint Investigator realiza um snapshot local sob demanda e relaciona processos, serviços, sockets e permissões de recursos utilizados.

A estratégia distingue evidência observada, interpretação técnica, hipótese e evidência ausente. Findings usam informational, needs_review ou inconclusive, sem score de risco artificial. O objetivo é apoiar uma investigação justificável, não maximizar alertas ou substituir um analista.

As fontes são psutil para processos/identidade e sockets locais, systemctl para serviços em execução, os.stat para recursos e pais imediatos, e pwd/grp para nomes de identidades. Não há port scan, enumeração global do filesystem, remediação ou agente residente.

## 2. Arquitetura e decisões

A implementação usa Python 3.11+, psutil como dependência de runtime e pytest no desenvolvimento. Dataclasses definem contratos JSON; biblioteca padrão implementa CLI, serialização, permissões e execução de comandos. A validação disponível foi executada em Python 3.13.12; não se afirma uma matriz de versões testadas.

O fluxo é collectors → modelos normalizados → correlações → findings → apresentação. Coletores não classificam risco. A função pura analyze_snapshot reutiliza os mesmos dados e regras em execução live e offline, sem consultar o host. reporting.py apresenta texto ou envelope JSON versionado. Comandos externos são centralizados, sem shell, com timeout e limitados às operações read-only utilizadas de systemctl.

Falhas de acesso, desaparecimento de processos, ausência de systemd e recursos indisponíveis viram issues, preservando coleta parcial. Valores desconhecidos usam null. Snapshot e relatório são formatos distintos: scan --save-snapshot cria dados brutos em arquivo novo 0600; analyze os reprocessa. Findings e limitações não alteram exit code para erro de execução.

Desde B8, analyze-dataset importa CSVs de processos/permissões, services.txt e metadata.json produzidos pelo generator original da disciplina, preservado. A normalização offline produz Snapshot v1: root literal recebe ID 0; demais nomes têm IDs desconhecidos; MainPID exige correspondência textual única e exata de ExecStart/cmd, com proveniência inferida nas lacunas. Pais vêm exclusivamente do CSV. Comandos, caminhos e identidades não são consultados no host. Arquivos inválidos são rejeitados e dados incompletos permanecem parciais. Sem sockets e sem análise de journal.log, essa fonte não produz C2.

## 3. Correlações e validação

C1 relaciona serviço ativo, MainPID, UID efetivo e recursos resolvidos. Só produz needs_review quando UID 0 é observado e permissões POSIX sugerem escrita ou substituição por não-root. Root sozinho não basta. Grupo com escrita permanece inconclusivo sem conhecer membros; substituição considera travessia e sticky bit do pai. A hipótese é possível relação insegura de privilégio, sem prova de exploração.

C2 relaciona socket, PID, processo, identidade e serviço por MainPID direto (`direct_main_pid`) ou cadeia PPID observada (`descendant_of_main_pid`). A associação indireta registra a cadeia de PIDs como evidência. A travessia pura termina em PPID desconhecido, pai ausente, self-parent ou ciclo, sem preencher lacunas; contexto incompleto permanece inconclusivo. TCP LISTEN e UDP vinculado são contexto; UDP não prova função de servidor. C3 relaciona PPID e identidades apenas de processos relevantes a serviços/listeners. Pai ou identidade ausente resulta em inconclusive. Nomes não determinam risco.

Quatro snapshots sintéticos exercitam a CLI em texto e JSON: normal resulta somente em C3 informational; unsafe_service muda o executável de 0755 para 0777 e produz C1 needs_review; listener associa a porta 8080 do filho PID 43 ao MainPID 42 pela cadeia 43 → 42, com um C2 e dois C3 informativos, sem alerta de privilégio; partial remove identidade/permissões/pai e produz três inconclusivos. Testes verificam dispositions exatas, rastreabilidade, preservação dos arquivos e operação offline sem coleta, comandos externos ou sockets.

A integração executa o generator real em diretório temporário: intermediate/seed 5 associa backup-agent.service ao PID 2417 e script 0777, produzindo needs_review. Seeds 1 (script 0700) e 2 (0777 sem vínculo) não geram alerta forte. Testes cobrem ambiguidades, entradas malformadas, IDs desconhecidos e bloqueiam consultas ao host na importação/análise. O seed reproduz o cenário, mas generated_at varia.

A suíte também cobre parsers, modelos, falhas parciais, permissões, códigos de saída e equivalência entre relatório live e reanálise de snapshot. Execute `.venv/bin/python -m pytest` para obter o resultado atual; o registro da validação está em PROGRESS.md. DEMO.md contém o roteiro e a matriz da rubrica.

## 4. Limitações e uso de IA

O snapshot não é atômico: PIDs, arquivos e estados podem mudar entre observações. MainPID e PPID não garantem identidade temporal; a ancestralidade observada é contexto, não prova de membership systemd. Cgroups, units .socket, socket activation e PID namespaces/containers permanecem fora do escopo. Falta de privilégios pode ocultar processos e sockets; ausência de registros não comprova ausência de atividade.

Bits POSIX não comprovam acesso efetivo: ACLs, capabilities, flags de mount, atributos imutáveis, namespaces, grupos suplementares, ancestrais e symlinks podem alterar a conclusão. stat segue links. ExecStart com opções/escapes ambíguos não é resolvido; há aviso. Não se mede intenção de configuração, firewall, autenticação ou integridade histórica. Esses limites podem produzir hipóteses incompletas e falsos positivos/negativos, explicitados como lacunas.

IA foi usada como assistência ao desenvolvimento e à documentação nesta implementação. Não há LLM na ferramenta: coleta, normalização, correlações e findings são mecanismos próprios determinísticos. Cabe ao grupo revisar o código, resultados e documento e explicar seu funcionamento. Não foram adicionados serviços externos, chaves de API ou interpretação remota de evidências.
