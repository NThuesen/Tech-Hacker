# Endpoint Investigator

PI de Tecnologias Hackers — ferramenta local de investigação de segurança para GNU/Linux.

## Status

**Planejamento concluído; implementação ainda não iniciada.**

O projeto foi deliberadamente desenhado para ser pequeno: snapshot sob demanda, coletores read-only, três correlações explicáveis e saída texto/JSON. Não há banco, servidor web, daemon ou LLM no núcleo.

## Documentação

Leia nesta ordem:

1. [docs/PROJECT_BRIEF.md](docs/PROJECT_BRIEF.md) — requisitos do enunciado;
2. [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — solução técnica e cobertura da rubrica;
3. [docs/IMPLEMENTATION_PLAN.md](docs/IMPLEMENTATION_PLAN.md) — execução por blocos;
4. [docs/PROGRESS.md](docs/PROGRESS.md) — bloco atual e handoff;
5. [AGENTS.md](AGENTS.md) — regras para agentes de código.

## Ideia central

```text
coleta -> normalização -> correlação -> evidências -> hipóteses -> resultado
```

Dimensões obrigatórias:

- processos;
- permissões;
- serviços.

Correlações planejadas:

- serviço privilegiado + recurso modificável;
- processo + serviço + socket de escuta;
- processo + PPID + identidade.

Cada finding deve separar **evidência, interpretação, hipótese e evidência ausente**.

## Escopo

O núcleo deve funcionar na VM Kali e também analisar snapshots JSON salvos, permitindo testes e demonstrações determinísticas.

Os comandos de instalação e execução serão adicionados no bloco B0, quando o scaffold existir. Não copie comandos provisórios para documentação como se já fossem suportados.
