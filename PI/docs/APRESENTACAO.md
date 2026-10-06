# Endpoint Investigator — Regras de Análise

## Ideia principal

O **Endpoint Investigator** analisa uma máquina Linux usando informações de **processos, serviços, permissões e rede**.

A ferramenta é **determinística**: ela segue regras fixas.  
Ela **não considera um sinal isolado como vulnerabilidade**.

---

## Regra 1 — Serviço privilegiado + recurso modificável

### Resumo
Um serviço rodando como **root** sozinho **não é considerado vulnerável**.

A ferramenta procura esta combinação:

```text
serviço ativo
+ processo com UID 0 (root)
+ recurso usado pelo serviço
+ recurso modificável por não-root
= needs_review
```

### Exemplo estranho

```text
backup-agent.service
→ processo root
→ /opt/backup/backup.sh
→ permissão 0777
```

**Resultado:** `needs_review`

Motivo: o serviço privilegiado usa um recurso que pode ser alterado por usuários não-root.

### Exemplo normal

```text
backup-agent.service
→ processo root
→ /opt/backup/backup.sh
→ permissão 0700
```

**Resultado:** não gera `needs_review` só por ser root.

---

## Regra 2 — Porta + processo + serviço

### Resumo
Uma porta aberta **não é considerada vulnerabilidade sozinha**.

A ferramenta tenta descobrir:

```text
porta
→ PID
→ processo
→ serviço relacionado
```

Se o processo for filho ou neto do `MainPID` do serviço, a ferramenta pode seguir a cadeia de `PPID`.

### Exemplo estranho

```text
0.0.0.0:8080
→ PID 43
→ PPID 42
→ PID 42 é MainPID do serviço
```

**Resultado:** contexto para investigação.

A porta pode ser inesperada, mas a ferramenta **não afirma que existe uma vulnerabilidade**.

### Exemplo normal

```text
127.0.0.1:8080
→ processo conhecido
→ serviço esperado
```

**Resultado:** `informational`

É uma relação observada, não um alerta de vulnerabilidade.

---

## Regra 3 — Processo + processo pai

### Resumo
A ferramenta usa `PID` e `PPID` para entender a **origem de um processo**.

```text
processo
→ PPID
→ processo pai
→ usuários dos dois
```

### Exemplo estranho

```text
processo inesperado
→ pai inesperado
→ identidade diferente
```

**Resultado:** contexto para investigação.

A diferença de usuário **não prova escalada de privilégio**.

### Exemplo normal

```text
serviço
→ processo iniciado pelo PID 1
→ identidades esperadas
```

**Resultado:** `informational`

---

## Regra 4 — Se faltam dados, não inventar

### Resumo
Quando faltam informações importantes, a ferramenta não força uma conclusão.

```text
faltou UID
ou
faltou permissão
ou
faltou processo pai
→ inconclusive
```

### Exemplo estranho

```text
serviço ativo
→ MainPID conhecido
→ UID não observado
```

**Resultado:** `inconclusive`

### Exemplo normal

```text
serviço ativo
→ MainPID conhecido
→ UID conhecido
→ permissões conhecidas
```

A ferramenta consegue aplicar normalmente as regras anteriores.

---

## Tipos de resultado

```text
needs_review
→ existe uma combinação de evidências que merece investigação

informational
→ a ferramenta encontrou contexto útil, sem indicar vulnerabilidade

inconclusive
→ faltam informações para concluir
```

---

# Demonstração

## 1. Dataset fornecido pela disciplina

```bash
.venv/bin/python tools/generate_dataset.py \
  --level intermediate \
  --seed 5 \
  --output training-generated/professor-correlation
```

```bash
.venv/bin/python -m endpoint_investigator analyze-dataset \
  training-generated/professor-correlation
```

### O que mostrar na saída

```text
backup-agent.service
PID 2417
root
/opt/backup/backup.sh
0777
C1 → needs_review
```

Explicação:

> Serviço privilegiado + recurso modificável por não-root = situação que merece investigação.

---

## 2. Caso normal para comparação

```bash
.venv/bin/python -m endpoint_investigator analyze \
  tests/fixtures/scenario_normal.json
```

Explicação:

> Existe processo root, mas os recursos observados não apresentam a condição de modificação por não-root. Portanto, root sozinho não gera alerta.

---

## Frase final

> O objetivo da ferramenta não é gerar o maior número possível de alertas. É correlacionar evidências e produzir uma conclusão justificável, deixando explícito quando faltam informações.
