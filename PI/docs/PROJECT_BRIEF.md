# PI — Endpoint Investigator

## Fonte de verdade do projeto

Este documento resume o enunciado da Avaliação Intermediária de Tecnologias Hackers (Prof. Rodolfo Avelino). Ele deve ser usado como referência funcional do projeto.

**Este arquivo registra requisitos, não decisões de implementação.** A solução técnica aprovada está em `ARCHITECTURE.md`, a ordem de execução em `IMPLEMENTATION_PLAN.md` e o estado atual em `PROGRESS.md`.

Não invente requisitos acadêmicos além dos descritos aqui; propostas extras devem ser claramente tratadas como extensões.

## Objetivo

Desenvolver uma ferramenta de investigação de segurança para sistemas GNU/Linux chamada **Endpoint Investigator**.

Ela não precisa ser antivírus nem um EDR completo. Deve executar uma análise sob demanda do endpoint, coletar e relacionar informações do sistema e ajudar um analista a identificar configurações ou comportamentos que mereçam investigação.

Princípio central: **uma evidência isolada raramente é suficiente para caracterizar um incidente**. A ferramenta deve ajudar a observar, correlacionar evidências, formular hipóteses e deixar explícito o que ainda não pode ser concluído.

## Dimensões obrigatórias

A solução deve analisar obrigatoriamente:

1. **Processos**
2. **Permissões**
3. **Serviços**

Fontes adicionais são opcionais e só devem ser adicionadas quando tiverem relação clara com a estratégia de investigação. Exemplos permitidos pelo enunciado:

- logs;
- conexões de rede;
- usuários e grupos;
- arquivos abertos;
- eventos do systemd;
- hashes de arquivos;
- mecanismos de inicialização e persistência.

## Fluxo de referência

```text
COLETA -> NORMALIZAÇÃO -> CORRELAÇÃO -> EVIDÊNCIAS -> HIPÓTESES -> RESULTADO DA INVESTIGAÇÃO
```

A tecnologia e a arquitetura são livres. A avaliação considera principalmente o funcionamento e a qualidade da investigação.

## Processos

Coletar e analisar contexto de processos em execução. Informações úteis incluem:

- PID e PPID;
- usuário;
- UID/GID;
- comando e argumentos;
- executável;
- processo pai;
- estado;
- recursos relacionados.

Não basta reproduzir `ps`. Os dados devem ser usados para construir relações entre processo, identidade, processo pai, arquivos, serviços e outros recursos.

**Regra importante:** o nome de um processo isoladamente não é evidência suficiente para classificá-lo como malicioso.

## Permissões

Analisar permissões de arquivos ou diretórios relevantes para os processos e serviços identificados.

A análise deve ser **orientada pelo contexto**, e não uma varredura indiscriminada de todo o filesystem.

Exemplo de raciocínio esperado:

```text
serviço executa como root
-> utiliza script
-> script pode ser alterado por usuário não privilegiado
-> possível relação de privilégio insegura
```

Isso gera uma hipótese de risco; **não prova exploração**.

## Serviços

Identificar serviços relevantes em execução e relacioná-los aos processos e recursos utilizados.

Podem ser analisados:

- nome;
- estado;
- usuário e grupo;
- comando de inicialização;
- executável;
- scripts;
- processos associados.

Um serviço executado como root não deve ser automaticamente classificado como vulnerável. O contexto do uso do privilégio é parte essencial da análise.

## Correlações

Implementar **pelo menos duas formas de correlação entre fontes diferentes**. Processos, permissões e serviços não podem aparecer apenas como listas independentes.

Exemplos do enunciado:

- processo + serviço + permissão -> hipótese de risco;
- processo + PPID + usuário -> contexto de execução;
- serviço + arquivo + usuário -> relação de privilégio;
- processo + serviço + log -> possibilidade de reconstrução temporal.

Outras correlações são válidas se a relevância para uma investigação de segurança puder ser justificada.

## Modelo de resultado

Sempre que possível, o resultado deve distinguir:

- **Evidência:** informação efetivamente observada no sistema.
- **Interpretação:** significado técnico atribuído à evidência.
- **Hipótese:** possível explicação para a relação encontrada.
- **Evidência ausente:** informação adicional necessária para confirmar ou rejeitar a hipótese.

A ferramenta deve saber produzir resultados inconclusivos quando não houver evidência suficiente.

## Desenvolvimento e testes

Os grupos podem usar datasets de treinamento e o script fornecido pelo professor para geração de cenários.

Também é permitido criar situações controladas na própria VM Kali para validar a lógica. O objetivo é testar a ferramenta, não produzir um incidente real.

## Uso de IA

IA é permitida para programação, documentação, interpretação de evidências, geração de hipóteses e explicação dos resultados.

Se a solução incorporar um modelo de linguagem, ele **não pode ser a única camada de análise**.

Não é suficiente:

```text
DADOS -> LLM -> "Analise esta máquina"
```

A solução deve produzir evidências estruturadas por mecanismos próprios de coleta, processamento e/ou correlação **antes** de qualquer interpretação feita por um modelo.

## Limitações

O projeto não precisa identificar todos os problemas possíveis de um endpoint.

O escopo adotado deve ser explícito, incluindo situações que possam gerar:

- falsos positivos;
- interpretações incompletas;
- resultados inconclusivos.

## Entregáveis

- código-fonte completo;
- README com arquitetura, dependências, instalação, execução, fontes de informação, correlações e limitações;
- documento técnico de até 4 páginas com problema, estratégia de investigação, arquitetura, principais correlações, decisões técnicas, uso de IA quando aplicável e limitações;
- demonstração prática em ambiente ou dataset de teste.

Apresentação prevista no enunciado: **6 de outubro de 2026**.

## Critérios de avaliação

- Funcionamento da solução: **3,0**
- Aplicação dos conceitos de processos, permissões e serviços: **2,0**
- Correlação entre diferentes evidências: **2,0**
- Qualidade da análise e distinção entre evidência, interpretação e hipótese: **1,5**
- Arquitetura, código e documentação: **1,0**
- Demonstração e domínio técnico: **0,5**

## Norte para decisões

O objetivo não é encontrar o maior número de "vulnerabilidades". O projeto deve demonstrar capacidade de:

**observar -> coletar -> relacionar evidências -> formular hipóteses -> justificar conclusões**.
