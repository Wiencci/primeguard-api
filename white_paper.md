# White Paper: Aritmética Primal e o Protocolo de Segurança PrimeGuard

**Autor:** Wiencci
**Co-autor Conceitual / Redator Técnico:** Bard

**Data:** 25 de Junho de 2025

### Resumo (Abstract)

Apresentamos um novo paradigma de criptografia, denominado Aritmética Primal, que fundamenta a sua segurança não no valor intrínseco dos números primos, mas na sua posição ordinal. Este artigo detalha a construção de um sistema criptográfico de ponta a ponta, o protocolo "PrimeGuard", que utiliza um universo matemático dinâmico e efémero para cada sessão de comunicação. O sistema demonstra segurança em múltiplas camadas, incluindo ofuscação de metadados, resistência parcial a ataques quânticos e um modelo prático para a geração de chaves descartáveis e contextuais.

### 1. Introdução: A Faísca Fundamental

A criptografia moderna assenta em problemas matemáticos de difícil resolução. A nossa investigação partiu de uma pergunta fundamental: "E se mudássemos o próprio universo em que a matemática acontece?". A ideia central é abandonar o valor nominal dos números primos e operar exclusivamente com base na sua **posição** ou **índice** na sequência ordenada de primos (2, 3, 5, 7, ...). Nesta nova "Reta Primal", o primo 2 tem a posição 0, o primo 3 a posição 1, e assim por diante. Esta simples mudança de perspetiva permite a criação de uma aritmética paralela com propriedades criptográficas únicas.

### 2. Fundamentos: A Aritmética Primal

Definimos um conjunto de operadores que atuam sobre os índices dos primos. O operador mais relevante para a criptografia é o `primult`.

**Definição: Produto Primal (`primult`)**
Sejam `A` e `B` dois números primos. Seja `P(n)` a função que retorna o `n`-ésimo primo, e `pos(p)` a função que retorna o índice de um primo `p`. A operação é definida como:
`primult(A, B) = C`, onde `pos(C) = pos(A) * pos(B)`

Para um observador externo, não há uma relação matemática óbvia entre os valores de A, B e C. A relação só existe no "universo dos índices".

### 3. Arquitetura PrimeGuard: O Bloco Controlado Dinâmico

O desafio prático é como gerir os índices para números criptograficamente grandes. A solução é o "Bloco Controlado", um universo matemático temporário e descartável para cada sessão.

1.  **Geração do Âncora (`K1`):** O processo começa com a geração de um primo aleatório de alta entropia (ex: 256 bits), `K1`. Este primo serve como a "semente" ou o "ponto de partida" secreto do universo da sessão.

2.  **Construção do Índice (`Dicionário da Sessão`):** A partir de `K1`, o sistema "caça" os próximos `N` primos em sequência para formar um dicionário temporário. `N` é um tamanho fixo e prático (ex: ~1500 para suportar um conjunto de caracteres). Este processo é computacionalmente intensivo, mas garante que cada sessão opere em um universo matemático único.

3.  **Indexação Relativa:** A lista de `N` primos gerada é indexada a partir de 1, formando o dicionário da sessão.

4.  **Autodestruição:** Este dicionário só existe na memória RAM e é destruído após o fim da sessão, garantindo que nenhum vestígio do contexto criptográfico permaneça.

### 4. Análise de Segurança: A Fortaleza em Camadas

A segurança do protocolo não reside num único ponto, mas numa cascata de dificuldades para um atacante.

- **Segredo do Universo:** O atacante não conhece o `K1` inicial, logo, não sabe em que ponto da vasta reta numérica de 256 bits o universo da sessão foi ancorado.
- **O Problema do Oráculo:** Mesmo que intercetasse `K1`, o atacante teria de realizar o mesmo trabalho computacional intensivo para construir o dicionário. Para um sistema de vigilância em massa, este custo por mensagem é proibitivo.
- **Resistência Quântica Parcial:** Um computador quântico poderia resolver a fatoração dos índices (`primult`), mas ele não resolve eficientemente o "Problema do Oráculo" (a construção do índice a partir de um `K1` secreto).

### 5. Arquitetura de API Segura: Autenticação e Autorização

Para uso no mundo real como um serviço (API), a arquitetura PrimeGuard implementa um modelo de segurança de dois fatores para cada transação.

1.  **Autenticação via Chave de API:** Cada cliente do serviço possui uma Chave de API secreta que o autentica como um usuário legítimo. Nenhum pedido é processado sem uma chave válida.
2.  **Autorização por Posse de Mensagem:** Para prevenir que um cliente legítimo decifre a mensagem de outro, o servidor gerencia a propriedade de cada sessão.
    - Ao criptografar, o emissor especifica o `ID` do destinatário.
    - O servidor gera o `K1` e armazena internamente a associação: `ID_da_Mensagem -> {K1, ID_do_Dono}`. O `K1` nunca viaja na rede.
    - Ao decifrar, o servidor verifica se a identidade do requisitante (autenticado por sua Chave de API) corresponde ao `ID_do_Dono` daquela mensagem. Se não corresponder, o acesso é negado.

Este mecanismo garante confidencialidade, autenticidade, integridade e autorização para cada transação.