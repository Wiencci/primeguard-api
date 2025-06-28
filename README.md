# PrimeGuard API: Criptografia Híbrida

**Desenvolvido com base nos conceitos de Wiencci.**

---

## 1. Visão Geral

A PrimeGuard API é um serviço de criptografia de ponta a ponta que implementa um modelo de segurança híbrido. A troca de chaves de sessão é protegida por um paradigma experimental chamado **"Aritmética Primal"**, enquanto os dados em massa são criptografados com o robusto e auditado algoritmo **AES-256-GCM**.

Este modelo combina a originalidade de um universo matemático dinâmico para a troca de segredos com a velocidade e segurança comprovada da criptografia simétrica padrão da indústria.

---

## 2. Principais Características

* **🔑 Modelo Híbrido Seguro**: Utiliza a "Aritmética Primal" para a troca segura de uma chave de sessão AES, que por sua vez criptografa os dados.
* **🚀 Performance**: A criptografia dos dados é realizada com AES-256-GCM, garantindo altíssima velocidade para qualquer volume de dados.
* **👤 Auto-Registo de Clientes**: Permite que novos utilizadores se registem e obtenham uma chave de API através de um *endpoint* público, sem necessidade de intervenção manual.
* **🛡️ Gestão Segura de Chaves**: As chaves de API dos clientes são armazenadas no servidor de forma segura, utilizando *hashing* com `bcrypt`.
* **🔒 Sessões Efêmeras**: Cada troca de mensagem utiliza uma sessão com contexto criptográfico único, gerido pelo Redis, que é destruído após o uso.

---

## 3. Como Executar o Projeto

Siga estes passos para configurar e executar o ambiente de desenvolvimento.

### Pré-requisitos

* Python 3.x
* Redis (instalado e em execução)

### Guia de Instalação

1.  **Clone o repositório**
    ```bash
    git clone [https://github.com/seu-usuario/primeguard-api.git](https://github.com/seu-usuario/primeguard-api.git)
    cd primeguard-api
    ```

2.  **Instale as dependências**
    O ficheiro `requirements.txt` contém todos os pacotes necessários.
    ```bash
    pip install -r requirements.txt
    ```

3.  **Inicialize o Banco de Dados**
    Este comando cria o ficheiro `clientes.db` que armazenará os dados dos utilizadores.
    ```bash
    python gerenciar_chaves.py init
    ```

4.  **Inicie o Servidor da API**
    Certifique-se de que o seu serviço Redis está em execução. Em seguida, inicie a API com o Waitress (compatível com Windows, Linux e macOS).
    ```bash
    waitress-serve --host 0.0.0.0 --port=5000 api_server:app
    ```
    O servidor estará disponível em `http://127.0.0.1:5000`.

5.  **Execute o Cliente de Demonstração**
    Num **novo terminal**, execute o cliente de exemplo. Este script irá registar dois novos utilizadores (Alice e Bob) e simular uma troca de mensagem segura entre eles.
    ```bash
    python primeguard_client.py
    ```

---

## 4. Documentação da API

A API expõe três *endpoints* principais.

### `POST /register`

Regista um novo cliente no sistema.

* **Corpo do Pedido (`JSON`)**:
    ```json
    {
      "nome_cliente": "nome_desejado_para_o_cliente"
    }
    ```
* **Resposta de Sucesso (`JSON`)**:
    ```json
    {
      "mensagem": "Cliente 'nome_desejado_para_o_cliente' registado com sucesso!",
      "api_key": "pg_live_sua_nova_chave_secreta_aqui",
      "aviso": "Esta é a única vez que a sua chave de API será exibida. Guarde-a num local seguro."
    }
    ```

### `POST /encrypt`

Criptografa dados para um destinatário.

* **Cabeçalhos**:
    * `Authorization`: `Bearer <sua_chave_de_api>`
* **Corpo do Pedido (`JSON`)**:
    ```json
    {
      "destinatario_id": "nome_do_cliente_destinatario",
      "dados_base64": "dados_a_serem_criptografados_em_base64"
    }
    ```
* **Resposta de Sucesso (`JSON`)**:
    ```json
    {
      "pacote_seguro_hibrido": "longo_pacote_json_criptografado"
    }
    ```

### `POST /decrypt`

Decifra um pacote de dados recebido.

* **Cabeçalhos**:
    * `Authorization`: `Bearer <sua_chave_de_api_como_destinatario>`
* **Corpo do Pedido (`JSON`)**:
    ```json
    {
      "pacote_seguro_hibrido": "pacote_json_criptografado_recebido"
    }
    ```
* **Resposta de Sucesso (`JSON`)**:
    ```json
    {
      "dados_recuperados_base64": "dados_originais_decifrados_em_base64"
    }
    ```
