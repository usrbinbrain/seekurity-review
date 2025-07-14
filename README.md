# 🔍 Seekurity Review

Sistema de triagem automatizada de vulnerabilidades SAST, que utiliza um modelo LLM local (DeepSeek-R1) para analisar contextualmente cada finding e determinar se trata-se de um risco real ou falso positivo, com justificativa técnica estruturada.

## 💡 Visão Geral

O script `seekurity-review.py` foi projetado para ambientes onde os resultados do SAST já foram gerados. Ele consome um arquivo `cx-sast-output.json`, percorre cada finding, analisa o trecho de código associado e utiliza um **LLM local** (via [Ollama](https://ollama.com)) para determinar:

- Se a vulnerabilidade é **real** ou um **falso positivo**
- **Por quê** (raciocínio técnico)
- **Como mitigar**, se aplicável

Ao final, um novo JSON enriquecido é salvo.  
Se a variável `GH_PAT` estiver definida, o output é **commitado de volta no repositório GitHub**.  
Caso contrário, o script opera **em modo local**, lendo o input do disco e **não realizando nenhum commit remoto**.

---

## 🧰 Características do Projeto

- ✅ Suporte a qualquer engine SAST (desde que o output siga o formato esperado)
- 🧠 Uso de LLM local (`deepseek-r1:14b`) via Ollama para revisão segura de código
- 🔄 Integração com GitHub via API (opcional, depende da variável `GH_PAT`)
- 🗃️ Organização cronológica dos outputs (`cx-scan/sast/YYYY/mmm/DD/`)
- 🔒 Raciocínio técnico estruturado para cada finding
- 💾 Persistência auditável por commit automático **(quando integrado ao GitHub)**

---

## 🧩 Repositório GitHub Esperado (modo com `GH_PAT`)

Se você estiver usando a integração com GitHub (ou seja, com `GH_PAT` definido), o repositório deve conter, **já commitado previamente**, um arquivo chamado:

```

cx-scan/sast/YYYY/mmm/DD/cx-sast-output.json

````

Esse arquivo representa o **output da ferramenta SAST da sua preferência**, que pode ser:

- Checkmarx
- Horusec
- Snyk
- Qualquer outra (desde que você converta para o formato suportado)

---

## 📥 Input Esperado (`cx-sast-output.json`)

Se `GH_PAT` **estiver definido**, o arquivo será buscado via GitHub API.  
Caso contrário, ele será carregado **localmente** a partir do mesmo diretório onde o script é executado.


Estrutura do JSON de entrada `cx-sast-output.json`:

```json
{
  "project-name": {
    "branch": "main",
    "scan_id": "123abc",
    "vulnerabilities": [
      {
        "severity": "High",
        "language": "JavaScript",
        "description": "Possible XSS via innerHTML",
        "vuln_files": [
          {
            "file_name": "app.js",
            "file_content": "<código vulnerável como string>",
            "file_sha": "sha123",
            "file_size": 1024
          }
        ]
      }
    ]
  }
}
```


## 📤 Output Gerado (`output-secure-review.json`)

O script adiciona os seguintes campos por finding:

```json
{
  "secure_review_think": "<raciocínio técnico interno do modelo>",
  "secure_review_result": "<relatório final estruturado>"
}
```

incluindo o pensamento* do deepseek-r1 em "secure_review_think" e o resultado da triagem em "secure_review_result". 

```json
{
  "project-name": {
    "branch": "main",
    "scan_id": "123abc",
    "vulnerabilities": [
      {
        "severity": "High",
        "language": "JavaScript",
        "description": "Possible XSS via innerHTML",
        "vuln_files": [
          {
            "file_name": "app.js",
            "file_content": "<código vulnerável como string>",
            "file_sha": "sha123",
            "file_size": 1024,
            "secure_review_think": "<raciocínio técnico interno do modelo>",
            "secure_review_result": "<relatório final estruturado>"
          }
        ]
      }
    ]
  }
}
```

Formato padrão do output gerado por cada analise SAST:

```
# Secure code review report

Vulnerability: Possible XSS via innerHTML  
File: app.js  
Language: JavaScript  
Status: Valid  
Analysis:  
The code uses `innerHTML` to inject user-controlled input without sanitization.  
This enables XSS attacks.

Recommendation:  
Use `textContent` or sanitize the input before DOM injection using DOMPurify.
```

> **Importante**: Caso esteja rodando o script localmente (sem `GH_PAT`), o arquivo de output **não será commitado** automaticamente no repositório remoto.

---

## ⚙️ Execução

### 🔑 Variáveis de Ambiente

| Variável  | Descrição                                                 | Exemplo            |
| --------- | --------------------------------------------------------- | ------------------ |
| `GH_PAT`  | Token pessoal do GitHub (com acesso de leitura e escrita) | `ghp_XXXX...`      |
| `GH_ORG`  | Nome da organização ou usuário GitHub                     | `usrbinbrain`      |
| `GH_REPO` | Nome do repositório onde estão os outputs SAST            | `seekurity-review` |
| `BRANCH`  | Nome da branch alvo                                       | `main`             |

> ⚠️ Se `GH_PAT` **não for definido**, o script funcionará em modo **offline**, lendo o input do arquivo `cx-sast-output.json` local e **não realizando commit** do output.

```bash
export GH_PAT=ghp_xxxxxxxxxxxxxxxxxx
export GH_ORG=usrbinbrain
export GH_REPO=seekurity-review
export BRANCH=main
```

### ▶️ Rodar o script

> Certifique-se de que o [Ollama](https://ollama.com) já está rodando localmente e que o modelo `deepseek-r1:14b` está disponível.

```bash
python3 seekurity-review.py
```

### 📍 Saídas esperadas

* `output-secure-review.json` no diretório local
* **Se `GH_PAT` estiver presente**:

  * Commit automático no repositório GitHub:

    ```
    Path: cx-scan/sast/YYYY/mmm/DD/cx-secure-review-output.json
    Message: Add: Secure review file cx-secure-review-output.json
    ```

---

## 🧠 Como o LLM Processa os Findings?

O modelo DeepSeek segue um fluxo explícito para revisar o código vulnerável:

1. **Entendimento do código**

   * O que ele faz?
   * Há proteção implementada?

2. **Validação da vulnerabilidade**

   * Existe risco real?
   * É explorável nesse contexto?

3. **Recomendações**

   * Corrigir ou justificar
   * Sugerir práticas seguras

Essas análises são armazenadas no output `output-secure-review.json` como evidência da triagem automatizada.

---

## 🧪 Testado com:

* ✅ Ollama + `deepseek-r1:14b`
* ✅ GitHub REST API v3
* ✅ Python 3.11+


