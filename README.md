# Security Checkup

MVP do "Security Checkup" — diagnóstico de segurança simples e sem jargão técnico, pensado para qualquer pessoa usar (não só quem é de TI).

Contexto completo do produto, casos de uso e roadmap: veja [ANALISE_CIBERSEGURANCA_PME.md](ANALISE_CIBERSEGURANCA_PME.md).

## O que ele verifica hoje (v1)

- **Domínio:** SPF / DKIM / DMARC (proteção contra falsificação de e-mail) e validade do certificado SSL do site
- **IP:** portas sensíveis expostas direto na internet (RDP, SSH, bancos de dados, etc.), com proteção contra varredura de endereços internos/privados
- **Dados vazados:** e-mails do domínio presentes em vazamentos conhecidos (requer `HIBP_API_KEY`)
- **Chaves vazadas:** chaves/senhas expostas em repositórios públicos do GitHub (requer `GITHUB_TOKEN`)
- **CNPJ (opcional):** situação cadastral da empresa na Receita Federal — dado público, útil também para checar fornecedores (via BrasilAPI, sem chave necessária)
- **Seu telefone (opcional):** checagem de vazamento de dados — hoje é um *placeholder* (veja nota abaixo)
- **Número suspeito que te ligou (opcional):** tipo de linha (fixa/móvel/VOIP), como sinal de possível golpe por telefone (requer `TWILIO_ACCOUNT_SID` + `TWILIO_AUTH_TOKEN`)

As checagens acima que citam uma chave exigem credenciais de terceiros. Sem elas configuradas, aparecem no relatório como "não configurado" em vez de quebrar o resto do diagnóstico.

> **Nota sobre dados pessoais (LGPD):** propositalmente **não** existe (e não vamos adicionar) uma busca reversa de CPF ou telefone que devolva identidade/dados de uma pessoa — isso é o padrão clássico de ferramenta de "people search"/doxxing, incompatível com o objetivo do produto (autoverificação de segurança da própria empresa). A checagem de "telefone em vazamentos" é só um placeholder porque, diferente do e-mail (HIBP) e do CNPJ (Receita Federal), não existe hoje um provedor de autoatendimento confiável para isso — o próprio HIBP restringiu essa busca por risco de abuso.

## Como rodar localmente

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # opcional — preencha as chaves de API que tiver
uvicorn app.main:app --reload
```

Depois abra http://localhost:8000

## Estrutura

```
app/
  main.py       # rotas FastAPI (formulário + relatório)
  report.py     # roda todas as checagens e calcula a nota geral
  checks/       # cada arquivo é uma categoria de checagem (domínio, IP, vazamentos...)
  templates/    # HTML do formulário e do relatório
  static/       # CSS
```

## Roadmap (próximos passos)

- Checagem de configuração de nuvem (Microsoft 365 / Google Workspace) via OAuth
- Reputação de IP (AbuseIPDB / Shodan)
- Detecção de domínios "sósia" (typosquatting)
- Exportar relatório em PDF
- Histórico de verificações por conta
