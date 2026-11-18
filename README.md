# Arquivo de relatórios

Site estático protegido por senha. Tudo em `d/` está criptografado com AES-256-GCM e uma chave derivada da senha (PBKDF2-SHA256, 600 mil iterações). Títulos, resumos e arquivos só aparecem em claro no navegador de quem digita a senha.

## Estrutura

- `index.html`: tela de senha, lista com busca e filtros, e o leitor dos relatórios
- `d/meta.json`: parâmetros públicos da criptografia (sal e iterações)
- `d/c.bin`: catálogo criptografado (títulos, categorias, resumos)
- `d/*.bin`: arquivos criptografados, com nomes aleatórios
- `tools/site.py`: ferramenta para adicionar, editar, remover e trocar a senha

## Manutenção

```bash
pip install cryptography
export SITE_SENHA='...'

python3 tools/site.py list
python3 tools/site.py add caminho/relatorio.pdf --titulo "..." --cat pautas --data 2026-11-20 --periodo "..." --resumo "..."
python3 tools/site.py edit <id> titulo="Novo título" cat=momentos
python3 tools/site.py remove <id>
SITE_SENHA_NOVA='...' python3 tools/site.py senha
```

Depois de qualquer mudança, faça commit e push de `d/`. O GitHub Pages publica em cerca de um minuto.

Nunca envie para o repositório os arquivos originais nem um catálogo exportado em `.json`.
