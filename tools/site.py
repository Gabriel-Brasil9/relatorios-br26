#!/usr/bin/env python3
"""Ferramenta de manutenção do arquivo de relatórios.

Tudo que vai para o repositório é criptografado (AES-256-GCM, chave derivada
da senha com PBKDF2-SHA256). Os títulos, resumos e arquivos só existem em
claro no navegador de quem digita a senha.

Senha: variável de ambiente SITE_SENHA ou pergunta no terminal.

Comandos
  build --src PASTA --catalogo catalogo.json   recria tudo a partir dos originais
  list                                         lista os relatórios publicados
  add ARQUIVO --titulo T --cat C --data AAAA-MM-DD --periodo P --resumo R
  edit ID campo=valor [campo=valor ...]        campos: titulo cat data periodo resumo
  remove ID
  export-catalogo SAIDA.json                   tira o catálogo para editar à mão
  import-catalogo ENTRADA.json                 devolve o catálogo editado
  senha                                        troca a senha (pede a nova em SITE_SENHA_NOVA)
  textos-en textos_en.json                     aplica títulos, resumos e categorias em inglês
  traducao ID ARQUIVO_EN                       anexa a versão em inglês de um relatório
  traducoes PASTA                              anexa em lote: cada arquivo da pasta com o mesmo nome do original
  capas capas.json                             aplica as capas (SVG) por ID: {"id": "<svg interno>"}
  edit ID destaque=1                           põe o relatório entre os destaques da página inicial (destaque=0 tira)

Requer: pip install cryptography. Para PPTX, LibreOffice (soffice) no PATH.
"""
import argparse, base64, getpass, gzip, json, mimetypes, os, secrets, shutil, subprocess, sys, tempfile

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "d")
META = os.path.join(DATA, "meta.json")
CAT = os.path.join(DATA, "c.bin")
ITER = 600_000
MIMES = {"html": "text/html", "pdf": "application/pdf",
         "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
         "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"}


# ---------- criptografia ----------
def derive(password, salt, iterations=ITER):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
    return kdf.derive(password.encode("utf-8"))


def seal(key, raw):
    iv = secrets.token_bytes(12)
    return iv + AESGCM(key).encrypt(iv, gzip.compress(raw, 9, mtime=0), None)


def unseal(key, blob):
    return gzip.decompress(AESGCM(key).decrypt(blob[:12], blob[12:], None))


def get_password(var="SITE_SENHA", prompt="Senha do site: "):
    pw = os.environ.get(var) or getpass.getpass(prompt)
    if not pw:
        sys.exit("Senha vazia.")
    return pw


def load_key(password):
    meta = json.load(open(META))
    key = derive(password, base64.b64decode(meta["salt"]), meta["iter"])
    try:
        cat = json.loads(unseal(key, open(CAT, "rb").read()))
    except Exception:
        sys.exit("Senha incorreta.")
    return key, cat


def save_catalog(key, cat):
    cat["relatorios"].sort(key=lambda r: (r["data"], r["titulo"]), reverse=True)
    open(CAT, "wb").write(seal(key, json.dumps(cat, ensure_ascii=False).encode("utf-8")))


def write_blob(key, raw):
    fid = secrets.token_hex(10)
    open(os.path.join(DATA, fid + ".bin"), "wb").write(seal(key, raw))
    return fid


# ---------- arquivos ----------
def pdf_pages(path):
    try:
        out = subprocess.run(["pdfinfo", path], capture_output=True, text=True).stdout
        for line in out.splitlines():
            if line.startswith("Pages:"):
                return int(line.split()[1])
    except Exception:
        pass
    return None


def pptx_to_pdf(path, pdf_dir=None):
    name = os.path.splitext(os.path.basename(path))[0] + ".pdf"
    if pdf_dir and os.path.exists(os.path.join(pdf_dir, name)):
        return os.path.join(pdf_dir, name)
    out = tempfile.mkdtemp()
    subprocess.run(["soffice", "--headless", "--convert-to", "pdf", "--outdir", out, path],
                   capture_output=True, timeout=300)
    pdf = os.path.join(out, name)
    if not os.path.exists(pdf):
        sys.exit(f"Não consegui converter {path} para PDF (LibreOffice instalado?).")
    return pdf


def make_entry(key, path, meta, pdf_dir=None):
    ext = path.rsplit(".", 1)[-1].lower()
    raw = open(path, "rb").read()
    entry = {"id": secrets.token_hex(4), "titulo": meta["titulo"], "cat": meta["cat"],
             "data": meta["data"], "periodo": meta.get("periodo", ""), "resumo": meta.get("resumo", ""),
             "fmt": ext, "nome": os.path.basename(path)}
    if ext == "html":
        entry["ver"] = {"f": write_blob(key, raw), "mime": MIMES["html"]}
        entry["baixar"] = entry["ver"]
    elif ext == "pdf":
        entry["pag"] = pdf_pages(path)
        entry["ver"] = {"f": write_blob(key, raw), "mime": MIMES["pdf"]}
        entry["baixar"] = entry["ver"]
    elif ext == "pptx":
        pdf = pptx_to_pdf(path, pdf_dir)
        entry["pag"] = pdf_pages(pdf)
        entry["ver"] = {"f": write_blob(key, open(pdf, "rb").read()), "mime": MIMES["pdf"]}
        entry["baixar"] = {"f": write_blob(key, raw), "mime": MIMES["pptx"]}
    else:
        mime = MIMES.get(ext) or mimetypes.guess_type(path)[0] or "application/octet-stream"
        entry["baixar"] = {"f": write_blob(key, raw), "mime": mime}
    entry["tam"] = len(raw)
    return entry


PARTS = ("ver", "baixar", "ver_en", "baixar_en")


def blobs_of(entry):
    return {v["f"] for k in PARTS if (v := entry.get(k))}


def drop_blobs(files):
    for f in files:
        p = os.path.join(DATA, f + ".bin")
        if os.path.exists(p):
            os.remove(p)


def attach_en(key, entry, path):
    """Criptografa a versão em inglês e liga ao relatório (substitui a anterior)."""
    old = {v["f"] for k in ("ver_en", "baixar_en") if (v := entry.get(k))} - {v["f"] for k in ("ver", "baixar") if (v := entry.get(k))}
    ext = path.rsplit(".", 1)[-1].lower()
    raw = open(path, "rb").read()
    if ext == "pptx":
        pdf = pptx_to_pdf(path)
        entry["ver_en"] = {"f": write_blob(key, open(pdf, "rb").read()), "mime": MIMES["pdf"]}
        entry["baixar_en"] = {"f": write_blob(key, raw), "mime": MIMES["pptx"], "nome": os.path.basename(path)}
    elif ext in ("html", "pdf"):
        part = {"f": write_blob(key, raw), "mime": MIMES[ext], "nome": os.path.basename(path)}
        entry["ver_en"] = part
        entry["baixar_en"] = part
    else:
        sys.exit(f"Formato não suportado para tradução: {path}")
    drop_blobs(old)


def check_cat(cat, cid):
    ids = [c["id"] for c in cat["categorias"]]
    if cid not in ids:
        sys.exit(f"Categoria '{cid}' não existe. Opções: {', '.join(ids)}")


# ---------- comandos ----------
def cmd_build(a):
    src = json.load(open(a.catalogo, encoding="utf-8"))
    pw = get_password()
    if os.path.isdir(DATA):
        shutil.rmtree(DATA)
    os.makedirs(DATA)
    salt = secrets.token_bytes(16)
    json.dump({"v": 1, "kdf": "PBKDF2-SHA256", "iter": ITER, "salt": base64.b64encode(salt).decode()},
              open(META, "w"))
    key = derive(pw, salt)
    cat = {"titulo": src.get("titulo", "Relatórios"), "categorias": src["categorias"], "relatorios": []}
    for r in src["relatorios"]:
        check_cat(cat, r["cat"])
        path = os.path.join(a.src, r["arquivo"])
        cat["relatorios"].append(make_entry(key, path, r, a.pdf_dir))
        print("ok ", r["titulo"])
    save_catalog(key, cat)
    print(f"\n{len(cat['relatorios'])} relatórios criptografados em d/.")


def cmd_list(a):
    _, cat = load_key(get_password())
    names = {c["id"]: c["nome"] for c in cat["categorias"]}
    for r in cat["relatorios"]:
        print(f"{r['id']}  {r['data']}  {names.get(r['cat'], r['cat'])[:22]:<22}  {r['titulo']}")


def cmd_add(a):
    key, cat = load_key(get_password())
    check_cat(cat, a.cat)
    meta = {"titulo": a.titulo, "cat": a.cat, "data": a.data, "periodo": a.periodo or "", "resumo": a.resumo or ""}
    e = make_entry(key, a.arquivo, meta)
    cat["relatorios"].append(e)
    save_catalog(key, cat)
    print(f"Adicionado: {e['id']}  {e['titulo']}")


def cmd_edit(a):
    key, cat = load_key(get_password())
    r = next((x for x in cat["relatorios"] if x["id"] == a.id), None) or sys.exit("ID não encontrado.")
    for pair in a.campos:
        k, _, v = pair.partition("=")
        if k in ("titulo_en", "periodo_en", "resumo_en"):
            r.setdefault("en", {})[k[:-3]] = v
            continue
        if k == "destaque":
            if v in ("1", "sim", "true"): r["destaque"] = True
            else: r.pop("destaque", None)
            continue
        if k not in ("titulo", "cat", "data", "periodo", "resumo"):
            sys.exit(f"Campo '{k}' não pode ser editado.")
        if k == "cat":
            check_cat(cat, v)
        r[k] = v
    save_catalog(key, cat)
    print("Atualizado:", r["titulo"])


def cmd_remove(a):
    key, cat = load_key(get_password())
    r = next((x for x in cat["relatorios"] if x["id"] == a.id), None) or sys.exit("ID não encontrado.")
    cat["relatorios"].remove(r)
    drop_blobs(blobs_of(r))
    save_catalog(key, cat)
    print("Removido:", r["titulo"])


def cmd_export(a):
    _, cat = load_key(get_password())
    json.dump(cat, open(a.saida, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print("Catálogo salvo em", a.saida, "(não envie este arquivo para o repositório)")


def cmd_import(a):
    key, old = load_key(get_password())
    new = json.load(open(a.entrada, encoding="utf-8"))
    known = {f for r in old["relatorios"] for f in blobs_of(r)}
    for r in new["relatorios"]:
        check_cat(new, r["cat"])
        if not blobs_of(r) <= known:
            sys.exit(f"'{r['titulo']}' aponta para um arquivo que não existe.")
    save_catalog(key, new)
    print("Catálogo importado.")


def cmd_textos_en(a):
    key, cat = load_key(get_password())
    en = json.load(open(a.arquivo, encoding="utf-8"))
    if en.get("titulo"):
        cat["titulo_en"] = en["titulo"]
    for c in cat["categorias"]:
        if c["id"] in en.get("categorias", {}):
            c["en"] = en["categorias"][c["id"]]
    faltam = []
    for r in cat["relatorios"]:
        t = en.get("relatorios", {}).get(r["nome"])
        if t:
            r["en"] = t
        else:
            faltam.append(r["nome"])
    save_catalog(key, cat)
    print(f"Textos em inglês aplicados. Sem tradução: {len(faltam)}")
    for n in faltam:
        print("  -", n)


def cmd_capas(a):
    key, cat = load_key(get_password())
    capas = json.load(open(a.arquivo, encoding="utf-8"))
    n = 0
    for r in cat["relatorios"]:
        if r["id"] in capas:
            r["capa"] = capas[r["id"]]; n += 1
    save_catalog(key, cat)
    print(f"Capas aplicadas: {n}")


def cmd_traducao(a):
    key, cat = load_key(get_password())
    r = next((x for x in cat["relatorios"] if x["id"] == a.id), None) or sys.exit("ID não encontrado.")
    attach_en(key, r, a.arquivo)
    save_catalog(key, cat)
    print("Versão em inglês anexada:", r["titulo"])


def cmd_traducoes(a):
    key, cat = load_key(get_password())
    by_name = {r["nome"]: r for r in cat["relatorios"]}
    n = 0
    for f in sorted(os.listdir(a.pasta)):
        r = by_name.get(f)
        if not r:
            print("  ignorado (sem original com esse nome):", f)
            continue
        attach_en(key, r, os.path.join(a.pasta, f))
        n += 1
        print("  ok", r["titulo"])
    save_catalog(key, cat)
    total = sum(1 for r in cat["relatorios"] if r.get("ver_en"))
    print(f"{n} traduções anexadas. Com versão em inglês: {total} de {len(cat['relatorios'])}.")


def cmd_senha(a):
    key, cat = load_key(get_password())
    novo = get_password("SITE_SENHA_NOVA", "Nova senha: ")
    salt = secrets.token_bytes(16)
    nkey = derive(novo, salt)
    for name in os.listdir(DATA):
        if name.endswith(".bin") and name != "c.bin":
            p = os.path.join(DATA, name)
            open(p, "wb").write(seal(nkey, unseal(key, open(p, "rb").read())))
    json.dump({"v": 1, "kdf": "PBKDF2-SHA256", "iter": ITER, "salt": base64.b64encode(salt).decode()},
              open(META, "w"))
    save_catalog(nkey, cat)
    print("Senha trocada. Quem estava conectado vai precisar entrar de novo.")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    s = p.add_subparsers(dest="cmd", required=True)
    b = s.add_parser("build"); b.add_argument("--src", required=True); b.add_argument("--catalogo", required=True)
    b.add_argument("--pdf-dir"); b.set_defaults(fn=cmd_build)
    s.add_parser("list").set_defaults(fn=cmd_list)
    ad = s.add_parser("add"); ad.add_argument("arquivo"); ad.add_argument("--titulo", required=True)
    ad.add_argument("--cat", required=True); ad.add_argument("--data", required=True)
    ad.add_argument("--periodo"); ad.add_argument("--resumo"); ad.set_defaults(fn=cmd_add)
    e = s.add_parser("edit"); e.add_argument("id"); e.add_argument("campos", nargs="+"); e.set_defaults(fn=cmd_edit)
    r = s.add_parser("remove"); r.add_argument("id"); r.set_defaults(fn=cmd_remove)
    ex = s.add_parser("export-catalogo"); ex.add_argument("saida"); ex.set_defaults(fn=cmd_export)
    im = s.add_parser("import-catalogo"); im.add_argument("entrada"); im.set_defaults(fn=cmd_import)
    s.add_parser("senha").set_defaults(fn=cmd_senha)
    te = s.add_parser("textos-en"); te.add_argument("arquivo"); te.set_defaults(fn=cmd_textos_en)
    tr = s.add_parser("traducao"); tr.add_argument("id"); tr.add_argument("arquivo"); tr.set_defaults(fn=cmd_traducao)
    cp = s.add_parser("capas"); cp.add_argument("arquivo"); cp.set_defaults(fn=cmd_capas)
    ts = s.add_parser("traducoes"); ts.add_argument("pasta"); ts.set_defaults(fn=cmd_traducoes)
    a = p.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
