# Cert Inject — módulo Magisk para CAs do usuário no Android 14/15

Substitui o **Cert Fix** (`cert-fixer`) com três correções que ele não faz:

1. **Normaliza para PEM.** O Cert Fix copia o arquivo do user store *verbatim*; se o usuário instalou um `.cer` DER, o sistema recebe DER.
2. **Escreve os dois nomes de hash.** Cada stack TLS do Android indexa o store por um hash diferente; com só um nome, metade dos clientes não acha a CA.
3. **Cobre os paths do Android 14/15 de verdade**, inclusive o `/apex`, com bind-mount em init e zygote.

## Por que dois hashes

O Android guarda CAs de sistema como `<hash>.0`. O hash é calculado sobre o *subject* do certificado, mas cada biblioteca usa um:

| Cliente | Hash | Exemplo (CA do Burp) |
|---|---|---|
| Conscrypt / Java (`TrustedCertificateStore`, OkHttp, SDKs) | `subject_hash_old` — **MD5** do subject DER | `9a5ba575.0` |
| BoringSSL / libflutter (Dart, código nativo) | `subject_hash` — **SHA-1** do subject canônico | `7bf17d07.0` |

Um certificado presente só como `9a5ba575.0` é invisível para o Dart: o handshake TLS aborta em silêncio, sem erro no logcat e sem request no proxy. Foi exatamente esse o bug que travou a interceptação do app no Moto G34.

> Detalhe importante: o `subject_hash` (SHA-1) **não** é `SHA1(RawSubject)`. O OpenSSL usa a codificação canônica do nome: strings em UTF-8, espaços colapsados, ASCII em minúsculas, SETs ordenados e o SEQUENCE externo removido. Para a CA do Burp, `SHA1(RawSubject)` dá `ab413755` — errado. O helper implementa a canonicalização correta e foi validado contra 122 CAs nativos do Android (0 divergências).

## O que o módulo faz

### Na instalação (`customize.sh`)
Lê `/data/misc/user/*/cacerts-added/`, normaliza cada certificado e pré-popula `system/etc/security/cacerts/` dentro do módulo. Assim o **primeiro boot** já tem as CAs (o Magisk faz magic-mount desse diretório).

### No boot (`post-fs-data.sh`, antes do zygote)
1. Reconstrói o stage a partir do user store.
2. Sincroniza o `system/` do módulo (fonte do magic mount).
3. Injeta no `/system/etc/security/cacerts` vivo (remonta o tmpfs do Magisk como rw, faz `umount` do bind ro de cada arquivo, escreve, volta para ro).
4. Clona `/apex/com.android.conscrypt/cacerts` para um tmpfs privado, adiciona as CAs e faz `bind --mount` no namespace atual, no pid 1 e nos zygotes.
5. Grava um manifesto dos hashes injetados.

> **Por que existe o `.cert-inject` no `system/` do módulo:** o Magisk só cria o tmpfs que torna o
> `/system/etc/security/cacerts` gravável quando o diretório do módulo tem ao menos uma entrada. Num
> device limpo o user store está vazio, então sem o marcador o store ficaria read-only até o próximo
> boot e CAs instaladas depois só chegariam ao `/apex`. O marcador é inerte: os consumidores indexam
> aquele diretório por `<8 hex>.0`, então um dotfile nunca é parseado como certificado. Ele também
> sobrevive ao prune (que só apaga `*.0`).

### Em runtime (`service.sh`, depois do boot)
Reaplica a injeção e fica observando o user store a cada **20 s**. Instalar ou remover uma CA em Configurações → Segurança → Criptografia e credenciais é refletido nos stores sem reboot.

> **Por que o `umount` é necessário:** o Magisk monta cada arquivo do módulo como um bind mount
> **read-only** dentro do tmpfs. `cp`/`rm` no caminho vivo falham com `EROFS` mesmo com o tmpfs em
> `rw`; o módulo desmonta o arquivo individual (`unmount_file` em `lib.sh`) e então grava o novo
> conteúdo. Sem isso, o `/system` só seria atualizado no próximo boot.

## Paths cobertos

| Path | Como |
|---|---|
| `/apex/com.android.conscrypt/cacerts` | clone em tmpfs + bind-mount (init/zygote) |
| `/system/etc/security/cacerts` | magic mount do Magisk + remount rw em runtime |
| `/data/misc/user/<id>/cacerts-added` | **fonte** — nunca é modificado |

`/product`, `/system_ext`, `/vendor` e `/odm` não têm `security/cacerts` neste device (Android 15); o módulo só toca em diretórios que existem.

## Instalação

```sh
# no host
cd magisk-cert-inject
./build.sh
adb push dist/cert-inject-v1.2.zip /data/local/tmp/

# no device (root)
adb shell su -c 'magisk --install-module /data/local/tmp/cert-inject-v1.2.zip'
```

Ou pelo app do Magisk: **Módulos → Instalar do armazenamento**.

> **Desative o `cert-fixer` antes de reiniciar.** Dois módulos fazendo bind-mount no mesmo `/apex/.../cacerts` brigam:
> ```sh
> adb shell su -c 'touch /data/adb/modules/cert-fixer/disable'
> ```
> Para reverter, apague esse arquivo e reinicie.

Reinicie. Depois do boot:

```sh
adb shell su -c 'ls /apex/com.android.conscrypt/cacerts | grep -E "7bf17d07|9a5ba575"'
adb shell su -c 'ls /system/etc/security/cacerts | grep -E "7bf17d07|9a5ba575"'
adb shell su -c 'cat /data/adb/cert-inject/inject.log'
```

## Logs

Tudo em `/data/adb/cert-inject/inject.log` (exemplo real deste device):

```
[1970-09-27 07:09:53] === post-fs-data: start (arch aarch64) ===
[1970-09-27 07:09:53] staged 2 trust-store name(s) from 2 input file(s)
[1970-09-27 07:09:53] system store: not writable here (applies on next boot)
[1970-09-27 07:09:53] apex store: cloned 120 native cert(s) into tmpfs
[1970-09-27 07:09:53] apex store: 122 cert(s) visible
[1970-09-27 07:09:53] === post-fs-data: done ===
[2026-10-24 19:23:18] === service: initial refresh ===
[2026-10-24 19:23:18] staged 2 trust-store name(s) from 2 input file(s)
[2026-10-24 19:23:18] system store: synced live
[2026-10-24 19:23:18] apex store: 122 cert(s) visible
[2026-10-24 19:23:18] service: watching user stores (poll 20s)
```

## Validação no device (G34, Android 15)

- Boot: apex **122** (120 nativos + 2), `/system` **147** (145 nativos + 2), ambos com
  `7bf17d07.0` e `9a5ba575.0`, `root:root 644`, contexto
  `u:object_r:system_security_cacerts_file:s0`.
- App alvo com o plugin Burp **intocado**:
  `requested https://api.example.com/graphql/query : status 401 (hello=native)`.
- Runtime: cert sintético adicionado ao user store apareceu nos dois stores em ~20 s; removido,
  foi podado dos dois em ~20 s, sem reboot.

## Dry run (sem tocar nos stores reais)

O `lib.sh` aceita overrides de path, então dá para validar clone, bind, prune e manifesto num diretório de teste:

```sh
adb shell su -c '
  rm -rf /data/local/tmp/ci-test && mkdir -p /data/local/tmp/ci-test/bin
  cp /data/adb/modules/cert-inject/bin/certinject-arm64 /data/local/tmp/ci-test/bin/
  cp /data/adb/modules/cert-inject/lib.sh /data/local/tmp/ci-test/
  cp -a /apex/com.android.conscrypt/cacerts /data/local/tmp/fakeapex
  mkdir -p /data/local/tmp/fakesys /data/local/tmp/fakeuser
  cp /data/local/tmp/ca-burp.pem /data/local/tmp/fakeuser/
  MODDIR=/data/local/tmp/ci-test APEX_DIR=/data/local/tmp/fakeapex \
  SYS_DIR=/data/local/tmp/fakesys USER_CERT_DIRS=/data/local/tmp/fakeuser \
  sh -c ". /data/local/tmp/ci-test/lib.sh; run_injection"
  ls /data/local/tmp/fakeapex | grep -E "7bf17d07|9a5ba575"
'
```

## Build

```sh
./build.sh          # ou: make build
```

Compila o helper Go estático para arm64, armv7 e x86_64 (`CGO_ENABLED=0`), roda o self-test e gera `dist/cert-inject-v1.2.zip`.

O self-test gera uma CA sintética (PEM e DER) em tempo de execução e compara o resultado do helper com o `openssl x509 -subject_hash -subject_hash_old` do host — o subject sintético mistura maiúsculas e espaço duplo, então exercita a canonicalização do OpenSSL em vez de só copiar o DER. Se `../burp.pem` existir no checkout local, ele também é verificado como referência; no CI essa parte é pulada, então o build não depende de material do pentest.

O device **não precisa de `openssl`**: o helper faz parse de DER/PEM e calcula os dois hashes.

## CI e Release

O repositório é **só o módulo** — nada de PFX, reports, plugin do Burp ou scripts do Frida. O `.gitignore` já bloqueia `dist/`, `bin/`, `*.zip`, `*.sha256` e qualquer `*.pem`/`*.pfx`/`*.key`.

### Primeiro push

```sh
cd magisk-cert-inject
git init -b main
git add .
git commit -m "cert-inject v1.2"
git remote add origin git@github.com:<org>/magisk-cert-inject.git
git push -u origin main
```

### Publicar um release (zip na barra lateral do GitHub)

1. Suba a versão no `module.prop` (`version=v1.2`, `versionCode=3`) e commite.
2. Crie e empurre a tag — o nome **precisa** ser igual ao `version=`:

```sh
make release TAG=v1.2
# equivale a: git tag -a v1.2 -m "Cert Inject v1.2" && git push origin v1.2
```

O `make release` aborta se a tag não bater com o `module.prop`, se houver mudanças não commitadas ou se a tag já existir.

O workflow [`release.yml`](.github/workflows/release.yml) então:

1. compila os três binários e roda o self-test;
2. valida que a tag == `version=` e que o zip contém `module.prop` e `META-INF/com/google/android/update-binary`;
3. gera `cert-inject-v1.2.zip` + `.sha256` e publica em **Releases**, com o `SHA-256` no corpo da release.

Também dá para disparar manualmente: **Actions → Release → Run workflow**, informando a tag.

### CI

[`ci.yml`](.github/workflows/ci.yml) roda em todo push/PR que mexe em `src/`, `*.sh`, `module.prop`, `META-INF/` ou nos próprios workflows: checa a sintaxe dos scripts (`sh -n`), builda, roda o self-test e sobe o zip como artifact. Não publica nada.

### Estrutura

```
build.sh                 build + self-test + empacotamento
lib.sh                   injeção (system + apex), prune, overrides de path
src/main.go              helper Go (hashes + normalização PEM)
post-fs-data.sh          injeção no boot, antes do zygote
service.sh               reaplica + watcher de 20 s
customize.sh             pré-popula o store na instalação
uninstall.sh             desfaz binds e limpa /data/adb/cert-inject
module.prop              id/version/versionCode (fonte da verdade da tag)
Makefile                 build / test / clean / release
.github/workflows/       ci.yml, release.yml
```

## Desinstalação

Pelo app do Magisk ou:

```sh
adb shell su -c 'magisk --remove-modules cert-inject'   # ou apague /data/adb/modules/cert-inject e reinicie
```

O `uninstall.sh` desfaz os bind-mounts do apex e remove `/data/adb/cert-inject`. O `/system` volta ao normal no reboot.

## Limitações

- CAs com subject em `T61String` são convertidas como Latin-1 (aproximação); `BMPString` e `UniversalString` são tratados corretamente.
- O `/apex` é recriado a cada boot (tmpfs), então o bind-mount é refeito no `post-fs-data`.
- Se outro módulo também fizer bind-mount no `/apex/.../cacerts`, o último a rodar vence. Não use junto com `cert-fixer`.
