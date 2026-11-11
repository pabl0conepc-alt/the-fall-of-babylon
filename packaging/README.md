# Instaladores nativos

Os instaladores contêm um executável independente da CLI `babylon`; a interface offline está embutida no executável e é servida por `babylon ui`. Não é necessário instalar Python nem dependências de runtime. Os pacotes são produzidos pelos workflows de CI e ficam disponíveis como artefatos da execução; não há publicação automática de GitHub Release.

| Sistema | Artefato | Instalação | Remoção |
| --- | --- | --- | --- |
| Debian 12+ / Ubuntu 22.04+ x86_64 | `.deb` | `sudo apt install ./babylon_*.deb` | `sudo apt remove babylon` |
| Arch Linux x86_64 | `.pkg.tar.zst` | `sudo pacman -U ./babylon-*.pkg.tar.zst` | `sudo pacman -R babylon` |
| Windows 10/11 x64 | `.msi` | Abra o MSI e confirme a instalação | Configurações → Aplicativos → Babylon → Desinstalar |
| macOS x86_64 / Apple Silicon | `.pkg` | Abra o pacote e siga o instalador | `sudo rm /usr/local/bin/babylon` e `sudo rm -r /usr/local/share/doc/babylon` |

No Debian/Ubuntu, a versão atual requer `libc6` 2.35 ou superior. A receita Arch compila no próprio Arch e acompanha a versão do projeto; ao atualizar `pyproject.toml`, atualize também `pkgver` em `packaging/arch/PKGBUILD`.

O MSI é x64 e o workflow valida a instalação em Windows Server 2022; os runners hospedados não são Windows 10/11 desktop, portanto a compatibilidade com essas versões é definida pelo instalador, mas não testada diretamente por esse runner. O `.pkg` é compilado e testado na arquitetura do runner macOS 15.

Depois de instalar, use `babylon --help` e `babylon ui`; a UI informa a URL loopback para abrir no navegador. No macOS, o pacote ainda não é assinado nem notarizado: o Gatekeeper pode bloquear sua abertura. Se isso ocorrer, permita explicitamente o pacote em Privacidade e Segurança após confirmar que ele veio do artefato de CI esperado. No Windows, o MSI também não é assinado; o SmartScreen pode exibir um aviso de publicador desconhecido. Não há certificados nem credenciais de assinatura configurados.

## Construção local

- Linux Debian/Ubuntu: instale Python 3.11+, PyInstaller e `dpkg-deb`; execute `python3 -m pip install pyinstaller` e `bash packaging/linux/build_deb.sh`.
- Arch Linux: com `base-devel`, Python e `python-pyinstaller` instalados, execute `cd packaging/arch && makepkg`.
- macOS: instale Python 3.11+, PyInstaller e as ferramentas de linha de comando do Xcode; execute `python3 -m pip install pyinstaller` e `bash packaging/macos/build_pkg.sh`.
- Windows: instale Python 3.11+, PyInstaller e WiX Toolset 5; execute os passos `setup-python`, `pip install pyinstaller`, `python packaging/build_binary.py` e `wix build` do workflow `.github/workflows/installers.yml`.

O PyInstaller e as ferramentas nativas são ferramentas de build; o aplicativo continua usando somente a biblioteca padrão do Python.
