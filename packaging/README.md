# Instaladores nativos

Os instaladores contêm um executável independente da CLI `babylon`; a interface offline e o helper C++ de parsing estrutural estão embutidos no executável PyInstaller `--onefile`. Não é necessário instalar Python nem toolchain C++ no host de execução. Os pacotes são produzidos pelos workflows de CI e ficam disponíveis como artefatos da execução; não há publicação automática de GitHub Release.

| Sistema | Artefato | Instalação | Remoção |
| --- | --- | --- | --- |
| Debian 12+ / Ubuntu 22.04+ x86_64 | `.deb` | `sudo apt install ./babylon_*.deb` | `sudo apt remove babylon` |
| Arch Linux x86_64 | `.pkg.tar.zst` | `sudo pacman -U ./babylon-*.pkg.tar.zst` | `sudo pacman -R babylon` |
| Windows 10/11 x64 | `.msi` | Abra o MSI e confirme a instalação | Configurações → Aplicativos → Babylon → Desinstalar |
| macOS arm64 (CI; builds locais seguem a arquitetura do host) | `.pkg` | Abra o pacote e siga o instalador | `sudo rm /usr/local/bin/babylon` e `sudo rm -r /usr/local/share/doc/babylon` |

No Debian/Ubuntu, a versão atual requer `libc6` 2.35 ou superior. A receita Arch compila no próprio Arch e acompanha a versão do projeto; ao atualizar `pyproject.toml`, atualize também `pkgver` em `packaging/arch/PKGBUILD`.

O helper C++ é compilado por CMake em cada runner. No Linux GNU, ele liga estaticamente `libstdc++`/`libgcc`; no Windows, usa o runtime MSVC estático; no macOS, usa `libc++` do sistema. Assim, os artefatos não requerem uma biblioteca C++ adicional de runtime.

O MSI é x64 e o workflow valida a instalação em Windows Server 2022; os runners hospedados não são Windows 10/11 desktop, portanto a compatibilidade com essas versões é definida pelo instalador, mas não testada diretamente por esse runner. O `.pkg` do CI é arm64, compilado e testado no runner Apple Silicon macOS 15; builds locais seguem a arquitetura do Mac, incluindo Intel.

Depois de instalar, use `babylon --help` e `babylon ui`; a UI informa a URL loopback para abrir no navegador. No macOS, o pacote ainda não é assinado nem notarizado: o Gatekeeper pode bloquear sua abertura. Se isso ocorrer, permita explicitamente o pacote em Privacidade e Segurança após confirmar que ele veio do artefato de CI esperado. No Windows, o MSI também não é assinado; o SmartScreen pode exibir um aviso de publicador desconhecido. Não há certificados nem credenciais de assinatura configurados.

## Construção local

- Linux Debian/Ubuntu: instale Python 3.11+, CMake 3.20+, um compilador C++17, PyInstaller e `dpkg-deb`; execute `python3 -m pip install -r packaging/requirements-build.txt` e `bash packaging/linux/build_deb.sh`.
- Arch Linux: com `base-devel`, CMake 3.20+, Python e `python-pip` instalados, execute `cd packaging/arch && makepkg`; a receita cria um ambiente isolado e instala a versão de build fixada.
- macOS: instale Python 3.11+, CMake 3.20+ e as ferramentas de linha de comando do Xcode; execute `python3 -m pip install -r packaging/requirements-build.txt` e `bash packaging/macos/build_pkg.sh`.
- Windows: instale Python 3.11+, CMake 3.20+, Visual Studio C++ Build Tools e WiX Toolset 5; execute os passos `setup-python`, `pip install -r packaging/requirements-build.txt`, `python packaging/build_binary.py` e `wix build` do workflow `.github/workflows/installers.yml`.

Para executar a suíte Python em um checkout, construa e teste antes o helper local com `python packaging/build_native.py`. O smoke test dos instaladores analisa fixtures sintéticas válidas de PE, ELF e Mach-O; nenhum arquivo é executado.

O PyInstaller e as ferramentas nativas são ferramentas de build; o aplicativo continua usando somente a biblioteca padrão do Python.
