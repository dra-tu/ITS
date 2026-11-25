# Benutzte Libs (müssen Installiert sein)
- [liboath](https://oath-toolkit.codeberg.page/liboath-api/liboath-oath.h.html) -> totp
- [sqlite](https://sqlite.org/) -> DB speicher
- [openssl](https://docs.openssl.org/master/) -> hash function && rng && AES-256-GCM 

# Neu DB erstellen (muss "login.db" heisen)
```bash
sqlite3 login.db <path to createTable.sql>
```

# Building
gin.db muss in der Working directory s
Es ist ein CMake project.

build optionen:
- import in eine IDE die CMake unterstützt
- manuel mit cmake cmd

## Manuel
```bash
mkdir build
cd build
cmake ..
# build cmd z.b. make
```

# Running

!! login.db muss in der Working directory sein

login.txt hat die anmeldedaten für die nutzer im Beispiel login.db

```bash
./cli # print help mesage
```
