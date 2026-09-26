# Установка и настройка

Два шага: поднять хотя бы один **узел** (сервер) и подключить к нему **клиент**.

---

## 1. Сервер (узел) — любой Linux одной командой

Требования: Linux с `systemd` (Debian/Ubuntu, Fedora/CentOS/Rocky, Arch,
openSUSE, Alpine) и права root. Скрипт сам поставит `python3`.

```bash
git clone https://github.com/StoedWizzard/SpaceCopVPN.git
cd SpaceCopVPN
sudo ./deploy/install_server.sh
```

Или без клонирования, одной строкой:

```bash
curl -fsSL https://raw.githubusercontent.com/StoedWizzard/SpaceCopVPN/main/deploy/install_server.sh | sudo bash
```

Скрипт:

1. ставит `python3` менеджером пакетов дистрибутива;
2. копирует проект в `/opt/spacecop`;
3. создаёт системного пользователя `spacecop` и каталог `/etc/spacecop`;
4. генерирует **постоянную идентичность** узла `/etc/spacecop/identity.json`
   (ключи переживают перезапуски — клиенты могут их закрепить, а очки узла не
   теряются). **Сделайте резервную копию этого файла** — это и есть узел;
5. устанавливает и запускает службу `spacecop-node` (автозапуск, перезапуск при
   сбое, ограничение привилегий);
6. открывает UDP-порт в `ufw`/`firewalld`, если они активны;
7. печатает **строку подключения**:

```
spacecop://203.0.113.9:51820/<x25519-ключ>/<ed25519-идентификатор>
```

Скопируйте её — она нужна клиенту.

### Настройки сервера

Переменные окружения при запуске скрипта (все необязательны):

| Переменная            | Значение по умолчанию | Смысл                                    |
|-----------------------|-----------------------|------------------------------------------|
| `SPACECOP_PORT`       | `51820`               | UDP-порт узла                            |
| `SPACECOP_ADVERTISE`  | автоопределение       | публичный IP/хост для клиентов           |
| `SPACECOP_BOOTSTRAP`  | —                     | другие узлы `host:port host:port` для gossip |
| `SPACECOP_NO_EXIT`    | —                     | `1` — только ретранслятор, не выход      |
| `SPACECOP_REPO`       | GitHub-репозиторий    | откуда клонировать при standalone-запуске |

Пример: `sudo SPACECOP_PORT=443 SPACECOP_ADVERTISE=vpn.example.net ./deploy/install_server.sh`

Позже параметры правятся в `/etc/spacecop/node.env`, затем
`sudo systemctl restart spacecop-node`.

### Управление

```bash
systemctl status spacecop-node          # состояние
journalctl -u spacecop-node -f          # журнал (очки, число сессий, пиры)
sudo -u spacecop python3 -m spacecop.cli uri --identity /etc/spacecop/identity.json --host <ip>   # строка подключения ещё раз
```

**Облако:** не забудьте открыть UDP-порт в security group / сетевом экране
провайдера — скрипт настраивает только локальный файрвол.

**Несколько узлов:** установите скрипт на каждом сервере и укажите узлам друг
друга через `SPACECOP_BOOTSTRAP`; они обменяются анонсами. В клиенте добавьте
все строки подключения — узлы будут конкурировать за трафик.

---

## 2. Клиент с графическим интерфейсом (Arch Linux)

```bash
git clone https://github.com/StoedWizzard/SpaceCopVPN.git
cd SpaceCopVPN
./packaging/install_client_arch.sh
```

Скрипт ставит `python` и `tk`, собирает пакет `spacecopvpn` через `makepkg` и
устанавливает его. Появятся команды `spacecop-gui`, `spacecop` и пункт
«SpaceCopVPN» в меню приложений.

Варианты:

* `./packaging/install_client_arch.sh --user` — без сборки пакета, установка в
  `~/.local` через pip + ярлык в меню.
* `packaging/arch/build.sh` — только собрать `.pkg.tar.zst` (затем
  `sudo pacman -U …`).
* Другие дистрибутивы: `pip install --user .` (нужен системный пакет tk, например
  `python3-tk` в Debian/Ubuntu), затем `spacecop-gui`.

### Как пользоваться окном

1. **Узлы** — вставьте строку `spacecop://…` в поле и нажмите «Добавить узел».
   Можно добавить несколько — клиент подключится ко всем, и они будут
   конкурировать. Нажмите «Сохранить».
2. **Локальный SOCKS5-прокси** — адрес и порт, где будет слушать прокси
   (по умолчанию `127.0.0.1:1080`).
3. **Подключиться** — клиент выполнит рукопожатия и запустит прокси. Статус
   станет зелёным, в таблице появятся узлы с задержкой и числом запросов.
4. **Тест** — отправит HTTP-запрос к «Тестовому адресу» через оверлей и
   покажет время и первую строку ответа.
5. **Профили** — несколько наборов узлов/портов; хранятся в
   `~/.config/spacecop/profiles.json`.

### Настройка приложений на прокси

* **Firefox:** Настройки → Сеть → Настроить… → «Ручная настройка», SOCKS-узел
  `127.0.0.1`, порт `1080`, SOCKS v5, включить «Проксировать DNS при SOCKS v5».
* **Chromium/Chrome:** `chromium --proxy-server="socks5://127.0.0.1:1080"`.
* **Система (GNOME/KDE):** Параметры → Сеть → Прокси → «Вручную», SOCKS-узел
  `127.0.0.1:1080`.
* **Терминал:** `export ALL_PROXY=socks5h://127.0.0.1:1080`, затем `curl`, `git`
  и др. будут ходить через VPN.

---

## 3. Клиент из командной строки (любая ОС)

```bash
# прокси через один или несколько узлов
python -m spacecop.cli proxy --uri spacecop://... --uri spacecop://... --listen 127.0.0.1:1080

# одиночный запрос (проверка)
python -m spacecop.cli relay --uri spacecop://... --dest example.com:80

# графический клиент
python -m spacecop.cli gui
```

**Windows:** установите Python 3 с python.org (Tkinter входит в комплект),
затем те же команды. **Android (Termux):** `pkg install python`, затем команды
`proxy`/`relay`; для системного VPN нужен обёрточный APK с `VpnService`
(см. `spacecop/tun/android.py`).

---

## 4. Проверка, что всё работает

```bash
curl --socks5-hostname 127.0.0.1:1080 http://example.com/
```

В журнале узла (`journalctl -u spacecop-node -f`) вырастут `score` и
`relayed_requests`. В окне клиента в таблице узлов появится запрос и задержка.

---

## 5. Диагностика: «handshake timed out» / «ни один узел не ответил»

Клиент отправляет INIT каждую секунду и ждёт ответа. Если ответа нет вовсе —
пакеты до узла не доходят или узел не запущен. Если узел **отверг**
рукопожатие, он теперь отвечает причиной, и клиент её показывает
(«node rejected the handshake: …»). Порядок проверки:

**На сервере** — одна команда проверяет всё разом:

```bash
sudo /opt/spacecop/deploy/check_server.sh
```

Она проверит: запущена ли служба (и покажет последние строки журнала, если
нет), слушает ли процесс UDP-порт, отвечает ли узел на локальный PING, открыт
ли порт в ufw/firewalld, синхронизированы ли часы, и напечатает строку
подключения для сверки с той, что в клиенте.

Вручную:

```bash
systemctl status spacecop-node          # служба active?
journalctl -u spacecop-node -n 30       # почему падает?
ss -ulnp | grep 51820                   # порт слушается?
```

**С клиента** — проверить достижимость и рукопожатие отдельно:

```bash
python -m spacecop.cli ping --uri 'spacecop://…'
```

или кнопка **«Проверить узел»** в GUI (проверяет строку в поле ввода или
выделенный узел в списке). Возможные вердикты:

| Вердикт | Причина | Что делать |
|---------|---------|------------|
| `NO REPLY` | узел не запущен **или** UDP-порт закрыт | `check_server.sh` на сервере; открыть UDP-порт **в панели провайдера / security group** — скрипт установки открывает только локальный файрвол |
| `PONG`, но `REJECTED … clock skew` | часы расходятся > 5 минут | `timedatectl set-ntp true` на сервере и на клиенте |
| `PONG`, но `REJECTED … identity` / `verification` | в строке подключения не те ключи | взять строку заново: `sudo /opt/spacecop/deploy/check_server.sh` печатает актуальную |
| `PONG`, `handshake OK` | всё работает | подключаться |

**Известная ошибка старых установок.** Если в журнале
`spacecop: error: unrecognized arguments:` (пусто) и служба перезапускается по
кругу — unit-файл передавал пустую переменную как пустой аргумент. Исправление:

```bash
sudo sed -i 's/\${SPACECOP_EXTRA_ARGS}/$SPACECOP_EXTRA_ARGS/' /etc/systemd/system/spacecop-node.service
sudo systemctl daemon-reload && sudo systemctl restart spacecop-node
```

(или просто повторно запустить обновлённый `install_server.sh`).
