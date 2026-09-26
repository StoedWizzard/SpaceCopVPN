# SpaceCopVPN для Android

Полноценный системный VPN на Android: приложение получает от `VpnService`
файловый дескриптор виртуального интерфейса, а весь стек SpaceCopVPN (протокол,
криптография, потоки, движок TCP/IP — тот же код, что на Linux) работает внутри
приложения на Python через [Chaquopy](https://chaquo.com/chaquopy/). Никаких
сторонних VPN-библиотек: `spacecop/tun/engine.py` терминирует TCP и DNS сам.

## Готовый APK (GitHub Actions)

Сборка автоматическая: workflow `.github/workflows/android.yml` собирает
debug-APK на каждый push и pull request, а по тегу `v*` публикует его в
Releases. Скачать: GitHub → Actions → «Android APK» → последний запуск →
Artifacts → `SpaceCopVPN-debug-apk` (или Releases для тегов). На телефоне
разрешите установку из неизвестных источников.

## Сборка вручную

Нужны JDK 17, Android SDK (platform 34) и Python 3.8–3.12 для Chaquopy.

```
cd android
./sync_python.sh               # копирует ../spacecop в app/src/main/python
gradle assembleDebug           # или через Android Studio; результат:
                               # app/build/outputs/apk/debug/app-debug.apk
```

Пакет кладётся в приложение как исходники (стандартный Python-каталог
Chaquopy), а не через `pip install` из корня репозитория: иначе Gradle
считает весь репозиторий входом задачи и падает на валидации.

`app/build.gradle.kts` устанавливает пакет `spacecopvpn` из корня репозитория
(`pip { install("..") }`), поэтому в APK попадает текущий код.

## Использование

1. Установите APK, откройте приложение.
2. Вставьте строку подключения `spacecop://…` (печатает узел или
   `deploy/install_server.sh`). Несколько строк — по одной на строку.
3. Нажмите «Подключиться», подтвердите системный запрос на создание VPN.
4. В шторке появится значок ключа: весь TCP-трафик и DNS телефона идут через
   оверлей. При автообнаружении остальные узлы подтянутся сами.

## Как устроено

* `SpaceCopVpnService` — `VpnService.Builder()`: адрес `10.77.0.2/24`, маршрут
  `0.0.0.0/0`, DNS `10.77.0.1`, MTU 1400; сокеты самого приложения защищены
  `protect()`, чтобы UDP к узлам не заворачивался в туннель (Chaquopy
  открывает сокеты Python через тот же процесс, для них вызывается
  `protect()` по номеру fd через `SocketProtector`).
* `spacecop.tun.android.run_engine(fd, uris, dns, discover, log)` — запускает
  клиент и `PacketEngine` на этом fd, возвращает `stop()`/`status()`.
* Служба работает в foreground с уведомлением; «Отключиться» вызывает `stop()`
  и закрывает интерфейс.

## Ограничения

* Только IPv4 и TCP + DNS; прочий UDP (звонки, QUIC) не переносится — браузеры
  сами откатываются на TCP.
* Производительность ограничена чистым Python: десятки мегабит, не сотни.
