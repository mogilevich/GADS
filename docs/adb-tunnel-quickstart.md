# ADB Tunnel — Quick Start (SSO)

## 1. Скачать и сделать исполняемым

```bash
curl -L -o gads.zip https://github.com/mogilevich/GADS/releases/latest/download/gads-mac-arm64.zip
unzip gads.zip && mv GADS-darwin-arm64 GADS && chmod +x GADS
```

Для Linux — замените ссылку на `gads-linux.zip` и файл на `GADS-linux-amd64`.

## 2. Взять устройство и скопировать команду

1. В GADS Hub через SSO залогиниться и открыть Android-устройство в remote control.
2. Нажать зелёную кнопку **"📋 adb-tunnel"** в правом нижнем углу — готовая команда скопируется в буфер обмена.

## 3. Запустить туннель

Вставить скопированную команду в терминал:

```bash
./GADS <вставить-из-буфера>
```

Дождаться сообщения `ADB tunnel verified, connecting adb...`

## 4. Разрешить подключение на устройстве

На экране Android-устройства появится диалог **"Allow USB debugging?"** — поставить галочку **"Always allow"** и нажать **Allow**.

## 5. Проверить в другом терминале

```bash
adb devices
```

Должен появиться `localhost:<port>  device`.

## Примечания

- Токен живёт ~1 час — по истечении скопировать свежую команду кнопкой.
- На страницах без открытого устройства кнопка показывает **"📋 ADB Token"** и копирует только токен.
