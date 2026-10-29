# VulScan XSS module

Модуль обнаружения отражённых (reflected) и сохранённых (stored) XSS. Читает задания из Kafka (`scan.jobs.xss.v1`), результаты публикует в `scan.job-events.v1`, состояние хранит Core.

Модуль **не исполняет JavaScript**: уязвимость доказывается структурой ответа (HTML-парсер и лексер JS). Пробы содержат только буквенно-цифровую канарейку и безвредную разметку без обработчиков событий.

| Уровень | Признак | Результат |
|---|---|---|
| L0/L1 | канарейка отражена или опасные символы закодированы | не finding |
| L2 | в контексте выживают символы, нужные для выхода из него | `SUSPECTED`, `LOW` |
| L3 | внедрённая разметка или код стали частью структуры ответа | `LIKELY`, `MEDIUM` |

Не покрыто: DOM-based XSS, исполнение в браузере (`CONFIRMED` не присваивается).

## Сборка

```
git clone https://github.com/tolegenjob/vulscan-kit && (cd vulscan-kit && ./gradlew publishToMavenLocal -PkitVersion=0.3.0 -x test)
./gradlew build installDist
docker build -t vulscan-xss-module .
```

## Переменные окружения

| Переменная | По умолчанию |
|---|---|
| `WORKER_CORE_BASE_URL` | обязательна |
| `WORKER_SERVICE_TOKEN` | обязательна |
| `KAFKA_BOOTSTRAP_SERVERS` | `kafka:9092` |
| `WORKER_CONSUMER_GROUP` | `xss-module` |
| `WORKER_MAX_CONCURRENT_JOBS` | `2` |
| `WORKER_ALLOWED_PRIVATE_CIDRS` | пусто (через запятую, например `172.20.0.0/16`) |
| `XSS_MAX_PARAMS_PER_ENDPOINT` | `10` |
| `XSS_REPEAT_REFLECTION_CHECK` | `true` |
| `HEALTH_PORT` | `8081` |
