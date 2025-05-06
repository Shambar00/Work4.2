# MDK_04.02_Educational_Practice
 
# Практическая работа  
**Тема:** Применение методов обеспечения качества функционирования компьютерных систем  
**Цель:** Ознакомиться с практическими аспектами стандартизации, тестирования и защиты информации.  

---

## Задание 1. Анализ требований к качеству ПО  


# Составление матрицы качества по ISO 9126

## a) Создание таблицы с основными характеристиками

| Характеристика       | Описание                                                                 |
|-----------------------|--------------------------------------------------------------------------|
| Функциональность      | Способность системы предоставлять функции, соответствующие заявленным требованиям. |
| Надежность            | Способность системы поддерживать свою работоспособность при заданных условиях в течение заданного времени. |
| Удобство использования| Способность системы быть понятной, легкой в использовании и привлекательной для пользователя в заданном контексте использования. |
| Эффективность         | Способность системы выполнять заданные функции с минимальными ресурсами. |
| Сопровождаемость      | Способность системы быть модифицированной для исправления дефектов, улучшения или адаптации к изменениям окружения, требований или функциональных спецификаций. |
| Переносимость         | Способность системы быть перенесенной из одной среды в другую.           |

## b) Определение метрик для каждой характеристики

| Характеристика       | Метрики                                                                 |
|-----------------------|--------------------------------------------------------------------------|
| Функциональность      | - Покрытие требований: 100% <br> - Количество реализованных функций: 100% |
| Надежность            | - Время безотказной работы: >99.9% <br> - Среднее время восстановления: <15 минут <br> - Максимальное количество ошибок: <0.1% запросов |
| Удобство использования| - Время выполнения задачи пользователем: <2 минуты <br> - Количество ошибок пользователя: <1% |
| Эффективность         | - Время отклика системы: <500мс <br> - Использование ресурсов (CPU, RAM): <70% |
| Сопровождаемость      | - Время на исправление дефекта: <1 час <br> - Частота обновлений: 1 раз в месяц |
| Переносимость         | - Совместимость с ОС: Windows 10/11, Linux <br> - Время на адаптацию к новой среде: <1 неделя |

2. **Настройка мониторинга производительности:**
   a) Установите Prometheus:
      - Настройте сбор метрик
        
     ![image](https://github.com/user-attachments/assets/56f0ab8d-ec87-4a62-b0fa-47668c09e875)

      - Определите ключевые показатели (KPI)
      KPI для мониторинга:
    `http_requests_total` (количество запросов).
`http_response_time_ms` (время отклика).
`system_cpu_usage` (нагрузка CPU).

   b) Настройте Grafana:
      - Создайте дашборды для:
        * Время отклика: `avg(rate(http_response_time_ms[1m]))`.
        * Запросы в секунду: `rate(http_requests_total[1m])`.
        * Ошибки: `sum(rate(http_requests_failed[1m])) by (status)`.

       
## Задание 2. Разработка плана тестирования


### 1. Введение
**Цель тестирования:** Обеспечение надежности, безопасности и производительности веб-приложения для онлайн-обучения с акцентом на:
- Защиту персональных данных пользователей
- Стабильность работы при высокой нагрузке
- Корректность функциональности ключевых сценариев

**Тестируемая система:** Веб-приложение онлайн-школы с функциями:
- Авторизация пользователей
- Просмотр и прохождение курсов
- Система оплаты
- Личный кабинет
- Административная панель

### 2. Виды тестирования

#### 2.1. Функциональное тестирование
**Область покрытия:**
- Работа форм авторизации/регистрации
- Функционал курсов (просмотр, прогресс, тесты)
- Платежная система
- Личный кабинет пользователя

**Пример теста:**

```python
def test_course_progress():
    driver = webdriver.Chrome()
    login(driver, "test@mail.com", "password123")
    driver.get("/course/python-basics")
    complete_lesson(driver, lesson_id=1)
    assert get_progress(driver) == "25%", "Прогресс курса не обновился"
```


#### 2.2. Тестирование безопасности
Ключевые проверки:


| Уязвимость | Метод проверки| Ожидаемый результат |
|-------------|-------------|-------------|
| SQL-инъекции   | Ввод ' OR '1'='1 в логин/пароль    | Ошибка авторизации    |
XSS |	Ввод `<script>alert(1)</script>` |	Скрипт не выполняется |
| CSRF |	Отправка формы без токена |	Отказ в обработке запроса |

**Инструменты**:
* OWASP ZAP
* Burp Suite
* Nmap

#### 2.3. Нагрузочное тестирование
**Сценарии:**

* 500+ одновременных пользователей:
* 70% просматривают курсы
* 20% проходят тесты
* 10% совершают платежи

**Команда для запуска:**
`locust -f load_test.py --users 500 --spawn-rate 50`

#### 2.4. Юзабилити-тестирование
**Чек-лист:**

* Интуитивная навигация
* Адаптивность под мобильные устройства
* Соответствие WCAG 2.1

#### 3. Этапы тестирования
1. Подготовка (1 день)

+ Настройка тестового окружения

+ Создание тестовых данных

2. Функциональное тестирование (2 дня)

+ Автоматизированные UI-тесты

+ Проверка API

3. Тестирование безопасности (2 дня)

+ Сканирование OWASP ZAP
+ Ручной аудит
4. Нагрузочное тестирование (1 день)

5. Финальный отчет (1 день)


### Задание 3. Конфигурационное управление

### 1. Настройка CI/CD пайплайна в GitHub Actions

#### 1.1. Базовый workflow для тестирования

```yaml
name: CI/CD Pipeline
on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Setup Node.js
        uses: actions/setup-node@v2
        with:
          node-version: '16'
          
      - name: Install dependencies
        run: npm install
          
      - name: Run unit tests
        run: npm test
          
      - name: Security audit
        run: npm audit
          
      - name: Container scanning
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: '.'
          format: 'table'
          exit-code: '1'

          
```
2. Стратегия управления окружениями

| Окружение | Назначение| Автодеплой |	Доступ |
|-------------|-------------|-------|------|	
| dev	| Разработка новых фич |	При push |	Только команда |
|staging|	Тестирование перед продом|	Вручную|	QA, PM|
|prod|	Продакшен|	Теги v1.0+|	Все пользователи|


####  Система откатов (Rollback)
1. Автоматический откат при:

+ Неудачных тестах

+ Ошибках health-check в течение 5 минут

2. Ручной откат через:

`gh workflow run rollback.yml -f version=1.2.1`

#### Управление версиями БД (Flyway)
 Пример структуры миграций
```db/
├── migrations/
│   ├── V1__Create_users_table.sql
│   ├── V2__Add_email_verification.sql
│   └── V3__Create_payment_logs.sql
└── flyway.conf
```
SQL-миграции
```-- V1__Create_users_table.sql
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_users_email ON users(email);
```
Конфигурация Flyway
```# flyway.conf
flyway.url=jdbc:postgresql://${DB_HOST}:5432/app_db
flyway.user=${DB_USER}
flyway.password=${DB_PASSWORD}
flyway.locations=filesystem:db/migrations
flyway.baselineOnMigrate=true
```
```# Проверка статуса пайплайна
gh run list --workflow=ci-cd.yml

# Просмотр логов миграций
flyway info -configFiles=db/flyway.conf
```
## Задание 4. Защита информации  

## 1. Шифрование данных

### 1.1. Шифрование данных в покое (At Rest)

**Используемые технологии:**
- AES-256 для шифрования полей
- Fernet для ключевого управления

**Пример реализации:**
```python
from cryptography.fernet import Fernet
import base64

# Генерация и сохранение ключа
def generate_key():
    return Fernet.generate_key()

# Шифрование данных
def encrypt_data(data: str, key: bytes) -> bytes:
    f = Fernet(key)
    return f.encrypt(data.encode())

# Дешифровка данных
def decrypt_data(encrypted_data: bytes, key: bytes) -> str:
    f = Fernet(key)
    return f.decrypt(encrypted_data).decode()

```

**Рекомендации:**

* Хранить ключи в аппаратном модуле безопасности (HSM)

* Регулярно ротировать ключи (каждые 90 дней)

* Отдельно шифровать особо чувствительные поля (пароли, паспортные данные)

**Реализация TOTP:**
```import pyotp
import qrcode

def generate_2fa_secret(user):
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret, interval=300)
    # Генерация URL для QR-кода
    provisioning_uri = totp.provisioning_uri(
        name=user.email,
        issuer_name="OurSecureApp"
    )
    # Создание QR-кода
    qrcode.make(provisioning_uri).save(f"2fa_{user.id}.png")
    return secret
```

**Процесс верификации:**
```def verify_2fa(code: str, secret: str) -> bool:
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)
```

#### Защита базы данных
**PostgreSQL Hardening:**

```ini
Copy
# postgresql.conf
ssl = on
password_encryption = scram-sha-256
log_statement = 'ddl'
log_connections = on
log_disconnections = on
```
**Рекомендации:**
* Регулярное резервное копирование с шифрованием

* Маскирование данных в тестовых средах

* Запрет прямого доступа из интернета

#### Система обнаружения вторжений
**Пример правил Suricata:**

```yaml
Copy
- rule: SQL Injection Attempt
  meta:
    severity: critical
  pattern: |
    (\'|\")(.*)(\s+OR\s+|\s+AND\s+)(.*)=
  action: drop
```

## Задание 5. Анализ рисков

### 1. Система мониторинга и оповещений

#### 1.1. Конфигурация алертов

```yaml
# alerts-config.yaml
alerts:
  - name: ddos_attack_detected
    condition: |
      rate(http_requests_total{status!~"2.."}[1m]) > 1000 
      AND 
      avg(upstream_response_time_seconds) > 3
    severity: critical
    for: 5m
    annotations:
      summary: "Possible DDoS attack detected"
      description: "High error rate ({{ $value }}%) with slow response times"
    notifications:
      - type: slack
        channel: "#security-alerts"
      - type: sms
        recipients: ["+79991112233"]
      - type: email
        addresses: ["security-team@company.com"]

  - name: abnormal_traffic_spike
    condition: |
      increase(http_requests_total[5m]) > 5000
    severity: warning
    notifications:
      - type: slack
        channel: "#devops-alerts"
```


**Активация WAF (Web Application Firewall)**

Включение правил:
```
curl -X PUT "https://api.cloudflare.com/client/v4/zones/{zone_id}/firewall/rules" \
-H "Authorization: Bearer {api_token}" \
-H "Content-Type: application/json" \
--data '{"action":"block","filter":{"expression":"(http.request.uri.path contains \"/api/\") and ip.src in $malicious_ips"}}'
```
**Режим защиты CDN**

* Установка "I'm Under Attack Mode"

* Включение CAPTCHA для подозрительных запросов

**Блокировка IP**
Автоматизированный скрипт:
```
import boto3
def block_ip(ip):
    client = boto3.client('wafv2')
    response = client.update_ip_set(
        Name='malicious-ips',
        Scope='REGIONAL',
        Addresses=[ip],
        Action='BLOCK'
    )
```
**Масштабирование ресурсов**

Terraform пример:
```
resource "aws_autoscaling_policy" "scale_out" {
  name                   = "ddos_scale_out"
  scaling_adjustment     = 4
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 300
  autoscaling_group_name = aws_autoscaling_group.web.name
}
```
