# SubwayRanks Backend
## Installation

```bash
npm install

npm start
```

## URL

* API endpoint: http://localhost:3000
* Swagger UI: http://localhost:3000/api/docs
* Swagger json: http://localhost:3000/api/docs/swagger

## Немного про IDEA/WebStorm
В первый раз запусти
```bash
npm run tsc:w
```
Потом идем в Run Configurations, создаем конфигурацию node.js, как стартовый скрипт указываем `server/app.js`.
После этого можно будет ставить брейкпоинты в идее прямо в typescript-коде.
Дебаг будет тоже работать полностью: в переменные можно подсматривать и т.д.
Проверь что в settings->languages&frameworks->typescript правильно все натроено и стоит галка `recompile on changes` 
